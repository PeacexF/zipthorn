package detector

import (
	"fmt"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

// Policy represents a named detection profile with threshold presets and
// rule configuration.
type Policy struct {
	Name        string
	Description string
	Thresholds  config.Thresholds
	Disabled    map[string]bool // rule IDs to disable
}

// Policies available for use
const (
	PolicyDefault    = "default"
	PolicyStrict     = "strict"
	PolicyPermissive = "permissive"
	PolicyWeb        = "web"
	PolicyCI         = "ci"
)

var policies = map[string]Policy{
	PolicyDefault: {
		Name:        PolicyDefault,
		Description: "Balanced detection suitable for general use",
		Thresholds: config.Thresholds{
			ExpansionRatio: 50,
			DeclaredSize:   1 * config.GB,
			FileCount:      10_000,
			Depth:          16,
			Nesting:        2,
		},
		Disabled: map[string]bool{},
	},
	PolicyStrict: {
		Name:        PolicyStrict,
		Description: "Conservative thresholds for untrusted sources",
		Thresholds: config.Thresholds{
			ExpansionRatio: 20,
			DeclaredSize:   100 * config.MB,
			FileCount:      1_000,
			Depth:          8,
			Nesting:        1,
		},
		Disabled: map[string]bool{},
	},
	PolicyPermissive: {
		Name:        PolicyPermissive,
		Description: "Relaxed thresholds for known-safe sources",
		Thresholds: config.Thresholds{
			ExpansionRatio: 200,
			DeclaredSize:   10 * config.GB,
			FileCount:      100_000,
			Depth:          32,
			Nesting:        4,
		},
		Disabled: map[string]bool{
			DuplicateEntries: true, // allow duplicate names
		},
	},
	PolicyWeb: {
		Name:        PolicyWeb,
		Description: "Tuned for user-uploaded content in web applications",
		Thresholds: config.Thresholds{
			ExpansionRatio: 30,
			DeclaredSize:   250 * config.MB,
			FileCount:      5_000,
			Depth:          12,
			Nesting:        1,
		},
		Disabled: map[string]bool{},
	},
	PolicyCI: {
		Name:        PolicyCI,
		Description: "Suitable for CI/CD artifact inspection",
		Thresholds: config.Thresholds{
			ExpansionRatio: 100,
			DeclaredSize:   5 * config.GB,
			FileCount:      50_000,
			Depth:          24,
			Nesting:        3,
		},
		Disabled: map[string]bool{
			DuplicateEntries: true, // build artifacts often duplicate
		},
	},
}

// GetPolicy retrieves a policy by name.
func GetPolicy(name string) (Policy, error) {
	p, ok := policies[name]
	if !ok {
		return Policy{}, fmt.Errorf("unknown policy %q", name)
	}
	return p, nil
}

// ListPolicies returns all available policy names.
func ListPolicies() []string {
	return []string{PolicyDefault, PolicyStrict, PolicyPermissive, PolicyWeb, PolicyCI}
}

// AssessWithPolicy runs detection with a named policy profile.
func AssessWithPolicy(info *archive.Info, policyName string) (Assessment, error) {
	p, err := GetPolicy(policyName)
	if err != nil {
		return Assessment{}, err
	}
	return AssessWithRules(info, p.Thresholds, p.Disabled), nil
}

// AssessWithRules is like Assess but allows disabling specific rules by ID —
// the same knob a Policy's Disabled map exposes, for a caller that wants it
// without going through a named Policy (Guard's GuardOptions.Disabled uses
// this directly, so it doesn't have to re-derive a Policy just to know which
// rules to skip).
func AssessWithRules(info *archive.Info, t config.Thresholds, disabled map[string]bool) Assessment {
	f := Extract(info)
	a := Assessment{
		Path:       info.Path,
		Features:   f,
		Thresholds: t,
		Indicators: []Indicator{},
	}

	levels := make(map[string]Level, len(categoryOrder))
	for _, r := range rules {
		if disabled[r.id] {
			continue
		}
		found := r.eval(f, t)
		if found.level == LevelLow {
			continue
		}
		ind := Indicator{
			ID:        r.id,
			Category:  r.category,
			Level:     found.level,
			Score:     contribution(r.weight, found.level),
			Detail:    found.detail,
			Value:     found.value,
			Threshold: found.threshold,
			Evidence:  cap5(found.evidence),
		}
		a.Indicators = append(a.Indicators, ind)
		a.Score += ind.Score
		if found.level > levels[r.category] {
			levels[r.category] = found.level
		}
	}

	if a.Score > 100 {
		a.Score = 100
	}
	sort := func(indicators []Indicator) {
		for i := 0; i < len(indicators); i++ {
			for j := i + 1; j < len(indicators); j++ {
				if indicators[i].Level < indicators[j].Level ||
					(indicators[i].Level == indicators[j].Level && indicators[i].Score < indicators[j].Score) {
					indicators[i], indicators[j] = indicators[j], indicators[i]
				}
			}
		}
	}
	sort(a.Indicators)

	for _, name := range categoryOrder {
		l := levels[name]
		a.Categories = append(a.Categories, Category{Name: name, Level: l})
		if l > a.Level {
			a.Level = l
		}
	}

	switch a.Level {
	case LevelHigh:
		a.Recommendation = Reject
	case LevelMedium:
		a.Recommendation = Review
	default:
		a.Recommendation = Accept
	}
	return a
}
