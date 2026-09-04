package detector

import (
	"fmt"
	"strings"

	"github.com/PeacexF/zipthorn/internal/config"
)

// mediumFraction is the share of a HIGH threshold at which a characteristic is
// already worth flagging. Config carries only the HIGH point, so MEDIUM is
// derived from it rather than configured separately.
const mediumFraction = 0.5

// finding is a rule's verdict. Its zero value means the rule did not trigger.
type finding struct {
	level     Level
	value     float64
	threshold float64
	detail    string
	evidence  []string
}

// weight is the score a rule contributes when it triggers at HIGH. Weights are
// relative: a path escape is as damaging as a compression bomb, a duplicate
// name much less so.
type rule struct {
	id       string
	category string
	weight   int
	eval     func(Features, config.Thresholds) finding
}

var rules = []rule{
	{HighCompressionRatio, CategoryCompression, 30, ratioRule},
	{ExcessiveDeclaredSize, CategoryCompression, 25, declaredSizeRule},
	{ExcessiveFileCount, CategoryFileCount, 20, fileCountRule},
	{DeepNesting, CategoryNesting, 10, depthRule},
	{ArchiveRecursion, CategoryNesting, 15, recursionRule},
	{PathTraversal, CategoryPaths, 30, traversalRule},
	{SuspiciousPath, CategoryPaths, 8, suspiciousPathRule},
	{DuplicateEntries, CategoryPaths, 8, duplicateRule},
	{EncryptedEntries, CategoryEncryption, 15, encryptedRule},
}

// levelFor grades a measurement against the threshold at which it becomes
// HIGH. A non-positive threshold disables the rule.
func levelFor(value, high float64) Level {
	switch {
	case high <= 0 || value <= 0:
		return LevelLow
	case value >= high:
		return LevelHigh
	case value >= high*mediumFraction:
		return LevelMedium
	default:
		return LevelLow
	}
}

func ratioRule(f Features, t config.Thresholds) finding {
	l := levelFor(f.ExpansionRatio, t.ExpansionRatio)
	if l == LevelLow {
		return finding{}
	}
	return finding{
		level:     l,
		value:     f.ExpansionRatio,
		threshold: t.ExpansionRatio,
		detail: fmt.Sprintf("archive expands %s against a %s threshold",
			ratioText(f.ExpansionRatio), ratioText(t.ExpansionRatio)),
	}
}

func declaredSizeRule(f Features, t config.Thresholds) finding {
	l := levelFor(float64(f.DeclaredSize), float64(t.DeclaredSize))
	if l == LevelLow {
		return finding{}
	}
	return finding{
		level:     l,
		value:     float64(f.DeclaredSize),
		threshold: float64(t.DeclaredSize),
		detail: fmt.Sprintf("declares %s of output against a %s threshold",
			bytesText(f.DeclaredSize), bytesText(t.DeclaredSize)),
	}
}

func fileCountRule(f Features, t config.Thresholds) finding {
	l := levelFor(float64(f.FileCount), float64(t.FileCount))
	if l == LevelLow {
		return finding{}
	}
	return finding{
		level:     l,
		value:     float64(f.FileCount),
		threshold: float64(t.FileCount),
		detail:    fmt.Sprintf("holds %d files against a %d threshold", f.FileCount, t.FileCount),
	}
}

func depthRule(f Features, t config.Thresholds) finding {
	l := levelFor(float64(f.MaxDepth), float64(t.Depth))
	if l == LevelLow {
		return finding{}
	}
	return finding{
		level:     l,
		value:     float64(f.MaxDepth),
		threshold: float64(t.Depth),
		detail:    fmt.Sprintf("nests directories %d deep against a %d threshold", f.MaxDepth, t.Depth),
	}
}

// Nested archives are identified by extension, so this rule is a hint that the
// archive warrants recursive inspection, not proof that it recurses.
func recursionRule(f Features, t config.Thresholds) finding {
	if f.NestedArchives == 0 {
		return finding{}
	}
	l := levelFor(float64(f.NestedArchives), float64(t.Nesting))
	if l == LevelLow {
		l = LevelMedium
	}
	return finding{
		level:     l,
		value:     float64(f.NestedArchives),
		threshold: float64(t.Nesting),
		detail: plural(f.NestedArchives,
			"entry looks like a nested archive", "entries look like nested archives"),
		evidence: f.NestedSample,
	}
}

func traversalRule(f Features, _ config.Thresholds) finding {
	if f.EscapingPaths == 0 {
		return finding{}
	}
	return finding{
		level: LevelHigh,
		value: float64(f.EscapingPaths),
		detail: plural(f.EscapingPaths,
			"entry would be written outside the destination",
			"entries would be written outside the destination"),
		evidence: pathNames(f.PathSample, true),
	}
}

func suspiciousPathRule(f Features, _ config.Thresholds) finding {
	if f.SuspiciousPaths == 0 {
		return finding{}
	}
	return finding{
		level: LevelMedium,
		value: float64(f.SuspiciousPaths),
		detail: plural(f.SuspiciousPaths,
			"entry carries a suspicious name", "entries carry suspicious names"),
		evidence: pathNames(f.PathSample, false),
	}
}

func duplicateRule(f Features, _ config.Thresholds) finding {
	if f.Duplicates == 0 {
		return finding{}
	}
	return finding{
		level: LevelMedium,
		value: float64(f.Duplicates),
		detail: plural(f.Duplicates,
			"name is claimed by more than one entry",
			"names are claimed by more than one entry"),
		evidence: f.DuplicateSample,
	}
}

// The archive's own metadata is trustworthy here — Encrypted comes from the
// general-purpose bit flag in the central directory, not from attempting to
// decrypt anything, so this rule is as safe on hostile input as every other
// one in this file. There is no natural threshold for a boolean, so this
// rule ignores config.Thresholds the same way traversalRule and
// duplicateRule do.
func encryptedRule(f Features, _ config.Thresholds) finding {
	if !f.Encrypted {
		return finding{}
	}
	return finding{
		level:  LevelMedium,
		value:  1,
		detail: "archive contains at least one encrypted entry; content cannot be inspected",
	}
}

func pathNames(findings []PathFinding, escaping bool) []string {
	var out []string
	for _, p := range findings {
		if p.Escapes == escaping {
			out = append(out, p.Name)
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func ratioText(r float64) string {
	if r >= 100 {
		return fmt.Sprintf("%.0fx", r)
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", r), ".0") + "x"
}

var byteUnits = []struct {
	limit int64
	name  string
}{
	{1 << 50, "PB"}, {1 << 40, "TB"}, {1 << 30, "GB"}, {1 << 20, "MB"}, {1 << 10, "KB"},
}

func bytesText(n int64) string {
	for _, u := range byteUnits {
		if n >= u.limit {
			return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/float64(u.limit)), ".0") + " " + u.name
		}
	}
	return fmt.Sprintf("%d B", n)
}
