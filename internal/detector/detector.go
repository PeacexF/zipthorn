// Package detector turns archive metadata into a risk assessment
package detector

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

type Level int

const (
	LevelLow Level = iota
	LevelMedium
	LevelHigh
)

var levelNames = map[Level]string{LevelLow: "LOW", LevelMedium: "MEDIUM", LevelHigh: "HIGH"}

func (l Level) String() string {
	if n, ok := levelNames[l]; ok {
		return n
	}
	return fmt.Sprintf("LEVEL_%d", int(l))
}

func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

func (l *Level) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for lvl, name := range levelNames {
		if name == s {
			*l = lvl
			return nil
		}
	}
	return fmt.Errorf("unknown risk level %q", s)
}

// Risk categories, in report order
const (
	CategoryCompression = "compression"
	CategoryFileCount   = "file_count"
	CategoryNesting     = "nesting"
	CategoryPaths       = "paths"
)

var categoryOrder = []string{CategoryCompression, CategoryFileCount, CategoryNesting, CategoryPaths}

// Indicator IDs
const (
	HighCompressionRatio  = "HIGH_COMPRESSION_RATIO"
	ExcessiveDeclaredSize = "EXCESSIVE_DECLARED_SIZE"
	ExcessiveFileCount    = "EXCESSIVE_FILE_COUNT"
	DeepNesting           = "DEEP_NESTING"
	ArchiveRecursion      = "ARCHIVE_RECURSION"
	PathTraversal         = "PATH_TRAVERSAL"
	SuspiciousPath        = "SUSPICIOUS_PATH"
	DuplicateEntries      = "DUPLICATE_ENTRIES"
)

const (
	Accept = "ACCEPT"
	Review = "REVIEW"
	Reject = "REJECT"
)

// PathFinding records why one entry name was flagged
type PathFinding struct {
	Name    string              `json:"name"`
	Issues  []archive.PathIssue `json:"issues"`
	Escapes bool                `json:"escapes"`
}

// sampleLimit bounds the name lists carried in Features, so a hostile archive
// with a million bad entries cannot turn a report into a second payload. The
// counts alongside them stay exact.
const sampleLimit = 20

// evidenceLimit bounds the names quoted by a single indicator.
const evidenceLimit = 5

// Features is what the rules see: the archive reduced to the quantities that
// carry risk.
type Features struct {
	ArchiveSize    int64   `json:"archive_size"`
	CompressedSize int64   `json:"compressed_size"`
	DeclaredSize   int64   `json:"declared_size"`
	ExpansionRatio float64 `json:"expansion_ratio"`
	FileCount      int64   `json:"file_count"`
	DirCount       int64   `json:"dir_count"`
	MaxDepth       int     `json:"max_depth"`
	Encrypted      bool    `json:"encrypted"`

	NestedArchives  int `json:"nested_archives"`
	Duplicates      int `json:"duplicates"`
	EscapingPaths   int `json:"escaping_paths"`
	SuspiciousPaths int `json:"suspicious_paths"`

	NestedSample    []string      `json:"nested_sample,omitempty"`
	DuplicateSample []string      `json:"duplicate_sample,omitempty"`
	PathSample      []PathFinding `json:"path_sample,omitempty"`
}

// Indicator is one triggered rule.
type Indicator struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Level     Level    `json:"level"`
	Score     int      `json:"score"`
	Detail    string   `json:"detail"`
	Value     float64  `json:"value"`
	Threshold float64  `json:"threshold,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
}

// Category is one facet of the archive's risk.
type Category struct {
	Name  string `json:"name"`
	Level Level  `json:"level"`
}

// Assessment is the detector's verdict on an archive.
type Assessment struct {
	Path           string            `json:"path,omitempty"`
	Level          Level             `json:"level"`
	Score          int               `json:"score"`
	Recommendation string            `json:"recommendation"`
	Categories     []Category        `json:"categories"`
	Indicators     []Indicator       `json:"indicators"`
	Features       Features          `json:"features"`
	Thresholds     config.Thresholds `json:"thresholds"`
}

// Extract reduces archive metadata to the features the rules operate on.
func Extract(info *archive.Info) Features {
	f := Features{
		ArchiveSize:    info.ArchiveSize,
		CompressedSize: info.CompressedSize,
		DeclaredSize:   info.DeclaredSize,
		ExpansionRatio: info.ExpansionRatio,
		FileCount:      info.FileCount,
		DirCount:       info.DirCount,
		MaxDepth:       info.MaxDepth,
		Encrypted:      info.Encrypted,
		NestedArchives: len(info.NestedArchives),
		Duplicates:     len(info.Duplicates),
	}

	f.NestedSample = sample(info.NestedArchives)
	for _, d := range info.Duplicates {
		if len(f.DuplicateSample) == sampleLimit {
			break
		}
		f.DuplicateSample = append(f.DuplicateSample, d.Name)
	}

	for _, e := range info.Entries {
		issues := archive.PathIssues(e.Name)
		if len(issues) == 0 {
			continue
		}
		escapes := archive.Escapes(e.Name)
		if escapes {
			f.EscapingPaths++
		} else {
			f.SuspiciousPaths++
		}
		if len(f.PathSample) < sampleLimit {
			f.PathSample = append(f.PathSample, PathFinding{Name: e.Name, Issues: issues, Escapes: escapes})
		}
	}
	return f
}

// Assess runs the detection pipeline over an archive's metadata.
func Assess(info *archive.Info, t config.Thresholds) Assessment {
	f := Extract(info)
	a := Assessment{
		Path:       info.Path,
		Features:   f,
		Thresholds: t,
		Indicators: []Indicator{},
	}

	levels := make(map[string]Level, len(categoryOrder))
	for _, r := range rules {
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
	sort.SliceStable(a.Indicators, func(i, j int) bool {
		if a.Indicators[i].Level != a.Indicators[j].Level {
			return a.Indicators[i].Level > a.Indicators[j].Level
		}
		return a.Indicators[i].Score > a.Indicators[j].Score
	})

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

// A MEDIUM indicator is a warning rather than a verdict, so it contributes a
// fraction of its rule's weight.
func contribution(weight int, l Level) int {
	if l == LevelHigh {
		return weight
	}
	return weight * 2 / 5
}

func sample(names []string) []string {
	if len(names) <= sampleLimit {
		return names
	}
	return names[:sampleLimit]
}

func cap5(names []string) []string {
	if len(names) <= evidenceLimit {
		return names
	}
	return names[:evidenceLimit]
}
