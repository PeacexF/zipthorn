package detector_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/detector"
)

func thresholds() config.Thresholds { return config.Default().Thresholds }

// info builds archive metadata directly so each rule can be driven to its exact
// boundary without hand-crafting a matching ZIP.
func info(mutate func(*archive.Info)) *archive.Info {
	i := &archive.Info{ArchiveSize: 1024, CompressedSize: 1024, DeclaredSize: 1024, ExpansionRatio: 1}
	if mutate != nil {
		mutate(i)
	}
	return i
}

func entries(names ...string) []archive.Entry {
	out := make([]archive.Entry, 0, len(names))
	for _, n := range names {
		out = append(out, archive.Entry{Name: n})
	}
	return out
}

func find(t *testing.T, a detector.Assessment, id string) detector.Indicator {
	t.Helper()
	for _, in := range a.Indicators {
		if in.ID == id {
			return in
		}
	}
	t.Fatalf("indicator %s not triggered; got %s", id, ids(a))
	return detector.Indicator{}
}

func refute(t *testing.T, a detector.Assessment, id string) {
	t.Helper()
	for _, in := range a.Indicators {
		if in.ID == id {
			t.Fatalf("indicator %s should not have triggered: %s", id, in.Detail)
		}
	}
}

func ids(a detector.Assessment) string {
	var out []string
	for _, in := range a.Indicators {
		out = append(out, in.ID+"="+in.Level.String())
	}
	if len(out) == 0 {
		return "(none)"
	}
	return strings.Join(out, " ")
}

func category(t *testing.T, a detector.Assessment, name string) detector.Level {
	t.Helper()
	for _, c := range a.Categories {
		if c.Name == name {
			return c.Level
		}
	}
	t.Fatalf("category %q missing from %+v", name, a.Categories)
	return detector.LevelLow
}

func TestCleanArchiveIsAccepted(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.FileCount = 10
		i.MaxDepth = 2
		i.Entries = entries("docs/readme.txt", "docs/notes.txt")
	}), thresholds())

	if a.Recommendation != detector.Accept {
		t.Errorf("Recommendation = %s, want %s (%s)", a.Recommendation, detector.Accept, ids(a))
	}
	if a.Level != detector.LevelLow || a.Score != 0 {
		t.Errorf("Level = %s, Score = %d, want LOW/0", a.Level, a.Score)
	}
	if len(a.Indicators) != 0 {
		t.Errorf("Indicators = %s, want none", ids(a))
	}
	for _, c := range a.Categories {
		if c.Level != detector.LevelLow {
			t.Errorf("category %s = %s, want LOW", c.Name, c.Level)
		}
	}
}

// Every rule grades on the same boundary: at the threshold is HIGH, at half of
// it is MEDIUM, and just below half is LOW.
func TestNumericThresholdBoundaries(t *testing.T) {
	th := thresholds()

	tests := []struct {
		name   string
		id     string
		at     func(*archive.Info, float64) // sets the graded quantity
		high   float64
		medium float64
		low    float64
	}{
		{
			"expansion ratio", detector.HighCompressionRatio,
			func(i *archive.Info, v float64) { i.ExpansionRatio = v },
			th.ExpansionRatio, th.ExpansionRatio / 2, th.ExpansionRatio/2 - 1,
		},
		{
			"declared size", detector.ExcessiveDeclaredSize,
			func(i *archive.Info, v float64) { i.DeclaredSize = int64(v) },
			float64(th.DeclaredSize), float64(th.DeclaredSize / 2), float64(th.DeclaredSize/2 - 1),
		},
		{
			"file count", detector.ExcessiveFileCount,
			func(i *archive.Info, v float64) { i.FileCount = int64(v) },
			float64(th.FileCount), float64(th.FileCount / 2), float64(th.FileCount/2 - 1),
		},
		{
			"depth", detector.DeepNesting,
			func(i *archive.Info, v float64) { i.MaxDepth = int(v) },
			float64(th.Depth), float64(th.Depth / 2), float64(th.Depth/2 - 1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cases := []struct {
				value float64
				want  detector.Level
			}{
				{tt.high, detector.LevelHigh},
				{tt.high + 1, detector.LevelHigh},
				{tt.medium, detector.LevelMedium},
				{tt.low, detector.LevelLow},
				{0, detector.LevelLow},
			}
			for _, c := range cases {
				a := detector.Assess(info(func(i *archive.Info) { tt.at(i, c.value) }), th)
				if c.want == detector.LevelLow {
					refute(t, a, tt.id)
					continue
				}
				if got := find(t, a, tt.id).Level; got != c.want {
					t.Errorf("value %v: level = %s, want %s", c.value, got, c.want)
				}
			}
		})
	}
}

func TestDisabledThresholdSilencesRule(t *testing.T) {
	th := thresholds()
	th.ExpansionRatio = 0

	a := detector.Assess(info(func(i *archive.Info) { i.ExpansionRatio = 10_000 }), th)
	refute(t, a, detector.HighCompressionRatio)
}

func TestHighRatioIsRejected(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.ExpansionRatio = 500
		i.DeclaredSize = 4 * config.GB
	}), thresholds())

	if a.Recommendation != detector.Reject {
		t.Errorf("Recommendation = %s, want REJECT (%s)", a.Recommendation, ids(a))
	}
	if got := category(t, a, detector.CategoryCompression); got != detector.LevelHigh {
		t.Errorf("compression category = %s, want HIGH", got)
	}
	in := find(t, a, detector.HighCompressionRatio)
	if in.Value != 500 || in.Threshold != thresholds().ExpansionRatio {
		t.Errorf("indicator value/threshold = %v/%v", in.Value, in.Threshold)
	}
}

func TestArchiveRecursion(t *testing.T) {
	th := thresholds() // Nesting threshold is 2

	single := detector.Assess(info(func(i *archive.Info) {
		i.NestedArchives = []string{"bundle/inner.zip"}
	}), th)
	if got := find(t, single, detector.ArchiveRecursion).Level; got != detector.LevelMedium {
		t.Errorf("one nested archive = %s, want MEDIUM", got)
	}

	many := detector.Assess(info(func(i *archive.Info) {
		i.NestedArchives = []string{"a.zip", "b.jar"}
	}), th)
	if got := find(t, many, detector.ArchiveRecursion).Level; got != detector.LevelHigh {
		t.Errorf("two nested archives = %s, want HIGH", got)
	}
	if got := many.Recommendation; got != detector.Reject {
		t.Errorf("Recommendation = %s, want REJECT", got)
	}
}

// A nested archive is worth flagging even when the threshold is set high
// enough that the derived MEDIUM band would otherwise miss it.
func TestSingleNestedArchiveSurvivesHighThreshold(t *testing.T) {
	th := thresholds()
	th.Nesting = 50

	a := detector.Assess(info(func(i *archive.Info) {
		i.NestedArchives = []string{"inner.zip"}
	}), th)
	if got := find(t, a, detector.ArchiveRecursion).Level; got != detector.LevelMedium {
		t.Errorf("level = %s, want MEDIUM", got)
	}
}

func TestPathTraversalIsHigh(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.Entries = entries("../../etc/passwd", "/etc/shadow", "docs/ok.txt")
	}), thresholds())

	in := find(t, a, detector.PathTraversal)
	if in.Level != detector.LevelHigh || in.Value != 2 {
		t.Errorf("indicator = %+v, want HIGH over 2 entries", in)
	}
	if got := category(t, a, detector.CategoryPaths); got != detector.LevelHigh {
		t.Errorf("paths category = %s, want HIGH", got)
	}
	if a.Recommendation != detector.Reject {
		t.Errorf("Recommendation = %s, want REJECT", a.Recommendation)
	}
	if len(in.Evidence) != 2 {
		t.Errorf("Evidence = %v, want both offending names", in.Evidence)
	}
}

// A ".." that cancels out never leaves the destination, so it is odd rather
// than dangerous.
func TestContainedDotDotIsSuspiciousNotTraversal(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.Entries = entries("a/../b.txt")
	}), thresholds())

	refute(t, a, detector.PathTraversal)
	if got := find(t, a, detector.SuspiciousPath).Level; got != detector.LevelMedium {
		t.Errorf("level = %s, want MEDIUM", got)
	}
}

func TestSuspiciousPathKinds(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.Entries = entries("dir\\file.txt", "./x.txt", "CON.txt", "trailing .", "bad\tname")
	}), thresholds())

	in := find(t, a, detector.SuspiciousPath)
	if in.Value != 5 {
		t.Errorf("flagged %v entries, want 5", in.Value)
	}
	if len(in.Evidence) != 5 {
		t.Errorf("Evidence = %v, want 5 names", in.Evidence)
	}
}

func TestDuplicateEntries(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.Duplicates = []archive.Duplicate{{Name: "dup.txt", Count: 2}}
	}), thresholds())

	in := find(t, a, detector.DuplicateEntries)
	if in.Level != detector.LevelMedium {
		t.Errorf("level = %s, want MEDIUM", in.Level)
	}
	if len(in.Evidence) != 1 || in.Evidence[0] != "dup.txt" {
		t.Errorf("Evidence = %v", in.Evidence)
	}
	if a.Recommendation != detector.Review {
		t.Errorf("Recommendation = %s, want REVIEW", a.Recommendation)
	}
}

func TestScoreAccumulatesAndCaps(t *testing.T) {
	mild := detector.Assess(info(func(i *archive.Info) {
		i.Duplicates = []archive.Duplicate{{Name: "dup.txt", Count: 2}}
	}), thresholds())

	severe := detector.Assess(info(func(i *archive.Info) {
		i.ExpansionRatio = 10_000
		i.DeclaredSize = 100 * config.GB
		i.FileCount = 1_000_000
		i.MaxDepth = 64
		i.NestedArchives = []string{"a.zip", "b.zip", "c.zip"}
		i.Duplicates = []archive.Duplicate{{Name: "dup.txt", Count: 9}}
		i.Entries = entries("../escape.txt")
	}), thresholds())

	if mild.Score <= 0 || mild.Score >= severe.Score {
		t.Errorf("scores = %d then %d, want increasing", mild.Score, severe.Score)
	}
	if severe.Score != 100 {
		t.Errorf("Score = %d, want the 100 cap", severe.Score)
	}
}

// Indicators lead with the most severe finding so a truncated report still
// shows the worst of it.
func TestIndicatorsSortedBySeverity(t *testing.T) {
	a := detector.Assess(info(func(i *archive.Info) {
		i.Duplicates = []archive.Duplicate{{Name: "dup.txt", Count: 2}}
		i.ExpansionRatio = 500
		i.Entries = entries("../escape.txt")
	}), thresholds())

	if len(a.Indicators) < 3 {
		t.Fatalf("Indicators = %s, want at least 3", ids(a))
	}
	for i := 1; i < len(a.Indicators); i++ {
		prev, cur := a.Indicators[i-1], a.Indicators[i]
		if cur.Level > prev.Level {
			t.Errorf("%s (%s) sorted after %s (%s)", cur.ID, cur.Level, prev.ID, prev.Level)
		}
		if cur.Level == prev.Level && cur.Score > prev.Score {
			t.Errorf("%s scored %d, sorted after %s at %d", cur.ID, cur.Score, prev.ID, prev.Score)
		}
	}
}

func TestFeatureExtraction(t *testing.T) {
	f := detector.Extract(info(func(i *archive.Info) {
		i.FileCount = 3
		i.DirCount = 1
		i.MaxDepth = 4
		i.Encrypted = true
		i.NestedArchives = []string{"inner.zip"}
		i.Duplicates = []archive.Duplicate{{Name: "dup.txt", Count: 2}}
		i.Entries = entries("../out.txt", "./odd.txt", "fine.txt")
	}))

	if f.FileCount != 3 || f.DirCount != 1 || f.MaxDepth != 4 || !f.Encrypted {
		t.Errorf("features = %+v", f)
	}
	if f.EscapingPaths != 1 || f.SuspiciousPaths != 1 {
		t.Errorf("EscapingPaths = %d, SuspiciousPaths = %d, want 1 and 1",
			f.EscapingPaths, f.SuspiciousPaths)
	}
	if len(f.PathSample) != 2 {
		t.Errorf("PathSample = %+v, want 2", f.PathSample)
	}
	if f.NestedArchives != 1 || f.Duplicates != 1 {
		t.Errorf("NestedArchives = %d, Duplicates = %d", f.NestedArchives, f.Duplicates)
	}
}

// Samples are bounded so a hostile archive cannot turn the report into a
// second payload, but the counts beside them stay exact.
func TestSamplesAreBoundedButCountsAreExact(t *testing.T) {
	names := make([]string, 500)
	for i := range names {
		names[i] = "../escape.txt"
	}

	f := detector.Extract(info(func(i *archive.Info) { i.Entries = entries(names...) }))
	if f.EscapingPaths != 500 {
		t.Errorf("EscapingPaths = %d, want 500", f.EscapingPaths)
	}
	if len(f.PathSample) > 20 {
		t.Errorf("len(PathSample) = %d, want it bounded", len(f.PathSample))
	}

	a := detector.Assess(info(func(i *archive.Info) { i.Entries = entries(names...) }), thresholds())
	if n := len(find(t, a, detector.PathTraversal).Evidence); n > 5 {
		t.Errorf("len(Evidence) = %d, want it bounded", n)
	}
}

func TestEmptyArchiveIsAccepted(t *testing.T) {
	a := detector.Assess(&archive.Info{}, thresholds())
	if a.Recommendation != detector.Accept {
		t.Errorf("Recommendation = %s, want ACCEPT (%s)", a.Recommendation, ids(a))
	}
}

func TestLevelJSONRoundTrip(t *testing.T) {
	for _, l := range []detector.Level{detector.LevelLow, detector.LevelMedium, detector.LevelHigh} {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatalf("Marshal(%s): %v", l, err)
		}
		if want := `"` + l.String() + `"`; string(b) != want {
			t.Errorf("Marshal(%s) = %s, want %s", l, b, want)
		}

		var got detector.Level
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("Unmarshal(%s): %v", b, err)
		}
		if got != l {
			t.Errorf("round trip = %s, want %s", got, l)
		}
	}

	var bad detector.Level
	if err := json.Unmarshal([]byte(`"CRITICAL"`), &bad); err == nil {
		t.Error("expected an error for an unknown level")
	}
}

// Every category appears in every report so JSON consumers see a stable shape.
func TestCategoriesAlwaysPresent(t *testing.T) {
	a := detector.Assess(&archive.Info{}, thresholds())

	want := []string{
		detector.CategoryCompression, detector.CategoryFileCount,
		detector.CategoryNesting, detector.CategoryPaths,
	}
	if len(a.Categories) != len(want) {
		t.Fatalf("Categories = %+v", a.Categories)
	}
	for i, name := range want {
		if a.Categories[i].Name != name {
			t.Errorf("Categories[%d] = %q, want %q", i, a.Categories[i].Name, name)
		}
	}
}
