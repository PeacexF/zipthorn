package detector

import (
	"testing"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"default", PolicyDefault, false},
		{"strict", PolicyStrict, false},
		{"permissive", PolicyPermissive, false},
		{"web", PolicyWeb, false},
		{"ci", PolicyCI, false},
		{"unknown", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := GetPolicy(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Name != tt.want {
				t.Errorf("got name %q, want %q", p.Name, tt.want)
			}
		})
	}
}

func TestListPolicies(t *testing.T) {
	names := ListPolicies()
	if len(names) != 5 {
		t.Errorf("got %d policies, want 5", len(names))
	}
	want := map[string]bool{
		PolicyDefault:    true,
		PolicyStrict:     true,
		PolicyPermissive: true,
		PolicyWeb:        true,
		PolicyCI:         true,
	}
	for _, name := range names {
		if !want[name] {
			t.Errorf("unexpected policy %q", name)
		}
	}
}

func TestAssessWithPolicy(t *testing.T) {
	// Create a test archive that will trigger HIGH ratio in strict mode
	info := &archive.Info{
		Path:           "test.zip",
		ArchiveSize:    1000,
		CompressedSize: 1000,
		DeclaredSize:   50000, // 50x ratio
		ExpansionRatio: 50,
		FileCount:      10,
		DirCount:       1,
		MaxDepth:       2,
		Entries:        []archive.Entry{{Name: "file.txt", UncompressedSize: 50000}},
	}

	t.Run("strict_triggers_high", func(t *testing.T) {
		a, err := AssessWithPolicy(info, PolicyStrict)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Strict has ratio threshold of 20, should trigger HIGH at 50x
		if a.Level != LevelHigh {
			t.Errorf("got level %v, want HIGH", a.Level)
		}
		if a.Recommendation != Reject {
			t.Errorf("got recommendation %q, want REJECT", a.Recommendation)
		}
	})

	t.Run("default_triggers_medium", func(t *testing.T) {
		a, err := AssessWithPolicy(info, PolicyDefault)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Default has ratio threshold of 50, should trigger HIGH at exactly 50x
		if a.Level != LevelHigh {
			t.Errorf("got level %v, want HIGH", a.Level)
		}
	})

	t.Run("permissive_accepts", func(t *testing.T) {
		a, err := AssessWithPolicy(info, PolicyPermissive)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Permissive has ratio threshold of 200, should be LOW at 50x
		if a.Level != LevelLow {
			t.Errorf("got level %v, want LOW", a.Level)
		}
		if a.Recommendation != Accept {
			t.Errorf("got recommendation %q, want ACCEPT", a.Recommendation)
		}
	})
}

func TestPolicyDisabledRules(t *testing.T) {
	// Create archive with duplicates
	info := &archive.Info{
		Path:           "test.zip",
		ArchiveSize:    1000,
		CompressedSize: 1000,
		DeclaredSize:   1000,
		ExpansionRatio: 1,
		FileCount:      2,
		DirCount:       0,
		MaxDepth:       1,
		Entries: []archive.Entry{
			{Name: "file.txt", UncompressedSize: 500},
			{Name: "file.txt", UncompressedSize: 500},
		},
		Duplicates: []archive.Duplicate{
			{Name: "file.txt", Count: 2},
		},
	}

	t.Run("default_detects_duplicates", func(t *testing.T) {
		a, err := AssessWithPolicy(info, PolicyDefault)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hasDuplicate := false
		for _, ind := range a.Indicators {
			if ind.ID == DuplicateEntries {
				hasDuplicate = true
			}
		}
		if !hasDuplicate {
			t.Error("expected duplicate indicator, got none")
		}
	})

	t.Run("permissive_ignores_duplicates", func(t *testing.T) {
		a, err := AssessWithPolicy(info, PolicyPermissive)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, ind := range a.Indicators {
			if ind.ID == DuplicateEntries {
				t.Error("expected no duplicate indicator, got one")
			}
		}
	})

	t.Run("ci_ignores_duplicates", func(t *testing.T) {
		a, err := AssessWithPolicy(info, PolicyCI)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, ind := range a.Indicators {
			if ind.ID == DuplicateEntries {
				t.Error("expected no duplicate indicator, got one")
			}
		}
	})
}

func TestPolicyThresholdDifferences(t *testing.T) {
	tests := []struct {
		policy    string
		ratioHigh float64
		sizeHigh  int64
		countHigh int64
	}{
		{PolicyDefault, 50, 1 * config.GB, 10_000},
		{PolicyStrict, 20, 100 * config.MB, 1_000},
		{PolicyPermissive, 200, 10 * config.GB, 100_000},
		{PolicyWeb, 30, 250 * config.MB, 5_000},
		{PolicyCI, 100, 5 * config.GB, 50_000},
	}

	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			p, err := GetPolicy(tt.policy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Thresholds.ExpansionRatio != tt.ratioHigh {
				t.Errorf("ratio: got %v, want %v", p.Thresholds.ExpansionRatio, tt.ratioHigh)
			}
			if p.Thresholds.DeclaredSize != tt.sizeHigh {
				t.Errorf("size: got %v, want %v", p.Thresholds.DeclaredSize, tt.sizeHigh)
			}
			if p.Thresholds.FileCount != tt.countHigh {
				t.Errorf("count: got %v, want %v", p.Thresholds.FileCount, tt.countHigh)
			}
		})
	}
}
