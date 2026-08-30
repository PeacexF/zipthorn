package generator_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/generator"
)

// build generates a fixture and reads its metadata back, which is how every
// shape assertion below is stated: through the exported archive view.
func build(t *testing.T, s generator.Spec) (*generator.Result, *archive.Info, []byte) {
	t.Helper()
	var buf bytes.Buffer
	res, err := generator.Generate(&buf, s)
	if err != nil {
		t.Fatalf("Generate(%s): %v", s.Profile, err)
	}
	info, err := archive.Read(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("reading generated %s archive: %v", s.Profile, err)
	}
	return res, info, buf.Bytes()
}

func generate(t *testing.T, s generator.Spec) ([]byte, error) {
	t.Helper()
	var buf bytes.Buffer
	_, err := generator.Generate(&buf, s)
	return buf.Bytes(), err
}

func TestSameSeedProducesIdenticalArchives(t *testing.T) {
	for _, profile := range generator.Profiles() {
		spec := generator.Spec{Profile: profile, Seed: 7, DeclaredSize: 512 * config.KB, FileCount: 24}
		_, _, first := build(t, spec)
		_, _, second := build(t, spec)
		if !bytes.Equal(first, second) {
			t.Errorf("%s: same seed produced different archives (%d vs %d bytes)",
				profile, len(first), len(second))
		}
	}
}

func TestSeedChangesContent(t *testing.T) {
	spec := generator.Spec{Profile: generator.ProfileRatio, Seed: 1, DeclaredSize: 512 * config.KB}
	_, _, first := build(t, spec)
	spec.Seed = 2
	_, _, second := build(t, spec)
	if bytes.Equal(first, second) {
		t.Error("different seeds produced identical archives")
	}
}

func TestProfileShapes(t *testing.T) {
	t.Run("ratio", func(t *testing.T) {
		res, info, _ := build(t, generator.Spec{
			Profile: generator.ProfileRatio, DeclaredSize: 4 * config.MB, Ratio: 40,
		})
		if info.FileCount != 1 {
			t.Errorf("file count = %d, want 1", info.FileCount)
		}
		if info.DeclaredSize != 4*config.MB {
			t.Errorf("declared size = %d, want %d", info.DeclaredSize, 4*config.MB)
		}
		if res.ExpansionRatio < 20 {
			t.Errorf("expansion ratio = %.1f, want a substantial expansion", res.ExpansionRatio)
		}
	})

	t.Run("file-count", func(t *testing.T) {
		_, info, _ := build(t, generator.Spec{
			Profile: generator.ProfileFileCount, FileCount: 500, FileSize: 32,
		})
		if info.FileCount != 500 {
			t.Errorf("file count = %d, want 500", info.FileCount)
		}
		if info.DeclaredSize != 500*32 {
			t.Errorf("declared size = %d, want %d", info.DeclaredSize, 500*32)
		}
	})

	t.Run("nested", func(t *testing.T) {
		res, info, _ := build(t, generator.Spec{
			Profile: generator.ProfileNested, Nesting: 3, DeclaredSize: 256 * config.KB,
		})
		if res.Nesting != 3 {
			t.Errorf("nesting = %d, want 3", res.Nesting)
		}
		if len(info.NestedArchives) != 1 {
			t.Errorf("nested archives = %v, want exactly one at the top level", info.NestedArchives)
		}
		// The payload is buried, so the outer archive declares far less than a
		// recursive extraction would produce.
		if info.DeclaredSize >= res.DeclaredSize {
			t.Errorf("outer declares %d, recursive total %d; want the outer to be smaller",
				info.DeclaredSize, res.DeclaredSize)
		}
	})

	t.Run("depth", func(t *testing.T) {
		_, info, _ := build(t, generator.Spec{Profile: generator.ProfileDepth, Depth: 12})
		if info.MaxDepth != 12 {
			t.Errorf("max depth = %d, want 12", info.MaxDepth)
		}
	})

	t.Run("metadata", func(t *testing.T) {
		_, info, _ := build(t, generator.Spec{Profile: generator.ProfileMetadata})
		if len(info.Duplicates) != 1 {
			t.Errorf("duplicates = %v, want exactly one duplicated name", info.Duplicates)
		}
		var escaping int
		for _, e := range info.Entries {
			if archive.Escapes(e.Name) {
				escaping++
			}
		}
		if escaping == 0 {
			t.Error("metadata profile produced no escaping entry names")
		}
	})

	t.Run("mixed", func(t *testing.T) {
		res, info, _ := build(t, generator.Spec{
			Profile: generator.ProfileMixed, DeclaredSize: 1 * config.MB, FileCount: 16, Depth: 5,
		})
		if len(info.Duplicates) == 0 {
			t.Error("want a duplicated name")
		}
		if len(info.NestedArchives) == 0 {
			t.Error("want a nested archive")
		}
		if info.MaxDepth != 5 {
			t.Errorf("max depth = %d, want 5", info.MaxDepth)
		}
		if res.ExpansionRatio <= 1 {
			t.Errorf("expansion ratio = %.1f, want the payload to dominate", res.ExpansionRatio)
		}
	})
}

func TestAchievedRatioTracksTarget(t *testing.T) {
	for _, target := range []float64{2, 10, 50} {
		res, _, _ := build(t, generator.Spec{
			Profile: generator.ProfileRatio, DeclaredSize: 4 * config.MB, Ratio: target,
		})
		if res.ExpansionRatio > target {
			t.Errorf("target %.0fx: achieved %.1fx, which must not exceed the target",
				target, res.ExpansionRatio)
		}
		if res.ExpansionRatio < target/2 {
			t.Errorf("target %.0fx: achieved %.1fx, want at least half the target",
				target, res.ExpansionRatio)
		}
	}
}

func TestLimitsFailClosed(t *testing.T) {
	small := config.Limits{
		MaxOutputBytes:    1 * config.MB,
		MaxExpansionRatio: 20,
		MaxFiles:          100,
		MaxDepth:          6,
		MaxNesting:        2,
	}

	cases := []struct {
		name string
		spec generator.Spec
	}{
		{"declared size", generator.Spec{Profile: generator.ProfileRatio, DeclaredSize: 2 * config.MB}},
		{"file count", generator.Spec{Profile: generator.ProfileFileCount, FileCount: 101, FileSize: 8}},
		{"depth", generator.Spec{Profile: generator.ProfileDepth, Depth: 7}},
		{"nesting", generator.Spec{Profile: generator.ProfileNested, Nesting: 3, DeclaredSize: config.KB}},
		{"expansion ratio", generator.Spec{Profile: generator.ProfileRatio, DeclaredSize: config.KB, Ratio: 21}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec.Limits = small
			out, err := generate(t, tc.spec)
			if !errors.Is(err, generator.ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
			if len(out) != 0 {
				t.Errorf("wrote %d bytes despite refusing to generate", len(out))
			}
		})
	}
}

func TestDefaultsStayWithinLimits(t *testing.T) {
	small := config.Limits{
		MaxOutputBytes:    1 * config.MB,
		MaxExpansionRatio: 10,
		MaxFiles:          64,
		MaxDepth:          4,
		MaxNesting:        1,
	}
	for _, profile := range generator.Profiles() {
		res, _, _ := build(t, generator.Spec{Profile: profile, Limits: small})
		switch {
		case res.DeclaredSize > small.MaxOutputBytes:
			t.Errorf("%s: declared %d bytes, above the %d limit", profile, res.DeclaredSize, small.MaxOutputBytes)
		case res.FileCount > small.MaxFiles:
			t.Errorf("%s: %d files, above the %d limit", profile, res.FileCount, small.MaxFiles)
		case res.MaxDepth > small.MaxDepth:
			t.Errorf("%s: depth %d, above the %d limit", profile, res.MaxDepth, small.MaxDepth)
		case res.Nesting > small.MaxNesting:
			t.Errorf("%s: nesting %d, above the %d limit", profile, res.Nesting, small.MaxNesting)
		case res.ExpansionRatio > small.MaxExpansionRatio:
			t.Errorf("%s: expands %.1fx, above the %.1fx limit", profile, res.ExpansionRatio, small.MaxExpansionRatio)
		}
	}
}

func TestUnknownProfile(t *testing.T) {
	_, err := generate(t, generator.Spec{Profile: "nope"})
	if !errors.Is(err, generator.ErrUnknownProfile) {
		t.Fatalf("err = %v, want ErrUnknownProfile", err)
	}
}

func TestInvalidCompressionLevel(t *testing.T) {
	if _, err := generate(t, generator.Spec{Profile: generator.ProfileDepth, Level: 12}); err == nil {
		t.Fatal("level 12 was accepted")
	}
}

func TestZeroSpecGeneratesDefaultProfile(t *testing.T) {
	res, _, _ := build(t, generator.Spec{DeclaredSize: 256 * config.KB})
	if res.Profile != generator.ProfileRatio {
		t.Errorf("profile = %q, want %q", res.Profile, generator.ProfileRatio)
	}
	if res.ExpansionRatio <= 1 {
		t.Errorf("expansion ratio = %.1f, want the default level to compress", res.ExpansionRatio)
	}
}
