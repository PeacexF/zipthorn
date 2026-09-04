// Package zipthorntest generates pathological ZIP fixtures for use as test
// data in another project's test suite.
//
// zipthorn.Generate is already deterministic and bounded, but assembling a
// zipthorn.Spec by hand means naming all ten of its fields even to get a
// one-line fixture. Bomb and BombFile fail the test on any error instead of
// returning one, so a call reads as setup, not something the calling test
// needs its own error handling for:
//
//	data := zipthorntest.Bomb(t, zipthorn.ProfileRatio)
//	path := zipthorntest.BombFile(t, t.TempDir(), zipthorn.ProfileNested, zipthorntest.Seed(2))
package zipthorntest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeacexF/zipthorn"
)

// Option customizes the zipthorn.Spec Bomb and BombFile build from a
// profile.
type Option func(*zipthorn.Spec)

// Seed sets the deterministic seed. The default is 1: two calls with the
// same profile and options are byte-identical unless Seed varies.
func Seed(seed int64) Option { return func(s *zipthorn.Spec) { s.Seed = seed } }

// DeclaredSize sets the target uncompressed size in bytes.
func DeclaredSize(bytes int64) Option { return func(s *zipthorn.Spec) { s.DeclaredSize = bytes } }

// FileCount sets the number of entries to generate.
func FileCount(n int64) Option { return func(s *zipthorn.Spec) { s.FileCount = n } }

// FileSize sets the uncompressed size of one generated entry, in bytes.
func FileSize(bytes int64) Option { return func(s *zipthorn.Spec) { s.FileSize = bytes } }

// Ratio sets the target expansion ratio of generated payloads.
func Ratio(ratio float64) Option { return func(s *zipthorn.Spec) { s.Ratio = ratio } }

// Depth sets the directory nesting depth.
func Depth(depth int) Option { return func(s *zipthorn.Spec) { s.Depth = depth } }

// Nesting sets the archive-within-archive nesting level.
func Nesting(levels int) Option { return func(s *zipthorn.Spec) { s.Nesting = levels } }

// Level sets the deflate compression level (1..9), or zipthorn.LevelDefault.
func Level(level int) Option { return func(s *zipthorn.Spec) { s.Level = level } }

// Limits overrides the safety limits generation must stay within. The
// default is zipthorn.DefaultConfig().Limits — generation fails the test if
// the profile's defaults for it would exceed them, so a profile that needs
// more room (a deeper ProfileDepth, say) should pass this explicitly rather
// than fail surprisingly.
func Limits(l zipthorn.Limits) Option { return func(s *zipthorn.Spec) { s.Limits = l } }

// Bomb generates a pathological fixture for profile and returns its bytes.
// It calls t.Helper() and fails the test via t.Fatalf on any error.
//
// profile is one of the zipthorn.Profile* constants (zipthorn.ProfileRatio,
// zipthorn.ProfileFileCount, zipthorn.ProfileNested, ...).
func Bomb(t testing.TB, profile string, opts ...Option) []byte {
	t.Helper()

	spec := zipthorn.Spec{
		Profile: profile,
		Seed:    1,
		Limits:  zipthorn.DefaultConfig().Limits,
	}
	for _, opt := range opts {
		opt(&spec)
	}

	var buf bytes.Buffer
	if _, err := zipthorn.Generate(&buf, spec); err != nil {
		t.Fatalf("zipthorntest.Bomb(%q): %v", profile, err)
	}
	return buf.Bytes()
}

// BombFile is Bomb, written to a file named profile+".zip" under dir, and
// returns its path. dir is typically t.TempDir().
func BombFile(t testing.TB, dir, profile string, opts ...Option) string {
	t.Helper()

	data := Bomb(t, profile, opts...)
	path := filepath.Join(dir, profile+".zip")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("zipthorntest.BombFile(%q): %v", profile, err)
	}
	return path
}
