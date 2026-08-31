package generator

import (
	"bytes"
	"testing"

	"github.com/PeacexF/zipthorn/internal/config"
)

// fuzzLimits keep each iteration small. The defaults allow a 256MB declared
// archive, which is far too heavy to build once per execution across parallel
// fuzzing workers.
var fuzzLimits = config.Limits{
	MaxOutputBytes:    4 * config.MB,
	MaxExpansionRatio: 100,
	MaxFiles:          500,
	MaxDepth:          12,
	MaxNesting:        3,
}

// FuzzGenerator tests the generator with various seed values.
// Run with: go test -fuzz=FuzzGenerator -fuzztime=30s
func FuzzGenerator(f *testing.F) {
	// Seed corpus with a few known seeds
	f.Add(int64(0))
	f.Add(int64(1))
	f.Add(int64(-1))
	f.Add(int64(42))
	f.Add(int64(123))
	f.Add(int64(999))
	f.Add(int64(12345))
	f.Add(int64(9223372036854775807))  // max int64
	f.Add(int64(-9223372036854775808)) // min int64

	f.Fuzz(func(t *testing.T, seed int64) {
		var buf bytes.Buffer
		spec := Spec{
			Profile: ProfileFuzz,
			Seed:    seed,
			Limits:  fuzzLimits,
		}

		result, err := Generate(&buf, spec)
		if err != nil {
			// Generation can legitimately fail for some configurations
			return
		}

		// Verify result is reasonable
		if result.ArchiveSize < 0 {
			t.Errorf("negative archive size: %d", result.ArchiveSize)
		}
		if result.DeclaredSize < 0 {
			t.Errorf("negative declared size: %d", result.DeclaredSize)
		}
		if result.FileCount < 0 {
			t.Errorf("negative file count: %d", result.FileCount)
		}
		if result.DirCount < 0 {
			t.Errorf("negative dir count: %d", result.DirCount)
		}

		// Verify the buffer actually contains data
		if buf.Len() == 0 {
			t.Error("generated archive is empty")
		}

		// Verify the archive size matches what we wrote
		if int64(buf.Len()) != result.ArchiveSize {
			t.Errorf("archive size mismatch: got %d bytes, result claims %d", buf.Len(), result.ArchiveSize)
		}

		// Generation must respect the bounds it was given.
		if result.DeclaredSize > fuzzLimits.MaxOutputBytes {
			t.Errorf("declared %d bytes, above the %d-byte limit",
				result.DeclaredSize, fuzzLimits.MaxOutputBytes)
		}
		if result.FileCount > fuzzLimits.MaxFiles {
			t.Errorf("generated %d files, above the %d-file limit",
				result.FileCount, fuzzLimits.MaxFiles)
		}
		if result.MaxDepth > fuzzLimits.MaxDepth {
			t.Errorf("nested %d deep, above the depth limit of %d",
				result.MaxDepth, fuzzLimits.MaxDepth)
		}
		if result.Nesting > fuzzLimits.MaxNesting {
			t.Errorf("nested %d archives, above the limit of %d",
				result.Nesting, fuzzLimits.MaxNesting)
		}
	})
}
