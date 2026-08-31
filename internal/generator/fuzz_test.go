package generator

import (
	"bytes"
	"testing"
)

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

		// Verify no panics occurred (implicit - if we got here, no panic)
	})
}
