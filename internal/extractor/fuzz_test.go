package extractor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/generator"
)

// FuzzExtractor tests the extractor against randomized archives.
// Run with: go test -fuzz=FuzzExtractor -fuzztime=30s
func FuzzExtractor(f *testing.F) {
	// Seed corpus with a few known seeds
	f.Add(int64(1))
	f.Add(int64(42))
	f.Add(int64(123))
	f.Add(int64(999))
	f.Add(int64(12345))

	f.Fuzz(func(t *testing.T, seed int64) {
		// Generate a fuzz archive with this seed
		var buf bytes.Buffer
		spec := generator.Spec{
			Profile: generator.ProfileFuzz,
			Seed:    seed,
			// Keep each iteration cheap: the default 256MB budget is far too
			// heavy to build once per execution across parallel workers.
			Limits: config.Limits{
				MaxOutputBytes:    4 * config.MB,
				MaxExpansionRatio: 100,
				MaxFiles:          500,
				MaxDepth:          12,
				MaxNesting:        3,
			},
		}

		_, err := generator.Generate(&buf, spec)
		if err != nil {
			t.Skip("generator failed (expected for some seeds)")
		}

		// Write to temp file
		tmpDir := t.TempDir()
		archivePath := filepath.Join(tmpDir, "fuzz.zip")
		if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
			t.Fatalf("failed to write archive: %v", err)
		}

		// Extract with safe limits
		opts := Options{
			Limits: config.Limits{
				MaxOutputBytes:    2 * config.MB,
				MaxFiles:          400,
				MaxDepth:          10,
				MaxNesting:        3,
				MaxExpansionRatio: 100,
			},
			DestDir:     filepath.Join(tmpDir, "extracted"),
			CleanOnFail: true,
		}

		ctx := context.Background()

		result := Extract(ctx, archivePath, opts)

		// We don't care if extraction fails - we just care that it doesn't crash
		// and that limits are respected
		if result.Status == StatusPass || result.Status == StatusLimitReached {
			// Check that output respects the limits
			if result.BytesProduced > opts.Limits.MaxOutputBytes {
				t.Errorf("bytes produced (%d) exceeded limit (%d)", result.BytesProduced, opts.Limits.MaxOutputBytes)
			}
			if result.FilesProcessed > opts.Limits.MaxFiles {
				t.Errorf("files processed (%d) exceeded limit (%d)", result.FilesProcessed, opts.Limits.MaxFiles)
			}
		}

		// Verify no panics occurred (implicit - if we got here, no panic)
	})
}
