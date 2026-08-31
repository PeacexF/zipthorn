package extractor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/extractor"
	"github.com/PeacexF/zipthorn/internal/generator"
)

func TestExtract_Pass(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 2048,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		DestDir:     dest,
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusPass {
		t.Errorf("status = %s, want PASS; reason: %s", r.Status, r.Reason)
	}
	if r.FilesProcessed == 0 {
		t.Errorf("no files processed")
	}
	if r.BytesProduced == 0 {
		t.Errorf("no bytes produced")
	}
}

func TestExtract_ByteLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 10 * 1024 * 1024,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    8192,
			MaxExpansionRatio: 1000,
			MaxFiles:          1000,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		DestDir:     dest,
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Errorf("status = %s, want LIMIT_REACHED", r.Status)
	}
	if r.LimitReached != "bytes" {
		t.Errorf("limit reached = %s, want bytes", r.LimitReached)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("dest dir should be cleaned up on failure")
	}
}

func TestExtract_FileLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 16384,
		FileCount:    100,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          10,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		DestDir:     dest,
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Errorf("status = %s, want LIMIT_REACHED", r.Status)
	}
	if r.LimitReached != "files" {
		t.Errorf("limit reached = %s, want files", r.LimitReached)
	}
}

func TestExtract_Timeout(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 100 * 1024,
		FileCount:    10,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		DestDir:     dest,
		CleanOnFail: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(2 * time.Millisecond)

	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusTimeout {
		t.Errorf("status = %s, want TIMEOUT", r.Status)
	}
	if r.LimitReached != "timeout" {
		t.Errorf("limit reached = %s, want timeout", r.LimitReached)
	}
}

func TestExtract_InvalidArchive(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "bad.zip")
	dest := filepath.Join(tmp, "out")

	if err := os.WriteFile(archive, []byte("not a zip"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		DestDir:     dest,
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusInvalid {
		t.Errorf("status = %s, want INVALID_ARCHIVE", r.Status)
	}
}

func TestExtract_DepthLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileDepth,
		DeclaredSize: 2048,
		FileCount:    5,
		Depth:        20,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          1000,
			MaxDepth:          10,
			MaxNesting:        4,
		},
		DestDir:     dest,
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Errorf("status = %s, want LIMIT_REACHED", r.Status)
	}
	if r.LimitReached != "depth" {
		t.Errorf("limit reached = %s, want depth", r.LimitReached)
	}
}

func TestExtract_CleanupPreserved(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 16384,
		FileCount:    50,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          100,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		DestDir:     dest,
		CleanOnFail: false,
	}

	ctx := context.Background()
	r := extractor.Extract(ctx, archive, opts)

	if r.Status != extractor.StatusPass && r.Status != extractor.StatusLimitReached {
		t.Logf("status = %s (unexpected but not critical for this test)", r.Status)
	}

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		t.Errorf("dest dir should exist when CleanOnFail=false, got: %v", err)
	}
}
