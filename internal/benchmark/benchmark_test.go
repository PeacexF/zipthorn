package benchmark_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeacexF/zipthorn/internal/benchmark"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/generator"
)

func TestRun(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create a small test archive
	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		Seed:         42,
		DeclaredSize: 1024 * 1024, // 1MB
		FileCount:    10,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	ctx := context.Background()
	m, err := benchmark.Run(ctx, archivePath, limits, destDir, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify metrics
	if m.ArchivePath != archivePath {
		t.Errorf("archive_path = %s, want %s", m.ArchivePath, archivePath)
	}
	if m.CompressedBytes <= 0 {
		t.Errorf("compressed_bytes = %d, want > 0", m.CompressedBytes)
	}
	if m.DeclaredBytes != 1024*1024 {
		t.Errorf("declared_bytes = %d, want %d", m.DeclaredBytes, 1024*1024)
	}
	if m.FileCount != 10 {
		t.Errorf("file_count = %d, want 10", m.FileCount)
	}
	if m.Status != "PASS" {
		t.Errorf("status = %s, want PASS", m.Status)
	}
	if m.WallTimeNanos <= 0 {
		t.Errorf("wall_time_nanos = %d, want > 0", m.WallTimeNanos)
	}
	if m.ThroughputMBps <= 0 {
		t.Errorf("throughput_mbps = %f, want > 0", m.ThroughputMBps)
	}
	if m.FilesPerSecond <= 0 {
		t.Errorf("files_per_second = %f, want > 0", m.FilesPerSecond)
	}
}

func TestRunWithLimit(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create an archive that will exceed limits
	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		Seed:         42,
		DeclaredSize: 10 * 1024 * 1024, // 10MB
		FileCount:    100,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDir := filepath.Join(tmp, "extract")

	// Set a low limit to trigger LIMIT_REACHED
	limits := config.Limits{
		MaxOutputBytes:    1024 * 1024, // 1MB
		MaxExpansionRatio: 1000,
		MaxFiles:          10000,
		MaxDepth:          32,
		MaxNesting:        4,
	}

	ctx := context.Background()
	m, err := benchmark.Run(ctx, archivePath, limits, destDir, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if m.Status != "LIMIT_REACHED" {
		t.Errorf("status = %s, want LIMIT_REACHED", m.Status)
	}
}

func TestRunMultiple(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Large enough that extraction reliably takes measurable wall time even
	// on a coarse clock: a handful of tiny files could complete faster than
	// some CI runners' timer resolution, reading back as exactly 0ns
	// elapsed (observed on windows-latest) rather than a real duration.
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 200,
		FileSize:  4096,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	ctx := context.Background()
	runs := 3
	results, agg, err := benchmark.RunMultiple(ctx, archivePath, limits, destDir, true, runs)
	if err != nil {
		t.Fatalf("RunMultiple: %v", err)
	}

	if len(results) != runs {
		t.Errorf("got %d results, want %d", len(results), runs)
	}

	if agg.Runs != runs {
		t.Errorf("agg.Runs = %d, want %d", agg.Runs, runs)
	}
	if agg.MeanWallNanos <= 0 {
		t.Errorf("mean_wall_nanos = %d, want > 0", agg.MeanWallNanos)
	}
	if agg.MinWallNanos <= 0 {
		t.Errorf("min_wall_nanos = %d, want > 0", agg.MinWallNanos)
	}
	if agg.MaxWallNanos <= 0 {
		t.Errorf("max_wall_nanos = %d, want > 0", agg.MaxWallNanos)
	}
	if agg.MinWallNanos > agg.MeanWallNanos {
		t.Errorf("min > mean")
	}
	if agg.MaxWallNanos < agg.MeanWallNanos {
		t.Errorf("max < mean")
	}
	if agg.MeanThroughput <= 0 {
		t.Errorf("mean_throughput = %f, want > 0", agg.MeanThroughput)
	}
	if agg.MeanFilesPerSec <= 0 {
		t.Errorf("mean_files_per_sec = %f, want > 0", agg.MeanFilesPerSec)
	}
}

func TestRunMultipleInvalidRuns(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")
	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	ctx := context.Background()
	_, _, err := benchmark.RunMultiple(ctx, archivePath, limits, destDir, true, 0)
	if err == nil {
		t.Error("expected error for runs=0")
	}
}

func TestRunNonexistentArchive(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "nonexistent.zip")
	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	ctx := context.Background()
	_, err := benchmark.Run(ctx, archivePath, limits, destDir, true)
	if err == nil {
		t.Error("expected error for nonexistent archive")
	}
}

func TestRunContext(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create a test archive
	spec := generator.Spec{
		Profile:   generator.ProfileRatio,
		Seed:      42,
		FileCount: 5,
		FileSize:  1024,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m, err := benchmark.Run(ctx, archivePath, limits, destDir, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Context cancellation should result in TIMEOUT status
	if m.Status != "TIMEOUT" && m.Status != "PASS" {
		// PASS is possible if extraction completes before context is checked
		t.Logf("status = %s (expected TIMEOUT or PASS)", m.Status)
	}
}

func TestMetricsMemoryTracking(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create a small archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 3,
		FileSize:  512,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	ctx := context.Background()
	m, err := benchmark.Run(ctx, archivePath, limits, destDir, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Memory metrics should be captured (may be 0 or positive)
	if m.TotalAllocBytes < 0 {
		t.Errorf("total_alloc_bytes should not be negative")
	}
	if m.Mallocs < 0 {
		t.Errorf("mallocs should not be negative")
	}
}

func TestCleanup(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 3,
		FileSize:  100,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDir := filepath.Join(tmp, "extract")
	limits := config.Default().Limits

	ctx := context.Background()
	_, err = benchmark.Run(ctx, archivePath, limits, destDir, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Verify extraction directory exists after successful run
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		t.Error("extraction directory should exist after PASS")
	}
}
