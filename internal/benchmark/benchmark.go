// Package benchmark provides archive extraction performance measurement.
package benchmark

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/extractor"
)

// Metrics captures the performance characteristics of an extraction operation.
type Metrics struct {
	// Archive characteristics
	ArchivePath     string  `json:"archive_path"`
	CompressedBytes int64   `json:"compressed_bytes"`
	DeclaredBytes   int64   `json:"declared_bytes"`
	ExtractedBytes  int64   `json:"extracted_bytes"`
	ExpansionRatio  float64 `json:"expansion_ratio"`
	FileCount       int64   `json:"file_count"`
	DirectoryCount  int64   `json:"directory_count"`
	MaxDepth        int     `json:"max_depth"`
	ArchiveNesting  int     `json:"archive_nesting"`

	// Performance metrics
	WallTimeNanos   int64   `json:"wall_time_nanos"`
	CPUTimeNanos    int64   `json:"cpu_time_nanos"`
	ThroughputMBps  float64 `json:"throughput_mbps"`
	FilesPerSecond  float64 `json:"files_per_second"`
	AllocBytes      uint64  `json:"alloc_bytes"`
	TotalAllocBytes uint64  `json:"total_alloc_bytes"`
	Mallocs         uint64  `json:"mallocs"`
	HeapAllocBytes  uint64  `json:"heap_alloc_bytes"`

	// Result
	Status string `json:"status"` // COMPLETE, LIMIT_REACHED, ERROR
	Error  string `json:"error,omitempty"`
}

// AggregateMetrics holds statistics across multiple runs.
type AggregateMetrics struct {
	Runs            int     `json:"runs"`
	MeanWallNanos   int64   `json:"mean_wall_nanos"`
	MinWallNanos    int64   `json:"min_wall_nanos"`
	MaxWallNanos    int64   `json:"max_wall_nanos"`
	MeanCPUNanos    int64   `json:"mean_cpu_nanos"`
	MeanThroughput  float64 `json:"mean_throughput_mbps"`
	MeanFilesPerSec float64 `json:"mean_files_per_second"`
	TotalAllocBytes uint64  `json:"total_alloc_bytes"`
	TotalMallocs    uint64  `json:"total_mallocs"`
}

// Run extracts an archive once and returns performance metrics.
func Run(ctx context.Context, archivePath string, limits config.Limits, destDir string, cleanOnFailure bool) (*Metrics, error) {
	// Open archive to read metadata
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat archive: %w", err)
	}
	archiveSize := stat.Size()

	info, err := archive.Read(f, archiveSize)
	if err != nil {
		return nil, fmt.Errorf("read archive: %w", err)
	}

	m := &Metrics{
		ArchivePath:     archivePath,
		CompressedBytes: info.CompressedSize,
		DeclaredBytes:   info.DeclaredSize,
		ExpansionRatio:  info.ExpansionRatio,
		FileCount:       info.FileCount,
		DirectoryCount:  info.DirCount,
		MaxDepth:        info.MaxDepth,
		ArchiveNesting:  len(info.NestedArchives),
	}

	// Capture memory before
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Measure CPU time before
	cpuStart := getCPUTime()

	// Measure wall time
	start := time.Now()

	opts := extractor.Options{
		Limits:      limits,
		Sink:        extractor.DirSink(destDir),
		CleanOnFail: cleanOnFailure,
	}
	result := extractor.Extract(ctx, f, archiveSize, opts)

	elapsed := time.Since(start)
	cpuElapsed := getCPUTime() - cpuStart

	// Capture memory after
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	m.WallTimeNanos = elapsed.Nanoseconds()
	m.CPUTimeNanos = cpuElapsed
	m.ExtractedBytes = result.BytesProduced
	m.Status = string(result.Status)

	if result.Error != "" {
		m.Error = result.Error
	}

	// Calculate throughput
	seconds := elapsed.Seconds()
	if seconds > 0 {
		m.ThroughputMBps = float64(result.BytesProduced) / seconds / (1024 * 1024)
		m.FilesPerSecond = float64(result.FilesProcessed) / seconds
	}

	// Memory metrics
	m.AllocBytes = memAfter.Alloc - memBefore.Alloc
	m.TotalAllocBytes = memAfter.TotalAlloc - memBefore.TotalAlloc
	m.Mallocs = memAfter.Mallocs - memBefore.Mallocs
	m.HeapAllocBytes = memAfter.HeapAlloc - memBefore.HeapAlloc

	return m, nil
}

// RunMultiple executes multiple benchmark runs and returns individual results plus aggregate stats.
func RunMultiple(ctx context.Context, archivePath string, limits config.Limits, destDir string, cleanOnFailure bool, runs int) ([]*Metrics, *AggregateMetrics, error) {
	if runs < 1 {
		return nil, nil, fmt.Errorf("runs must be at least 1")
	}

	results := make([]*Metrics, 0, runs)
	var sumWall, sumCPU int64
	var sumThroughput, sumFilesPerSec float64
	var totalAlloc, totalMallocs uint64
	var minWall, maxWall int64

	for i := 0; i < runs; i++ {
		m, err := Run(ctx, archivePath, limits, destDir, cleanOnFailure)
		if err != nil {
			return results, nil, fmt.Errorf("run %d: %w", i+1, err)
		}

		results = append(results, m)

		sumWall += m.WallTimeNanos
		sumCPU += m.CPUTimeNanos
		sumThroughput += m.ThroughputMBps
		sumFilesPerSec += m.FilesPerSecond
		totalAlloc += m.TotalAllocBytes
		totalMallocs += m.Mallocs

		if i == 0 || m.WallTimeNanos < minWall {
			minWall = m.WallTimeNanos
		}
		if i == 0 || m.WallTimeNanos > maxWall {
			maxWall = m.WallTimeNanos
		}
	}

	agg := &AggregateMetrics{
		Runs:            runs,
		MeanWallNanos:   sumWall / int64(runs),
		MinWallNanos:    minWall,
		MaxWallNanos:    maxWall,
		MeanCPUNanos:    sumCPU / int64(runs),
		MeanThroughput:  sumThroughput / float64(runs),
		MeanFilesPerSec: sumFilesPerSec / float64(runs),
		TotalAllocBytes: totalAlloc,
		TotalMallocs:    totalMallocs,
	}

	return results, agg, nil
}

// getCPUTime returns the current CPU time in nanoseconds.
// This is a rough approximation using runtime data.
func getCPUTime() int64 {
	var ru runtime.MemStats
	runtime.ReadMemStats(&ru)
	// Note: Go's runtime doesn't expose direct CPU time per goroutine
	// We use wall time as a proxy here. For true CPU time, platform-specific
	// syscalls would be needed (getrusage on Unix, GetProcessTimes on Windows).
	return time.Now().UnixNano()
}
