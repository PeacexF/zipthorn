package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PeacexF/zipthorn/internal/benchmark"
)

func runBenchmark(args []string, stdout, stderr io.Writer) error {
	res, err := loadConfig()
	if err != nil {
		return coded(ExitError, fmt.Errorf("config: %w", err))
	}

	var cf commonFlags
	fs := newFlagSet("benchmark", stderr, &cf)

	limits := res.Config.Limits
	sizeVar(fs, &limits.MaxOutputBytes, "max-bytes", "maximum bytes to extract")
	ratioVar(fs, &limits.MaxExpansionRatio, "max-ratio", "maximum expansion ratio")
	fs.Int64Var(&limits.MaxFiles, "max-files", limits.MaxFiles, "maximum files to extract")
	fs.IntVar(&limits.MaxDepth, "max-depth", limits.MaxDepth, "maximum directory depth")
	fs.IntVar(&limits.MaxNesting, "max-nesting", limits.MaxNesting, "maximum nested archives")

	var destDir string
	var timeoutSec int
	var runs int
	var noClean bool

	fs.StringVar(&destDir, "dest", "", "extraction destination (default: temp dir)")
	fs.IntVar(&timeoutSec, "timeout", 0, "timeout in seconds (0 = no timeout)")
	fs.IntVar(&runs, "runs", 1, "number of benchmark runs")
	fs.BoolVar(&noClean, "no-clean", false, "preserve output on failure")

	fs.Usage = usageFunc(fs, stderr, "benchmark [options] <archive>",
		"Measure archive extraction performance.")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return codef(ExitUsage, "expected exactly one archive path")
	}
	markFlagOverrides(fs, res, limitFlagKeys("max-bytes", "max-ratio"))
	res.Config.Limits = limits

	archivePath := fs.Arg(0)
	if _, err := os.Stat(archivePath); err != nil {
		return coded(ExitError, err)
	}

	if runs < 1 {
		return codef(ExitUsage, "runs must be at least 1")
	}

	ctx := context.Background()
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	// Use temp dir if no dest specified
	if destDir == "" {
		destDir, err = os.MkdirTemp("", "zipthorn-bench-*")
		if err != nil {
			return coded(ExitError, fmt.Errorf("create temp dir: %w", err))
		}
		defer os.RemoveAll(destDir)
	}

	cleanOnFailure := !noClean

	if runs == 1 {
		// Single run
		m, err := benchmark.Run(ctx, archivePath, limits, destDir, cleanOnFailure)
		if err != nil {
			return coded(ExitError, err)
		}

		if cf.json {
			return printJSON(stdout, withConfig(m, res))
		}

		printBenchmarkSingle(stdout, m)
		if cf.verbose {
			writeConfig(stdout, res)
		}
		return nil
	}

	// Multiple runs
	results, agg, err := benchmark.RunMultiple(ctx, archivePath, limits, destDir, cleanOnFailure, runs)
	if err != nil {
		return coded(ExitError, err)
	}

	if cf.json {
		output := map[string]any{
			"runs":      results,
			"aggregate": agg,
		}
		return printJSON(stdout, withConfig(output, res))
	}

	printBenchmarkMultiple(stdout, results, agg)
	if cf.verbose {
		writeConfig(stdout, res)
	}
	return nil
}

func printBenchmarkSingle(w io.Writer, m *benchmark.Metrics) {
	fmt.Fprintln(w, "zipthorn")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Archive")
	fmt.Fprintf(w, "  Path:             %s\n", m.ArchivePath)
	fmt.Fprintf(w, "  Compressed:       %s\n", humanBytes(m.CompressedBytes))
	fmt.Fprintf(w, "  Declared output:  %s\n", humanBytes(m.DeclaredBytes))
	fmt.Fprintf(w, "  Extracted:        %s\n", humanBytes(m.ExtractedBytes))
	fmt.Fprintf(w, "  Expansion:        %s\n", humanRatio(m.ExpansionRatio))
	fmt.Fprintf(w, "  Files:            %s\n", humanCount(m.FileCount))
	fmt.Fprintf(w, "  Directories:      %s\n", humanCount(m.DirectoryCount))
	fmt.Fprintf(w, "  Max depth:        %d\n", m.MaxDepth)
	fmt.Fprintf(w, "  Archive nesting:  %d\n", m.ArchiveNesting)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Performance")
	fmt.Fprintf(w, "  Wall time:        %s\n", humanDuration(time.Duration(m.WallTimeNanos)))
	fmt.Fprintf(w, "  Throughput:       %.2f MB/s\n", m.ThroughputMBps)
	fmt.Fprintf(w, "  Files/second:     %.1f\n", m.FilesPerSecond)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Memory")
	fmt.Fprintf(w, "  Allocated:        %s\n", humanBytes(int64(m.AllocBytes)))
	fmt.Fprintf(w, "  Total alloc:      %s\n", humanBytes(int64(m.TotalAllocBytes)))
	fmt.Fprintf(w, "  Mallocs:          %s\n", humanCount(int64(m.Mallocs)))
	fmt.Fprintf(w, "  Heap alloc:       %s\n", humanBytes(int64(m.HeapAllocBytes)))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Result")
	fmt.Fprintf(w, "  Status:           %s\n", m.Status)
	if m.Error != "" {
		fmt.Fprintf(w, "  Error:            %s\n", m.Error)
	}
}

func printBenchmarkMultiple(w io.Writer, results []*benchmark.Metrics, agg *benchmark.AggregateMetrics) {
	fmt.Fprintln(w, "zipthorn")
	fmt.Fprintln(w)

	// Print first run details
	if len(results) > 0 {
		m := results[0]
		fmt.Fprintln(w, "Archive")
		fmt.Fprintf(w, "  Path:             %s\n", m.ArchivePath)
		fmt.Fprintf(w, "  Compressed:       %s\n", humanBytes(m.CompressedBytes))
		fmt.Fprintf(w, "  Declared output:  %s\n", humanBytes(m.DeclaredBytes))
		fmt.Fprintf(w, "  Expansion:        %s\n", humanRatio(m.ExpansionRatio))
		fmt.Fprintf(w, "  Files:            %s\n", humanCount(m.FileCount))
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Benchmark (%d runs)\n", agg.Runs)
	fmt.Fprintf(w, "  Mean wall time:   %s\n", humanDuration(time.Duration(agg.MeanWallNanos)))
	fmt.Fprintf(w, "  Min wall time:    %s\n", humanDuration(time.Duration(agg.MinWallNanos)))
	fmt.Fprintf(w, "  Max wall time:    %s\n", humanDuration(time.Duration(agg.MaxWallNanos)))
	fmt.Fprintf(w, "  Mean throughput:  %.2f MB/s\n", agg.MeanThroughput)
	fmt.Fprintf(w, "  Mean files/sec:   %.1f\n", agg.MeanFilesPerSec)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Memory (total across runs)")
	fmt.Fprintf(w, "  Total alloc:      %s\n", humanBytes(int64(agg.TotalAllocBytes)))
	fmt.Fprintf(w, "  Total mallocs:    %s\n", humanCount(int64(agg.TotalMallocs)))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Individual Runs")
	for i, m := range results {
		fmt.Fprintf(w, "  Run %d:  %s  (%.2f MB/s, %s)\n",
			i+1,
			humanDuration(time.Duration(m.WallTimeNanos)),
			m.ThroughputMBps,
			m.Status)
	}
}

func printJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
