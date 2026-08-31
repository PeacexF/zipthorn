package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/PeacexF/zipthorn/internal/generator"
)

func runFuzz(args []string, stdout, stderr io.Writer) error {
	var cf commonFlags
	fs := newFlagSet("fuzz", stderr, &cf)

	var output string
	var seed int64
	var count int

	fs.StringVar(&output, "output", "./fixtures", "output directory")
	fs.Int64Var(&seed, "seed", 1, "starting seed value")
	fs.IntVar(&count, "count", 10, "number of fixtures to generate")

	fs.Usage = usageFunc(fs, stderr, "fuzz [options]",
		"Generate randomized test fixtures for fuzzing and robustness testing.")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return codef(ExitUsage, "unexpected arguments")
	}

	if count <= 0 {
		return codef(ExitUsage, "count must be positive")
	}

	// Create output directory
	if err := os.MkdirAll(output, 0755); err != nil {
		return coded(ExitError, fmt.Errorf("cannot create output directory: %w", err))
	}

	out := newOutput(stdout, stderr, cf.json)

	if cf.json {
		return runFuzzJSON(output, seed, count, out)
	}

	out.Line("zipthorn")
	out.Line("")
	out.Line("Generating %d fuzz fixtures in %s", count, output)
	out.Line("Starting seed: %d", seed)
	out.Line("")

	// Generate fixtures
	for i := 0; i < count; i++ {
		s := seed + int64(i)
		filename := fmt.Sprintf("fuzz-%05d.zip", i+1)
		path := filepath.Join(output, filename)

		spec := generator.Spec{
			Profile: generator.ProfileFuzz,
			Seed:    s,
		}

		// Create the output file
		f, err := os.Create(path)
		if err != nil {
			return coded(ExitError, fmt.Errorf("failed to create %s: %w", filename, err))
		}
		bw := bufio.NewWriter(f)

		_, genErr := generator.Generate(bw, spec)
		if genErr == nil {
			genErr = bw.Flush()
		}
		closeErr := f.Close()

		if genErr != nil {
			os.Remove(path)
			return coded(ExitError, fmt.Errorf("failed to generate %s: %w", filename, genErr))
		}
		if closeErr != nil {
			return coded(ExitError, fmt.Errorf("failed to close %s: %w", filename, closeErr))
		}

		out.Line("  [%3d/%3d] %s (seed=%d)", i+1, count, filename, s)
	}

	out.Line("")
	out.Line("Complete")
	out.Line("  Fixtures: %d", count)
	out.Line("  Directory: %s", output)

	return nil
}

func runFuzzJSON(output string, seed int64, count int, out *output) error {
	type result struct {
		Fixtures  []string `json:"fixtures"`
		Directory string   `json:"directory"`
		Count     int      `json:"count"`
		StartSeed int64    `json:"start_seed"`
	}

	var fixtures []string

	for i := 0; i < count; i++ {
		s := seed + int64(i)
		filename := fmt.Sprintf("fuzz-%05d.zip", i+1)
		path := filepath.Join(output, filename)

		spec := generator.Spec{
			Profile: generator.ProfileFuzz,
			Seed:    s,
		}

		// Create the output file
		f, err := os.Create(path)
		if err != nil {
			return coded(ExitError, fmt.Errorf("failed to create %s: %w", filename, err))
		}
		bw := bufio.NewWriter(f)

		_, genErr := generator.Generate(bw, spec)
		if genErr == nil {
			genErr = bw.Flush()
		}
		closeErr := f.Close()

		if genErr != nil {
			os.Remove(path)
			return coded(ExitError, fmt.Errorf("failed to generate %s: %w", filename, genErr))
		}
		if closeErr != nil {
			return coded(ExitError, fmt.Errorf("failed to close %s: %w", filename, closeErr))
		}

		fixtures = append(fixtures, filename)
	}

	r := result{
		Fixtures:  fixtures,
		Directory: output,
		Count:     count,
		StartSeed: seed,
	}

	return out.Emit(r, nil)
}
