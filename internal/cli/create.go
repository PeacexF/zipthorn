package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/generator"
)

func runCreate(args []string, stdout, stderr io.Writer) error {
	res, err := loadConfig()
	if err != nil {
		return coded(ExitError, fmt.Errorf("config: %w", err))
	}

	var (
		cf    commonFlags
		out   string
		force bool
		spec  generator.Spec
	)
	limits := res.Config.Limits
	spec.Level = generator.LevelDefault

	fs := newFlagSet("create", stderr, &cf)
	fs.StringVar(&out, "output", "", "path to write the archive to (required)")
	fs.StringVar(&spec.Profile, "profile", generator.ProfileRatio,
		"fixture profile: "+strings.Join(generator.Profiles(), ", "))
	fs.Int64Var(&spec.Seed, "seed", 0, "seed for deterministic generation")
	sizeVar(fs, &spec.DeclaredSize, "declared-size", "uncompressed bytes to generate")
	fs.Int64Var(&spec.FileCount, "files", 0, "number of entries to generate")
	sizeVar(fs, &spec.FileSize, "file-size", "uncompressed size of each generated entry")
	ratioVar(fs, &spec.Ratio, "ratio", "target expansion ratio of generated payloads")
	fs.IntVar(&spec.Depth, "depth", 0, "directory nesting depth")
	fs.IntVar(&spec.Nesting, "nesting", 0, "archive-within-archive levels")
	fs.IntVar(&spec.Level, "level", generator.LevelDefault, "deflate level (-2..9; 0 selects the default)")
	sizeVar(fs, &limits.MaxOutputBytes, "max-output", "safety limit on total uncompressed output")
	ratioVar(fs, &limits.MaxExpansionRatio, "max-expansion", "safety limit on expansion ratio")
	fs.Int64Var(&limits.MaxFiles, "max-files", limits.MaxFiles, "safety limit on entry count")
	fs.IntVar(&limits.MaxDepth, "max-depth", limits.MaxDepth, "safety limit on directory depth")
	fs.IntVar(&limits.MaxNesting, "max-nesting", limits.MaxNesting, "safety limit on archive nesting")
	fs.BoolVar(&force, "force", false, "overwrite an existing output file")

	fs.Usage = usageFunc(fs, stderr, "create [options] --output <archive>",
		"Generate a bounded, deterministic test archive.")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return codef(ExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	if out == "" {
		fs.Usage()
		return codef(ExitUsage, "--output is required")
	}
	markFlagOverrides(fs, res, limitFlagKeys("max-output", "max-expansion"))
	res.Config.Limits = limits
	spec.Limits = limits

	gen, err := create(out, force, spec)
	if err != nil {
		return err
	}

	o := newOutput(stdout, stderr, cf.json)
	return o.Emit(withConfig(gen, res), func(w io.Writer) { writeCreate(w, gen, res, cf) })
}

// create writes the fixture, leaving no output behind if generation fails:
// a partial fixture is worse than none.
func create(path string, force bool, spec generator.Spec) (*generator.Result, error) {
	mode := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		mode = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, mode, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, codef(ExitError, "%s already exists (use --force to overwrite)", path)
		}
		return nil, coded(ExitError, err)
	}

	bw := bufio.NewWriter(f)
	res, genErr := generator.Generate(bw, spec)
	if genErr == nil {
		genErr = bw.Flush()
	}
	if closeErr := f.Close(); genErr == nil {
		genErr = closeErr
	}
	if genErr != nil {
		os.Remove(path)
		return nil, coded(exitFor(genErr), genErr)
	}

	res.Path = path
	return res, nil
}

func exitFor(err error) int {
	switch {
	case errors.Is(err, generator.ErrLimitExceeded):
		return ExitRisk
	case errors.Is(err, generator.ErrUnknownProfile):
		return ExitUsage
	default:
		return ExitError
	}
}

func writeCreate(w io.Writer, r *generator.Result, res *config.Resolved, cf commonFlags) {
	if cf.quiet {
		fmt.Fprintf(w, "%s %s %s -> %s (%s) %s files\n",
			r.Path, r.Profile, humanBytes(r.ArchiveSize), humanBytes(r.DeclaredSize),
			humanRatio(r.ExpansionRatio), humanCount(r.FileCount))
		return
	}

	fmt.Fprint(w, "zipthorn\n")

	section(w, "Created")
	field(w, "Path", r.Path)
	field(w, "Profile", r.Profile)
	field(w, "Seed", humanCount(r.Seed))

	section(w, "Archive")
	field(w, "Compressed", humanBytes(r.ArchiveSize))
	field(w, "Declared output", humanBytes(r.DeclaredSize))
	field(w, "Expansion", humanRatio(r.ExpansionRatio))
	field(w, "Files", humanCount(r.FileCount))
	field(w, "Directories", humanCount(r.DirCount))
	field(w, "Max depth", humanCount(int64(r.MaxDepth)))
	field(w, "Archive nesting", humanCount(int64(r.Nesting)))

	if cf.verbose {
		writeConfig(w, res)
	}
}
