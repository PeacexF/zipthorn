package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/PeacexF/zipthorn/internal/config"
)

type commonFlags struct {
	json    bool
	quiet   bool
	verbose bool
}

func newFlagSet(name string, stderr io.Writer, cf *commonFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&cf.json, "json", false, "emit machine-readable JSON")
	fs.BoolVar(&cf.quiet, "quiet", false, "suppress non-essential output")
	fs.BoolVar(&cf.verbose, "verbose", false, "emit additional detail")
	return fs
}

// usageFunc renders a command's own help, keeping the shape consistent with
// the top-level usage block.
func usageFunc(fs *flag.FlagSet, w io.Writer, use, summary string) func() {
	return func() {
		fmt.Fprintf(w, "%s\n\nUsage:\n  zipthorn %s\n\nOptions:\n", summary, use)
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
}

// permute moves operands after the flags so options can follow the archive
// path. Go's flag package stops at the first non-flag argument, which would
// silently ignore "zipthorn test archive.zip --max-bytes 64MB".
func permute(fs *flag.FlagSet, args []string) []string {
	flags := make([]string, 0, len(args))
	operands := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			operands = append(operands, arg)
			continue
		}

		flags = append(flags, arg)

		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if hasValue {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // unknown flag: let Parse produce the error
		}
		if b, ok := f.Value.(boolFlag); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}

	return append(flags, operands...)
}

// boolFlag matches the flag package's own unexported interface for options
// that take no value.
type boolFlag interface{ IsBoolFlag() bool }

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(permute(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return coded(ExitOK, nil) // usage has already been printed
		}
		return coded(ExitUsage, err)
	}
	return nil
}

func notImplemented(name string, args []string, stdout, stderr io.Writer) error {
	var cf commonFlags
	fs := newFlagSet(name, stderr, &cf)
	if err := parse(fs, args); err != nil {
		return err
	}

	_ = config.Default() // wired now so later milestones extend, not introduce, the config surface

	out := newOutput(stdout, stderr, cf.json)
	_ = out.Emit(
		map[string]any{"command": name, "status": "not_implemented"},
		func(w io.Writer) { out.Line("zipthorn %s: not implemented yet", name) },
	)
	return codef(ExitUnsupported, "%s is not implemented yet", name)
}
