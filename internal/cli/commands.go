package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

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

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
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

func runCreate(args []string, stdout, stderr io.Writer) error {
	return notImplemented("create", args, stdout, stderr)
}

func runDetect(args []string, stdout, stderr io.Writer) error {
	return notImplemented("detect", args, stdout, stderr)
}

func runTest(args []string, stdout, stderr io.Writer) error {
	return notImplemented("test", args, stdout, stderr)
}
