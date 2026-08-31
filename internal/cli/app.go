// Package cli implements zipthorn's command-line interface.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Version information, set by main via SetVersion.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// SetVersion sets the version information for display.
func SetVersion(v, c, d string) {
	version, commit, date = v, c, d
}

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) error
}

var commands = []command{
	{"create", "Generate a controlled test archive", runCreate},
	{"inspect", "Analyze an archive", runInspect},
	{"detect", "Assess archive risk", runDetect},
	{"test", "Safely test archive extraction", runTest},
	{"benchmark", "Measure archive extraction performance", runBenchmark},
	{"fuzz", "Generate fuzz fixtures for testing", runFuzz},
	{"policy", "Show detection policy details", runPolicyCmd},
}

// Main runs the requested command and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return ExitOK
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "zipthorn %s\n", version)
		if commit != "none" {
			fmt.Fprintf(stdout, "commit: %s\n", commit)
		}
		if date != "unknown" {
			fmt.Fprintf(stdout, "built: %s\n", date)
		}
		return ExitOK
	}

	cmd := lookup(args[0])
	if cmd == nil {
		fmt.Fprintf(stderr, "zipthorn: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}

	err := cmd.run(args[1:], stdout, stderr)
	if err == nil {
		return ExitOK
	}
	if ce, ok := errors.AsType[*CodedError](err); ok {
		if ce.Err != nil {
			fmt.Fprintf(stderr, "zipthorn %s: %v\n", cmd.name, ce.Err)
		}
		return ce.Code
	}
	fmt.Fprintf(stderr, "zipthorn %s: %v\n", cmd.name, err)
	return ExitError
}

func Run() int {
	return Main(os.Args[1:], os.Stdout, os.Stderr)
}

func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, "zipthorn — defensive ZIP-archive security-testing toolkit\n\n")
	fmt.Fprint(w, "Usage:\n  zipthorn <command> [options]\n\n")
	fmt.Fprint(w, "Commands:\n")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nGlobal:\n")
	fmt.Fprintf(w, "  %-12s %s\n", "--help", "Show this help")
	fmt.Fprintf(w, "  %-12s %s\n", "--version", "Show version")
	fmt.Fprint(w, "\nRun 'zipthorn <command> --help' for command-specific options.\n")
}
