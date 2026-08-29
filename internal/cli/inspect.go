package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/PeacexF/zipthorn/internal/archive"
)

func runInspect(args []string, stdout, stderr io.Writer) error {
	var cf commonFlags
	fs := newFlagSet("inspect", stderr, &cf)
	fs.Usage = usageFunc(fs, stderr, "inspect <archive>", "Analyze an archive's metadata without extracting it.")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return codef(ExitUsage, "expected exactly one archive path")
	}

	info, err := archive.Open(fs.Arg(0))
	if err != nil {
		code := ExitError
		if errors.Is(err, archive.ErrInvalidArchive) {
			code = ExitRisk
		}
		return coded(code, err)
	}

	// The entry list is unbounded, so it rides along only when asked for.
	report := *info
	if !cf.verbose {
		report.Entries = nil
	}

	out := newOutput(stdout, stderr, cf.json)
	return out.Emit(&report, func(w io.Writer) { writeInspect(w, info, cf) })
}

func writeInspect(w io.Writer, info *archive.Info, cf commonFlags) {
	if cf.quiet {
		fmt.Fprintf(w, "%s -> %s (%s) %s files, depth %d\n",
			humanBytes(info.ArchiveSize), humanBytes(info.DeclaredSize),
			humanRatio(info.ExpansionRatio), humanCount(info.FileCount), info.MaxDepth)
		return
	}

	fmt.Fprint(w, "zipthorn\n")

	section(w, "Archive")
	if info.Path != "" {
		field(w, "Path", info.Path)
	}
	field(w, "Compressed", humanBytes(info.ArchiveSize))
	field(w, "Declared output", humanBytes(info.DeclaredSize))
	field(w, "Expansion", humanRatio(info.ExpansionRatio))
	field(w, "Files", humanCount(info.FileCount))
	field(w, "Directories", humanCount(info.DirCount))
	field(w, "Max depth", humanCount(int64(info.MaxDepth)))

	section(w, "Compression")
	for _, m := range info.Methods {
		label := m.Name
		if !archive.Supported(m.Method) {
			label += " (unsupported)"
		}
		field(w, label, plural(m.Count, "entry", "entries"))
	}
	if len(info.Methods) == 0 {
		field(w, "none", "empty archive")
	}

	writeInspectNotes(w, info)

	if cf.verbose {
		section(w, "Entries")
		for _, e := range info.Entries {
			fmt.Fprintf(w, "  %-10s %10s %10s  %s\n",
				e.MethodName, humanBytes(e.CompressedSize),
				humanBytes(e.UncompressedSize), e.Name)
		}
	}
}

func writeInspectNotes(w io.Writer, info *archive.Info) {
	if len(info.Duplicates) == 0 && len(info.NestedArchives) == 0 &&
		!info.Encrypted && info.Comment == "" {
		return
	}

	section(w, "Notes")
	if n := len(info.Duplicates); n > 0 {
		field(w, "Duplicate names", humanCount(int64(n)))
	}
	if n := len(info.NestedArchives); n > 0 {
		field(w, "Nested archives", humanCount(int64(n)))
	}
	if info.Encrypted {
		field(w, "Encrypted", "yes")
	}
	if info.Comment != "" {
		field(w, "Comment", fmt.Sprintf("%d bytes", len(info.Comment)))
	}
}
