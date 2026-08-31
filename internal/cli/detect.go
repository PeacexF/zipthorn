package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/detector"
)

var categoryLabels = map[string]string{
	detector.CategoryCompression: "Compression",
	detector.CategoryFileCount:   "File count",
	detector.CategoryNesting:     "Nesting",
	detector.CategoryPaths:       "Paths",
}

func runDetect(args []string, stdout, stderr io.Writer) error {
	var cf commonFlags
	var policyName string
	fs := newFlagSet("detect", stderr, &cf)

	res, err := loadConfig()
	if err != nil {
		return coded(ExitError, fmt.Errorf("config: %w", err))
	}

	th := res.Config.Thresholds
	fs.StringVar(&policyName, "policy", "", "use a named detection policy (default, strict, permissive, web, ci)")
	fs.Float64Var(&th.ExpansionRatio, "threshold-ratio", th.ExpansionRatio, "expansion ratio treated as HIGH risk")
	sizeVar(fs, &th.DeclaredSize, "threshold-size", "declared output size treated as HIGH risk")
	fs.Int64Var(&th.FileCount, "threshold-files", th.FileCount, "file count treated as HIGH risk")
	fs.IntVar(&th.Depth, "threshold-depth", th.Depth, "directory depth treated as HIGH risk")
	fs.IntVar(&th.Nesting, "threshold-nesting", th.Nesting, "nested-archive count treated as HIGH risk")

	fs.Usage = usageFunc(fs, stderr, "detect [options] <archive>",
		"Assess an archive's risk without extracting it.")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return codef(ExitUsage, "expected exactly one archive path")
	}
	markFlagOverrides(fs, res, thresholdFlagKeys)

	info, err := archive.Open(fs.Arg(0))
	if err != nil {
		code := ExitError
		if errors.Is(err, archive.ErrInvalidArchive) {
			code = ExitRisk
		}
		return coded(code, err)
	}

	var a detector.Assessment
	if policyName != "" {
		a, err = detector.AssessWithPolicy(info, policyName)
		if err != nil {
			return coded(ExitError, err)
		}
		// A named policy supersedes every configured threshold.
		res.SetThresholds(a.Thresholds, config.LayerPolicy, policyName)
	} else {
		res.Config.Thresholds = th
		a = detector.Assess(info, th)
	}

	out := newOutput(stdout, stderr, cf.json)
	if err := out.Emit(withConfig(&a, res), func(w io.Writer) { writeDetect(w, &a, res, cf) }); err != nil {
		return err
	}
	if a.Recommendation == detector.Reject {
		// A rejection is a verdict, not a failure, so it carries no message.
		return coded(ExitRisk, nil)
	}
	return nil
}

func writeDetect(w io.Writer, a *detector.Assessment, res *config.Resolved, cf commonFlags) {
	f := a.Features
	if cf.quiet {
		fmt.Fprintf(w, "%s %s score %d/100%s\n",
			a.Recommendation, a.Level, a.Score, indicatorIDs(a))
		return
	}

	fmt.Fprint(w, "zipthorn\n")

	section(w, "Archive")
	if a.Path != "" {
		field(w, "Path", a.Path)
	}
	field(w, "Compressed", humanBytes(f.ArchiveSize))
	field(w, "Declared output", humanBytes(f.DeclaredSize))
	field(w, "Expansion", humanRatio(f.ExpansionRatio))
	field(w, "Files", humanCount(f.FileCount))
	field(w, "Max depth", humanCount(int64(f.MaxDepth)))

	section(w, "Risk")
	for _, c := range a.Categories {
		field(w, categoryLabels[c.Name], c.Level.String())
	}

	if len(a.Indicators) > 0 {
		section(w, "Indicators")
		for _, in := range a.Indicators {
			fmt.Fprintf(w, "  %-6s %-24s %s\n", in.Level, in.ID, in.Detail)
			if cf.verbose {
				for _, e := range in.Evidence {
					fmt.Fprintf(w, "  %-6s %-24s   %s\n", "", "", e)
				}
			}
		}
	}

	if cf.verbose {
		writeConfig(w, res)
	}

	fmt.Fprintf(w, "\nScore: %d/100\n", a.Score)
	fmt.Fprintf(w, "Recommendation: %s\n", a.Recommendation)
}

func indicatorIDs(a *detector.Assessment) string {
	if len(a.Indicators) == 0 {
		return ""
	}
	ids := make([]string, 0, len(a.Indicators))
	for _, in := range a.Indicators {
		ids = append(ids, in.ID)
	}
	return " " + strings.Join(ids, ",")
}
