package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/extractor"
)

func runTest(args []string, stdout, stderr io.Writer) error {
	var cf commonFlags
	fs := newFlagSet("test", stderr, &cf)

	res, err := loadConfig()
	if err != nil {
		return coded(ExitError, fmt.Errorf("config: %w", err))
	}

	limits := res.Config.Limits
	sizeVar(fs, &limits.MaxOutputBytes, "max-bytes", "maximum bytes to extract")
	ratioVar(fs, &limits.MaxExpansionRatio, "max-ratio", "maximum expansion ratio")
	fs.Int64Var(&limits.MaxFiles, "max-files", limits.MaxFiles, "maximum files to extract")
	fs.IntVar(&limits.MaxDepth, "max-depth", limits.MaxDepth, "maximum directory depth")
	fs.IntVar(&limits.MaxNesting, "max-nesting", limits.MaxNesting, "maximum nested archives")

	var destDir string
	var timeoutSec int
	var noClean bool

	fs.StringVar(&destDir, "dest", "", "extraction destination (default: temp dir)")
	fs.IntVar(&timeoutSec, "timeout", 0, "timeout in seconds (0 = no timeout)")
	fs.BoolVar(&noClean, "no-clean", false, "preserve output on failure")

	fs.Usage = usageFunc(fs, stderr, "test [options] <archive>",
		"Safely test archive extraction under resource limits.")
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

	tempDest := destDir == ""
	if tempDest {
		tmp, err := os.MkdirTemp("", "zipthorn-test-*")
		if err != nil {
			return coded(ExitError, err)
		}
		destDir = tmp
		defer func() {
			if tempDest {
				_ = os.RemoveAll(destDir)
			}
		}()
	}

	opts := extractor.Options{
		Limits:      limits,
		Sink:        extractor.DirSink(destDir),
		CleanOnFail: !noClean,
	}

	ctx := context.Background()
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	result := extractor.ExtractFile(ctx, archivePath, opts)

	out := newOutput(stdout, stderr, cf.json)
	if err := out.Emit(withConfig(&result, res), func(w io.Writer) { writeTest(w, archivePath, &result, res, cf) }); err != nil {
		return err
	}

	switch result.Status {
	case extractor.StatusPass:
		return nil
	case extractor.StatusLimitReached, extractor.StatusTimeout:
		return coded(ExitRisk, nil)
	case extractor.StatusInvalid:
		if result.Reason != "" {
			return coded(ExitRisk, errors.New(result.Reason))
		}
		return coded(ExitRisk, archive.ErrInvalidArchive)
	case extractor.StatusError:
		if result.Error != "" {
			return coded(ExitError, errors.New(result.Error))
		}
		return coded(ExitError, errors.New("extraction failed"))
	default:
		return coded(ExitError, fmt.Errorf("unknown status: %s", result.Status))
	}
}

func writeTest(w io.Writer, archivePath string, r *extractor.Result, res *config.Resolved, cf commonFlags) {
	if cf.quiet {
		fmt.Fprintf(w, "%s\n", r.Status)
		return
	}

	fmt.Fprint(w, "zipthorn\n")

	section(w, "Archive")
	field(w, "Path", filepath.Base(archivePath))

	section(w, "Result")
	field(w, "Status", string(r.Status))
	field(w, "Elapsed", humanDuration(r.Elapsed))
	field(w, "Files processed", humanCount(r.FilesProcessed))
	field(w, "Bytes produced", humanBytes(r.BytesProduced))
	if r.Ratio > 0 {
		field(w, "Expansion ratio", humanRatio(r.Ratio))
	}

	if r.LimitReached != "" {
		field(w, "Limit reached", r.LimitReached)
	}
	if r.Reason != "" {
		field(w, "Reason", r.Reason)
	}
	if r.Error != "" && cf.verbose {
		field(w, "Error", r.Error)
	}

	if cf.verbose {
		writeConfig(w, res)
	}

	fmt.Fprintln(w)
}

func humanDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Milliseconds()))
	}
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}
