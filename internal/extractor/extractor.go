// Package extractor implements bounded, fail-safe ZIP extraction
package extractor

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

var (
	ErrInvalidArchive = errors.New("invalid archive")
	ErrUnsafePath     = errors.New("unsafe path")
	ErrByteLimitHit   = errors.New("byte limit exceeded")
	ErrRatioLimitHit  = errors.New("expansion ratio limit exceeded")
	ErrFileLimitHit   = errors.New("file limit exceeded")
	ErrDepthLimitHit  = errors.New("depth limit exceeded")
	ErrNestingHit     = errors.New("nesting limit exceeded")
	ErrTimeout        = errors.New("timeout")
)

type Status string

const (
	StatusPass         Status = "PASS"
	StatusLimitReached Status = "LIMIT_REACHED"
	StatusTimeout      Status = "TIMEOUT"
	StatusInvalid      Status = "INVALID_ARCHIVE"
	StatusError        Status = "ERROR"
)

type Result struct {
	Status         Status        `json:"status"`
	Elapsed        time.Duration `json:"elapsed_ns"`
	FilesProcessed int64         `json:"files_processed"`
	BytesProduced  int64         `json:"bytes_produced"`
	Ratio          float64       `json:"ratio"`
	LimitReached   string        `json:"limit_reached,omitempty"`
	Reason         string        `json:"reason,omitempty"`
	Error          string        `json:"error,omitempty"`

	err error
}

// Err returns the underlying error behind a non-PASS result, still wrapping
// whichever sentinel (ErrUnsafePath, ErrByteLimitHit, ...) caused it, so
// callers can branch with errors.Is instead of matching on Reason strings.
// It is nil when Status is StatusPass.
func (r Result) Err() error { return r.err }

type Options struct {
	Limits      config.Limits
	DestDir     string
	CleanOnFail bool

	// OnEntry, if set, is called once for every entry zipthorn refuses to
	// extract, with the reason. It fires for entries rejected during
	// pre-extraction path validation (before anything is written, and even
	// though the archive is refused after the first one found) as well as
	// entries that fail during extraction itself (an unsupported method, or
	// a limit hit mid-stream). It is not called for entries that extract
	// successfully.
	OnEntry func(name string, err error)
}

// Extract performs bounded extraction of archivePath into opts.DestDir under the
// constraints in opts.Limits. The context can carry a timeout; extraction stops
// immediately when ctx is canceled.
func Extract(ctx context.Context, archivePath string, opts Options) Result {
	start := time.Now()
	r := Result{Status: StatusPass}

	zr, archiveSize, err := openArchive(archivePath)
	if err != nil {
		r.err = err
		if errors.Is(err, archive.ErrInvalidArchive) {
			r.Status = StatusInvalid
			r.Reason = err.Error()
		} else {
			r.Status = StatusError
			r.Error = err.Error()
		}
		r.Elapsed = time.Since(start)
		return r
	}
	defer zr.Close()

	info, err := archive.Read(zr, archiveSize)
	if err != nil {
		r.err = err
		if errors.Is(err, archive.ErrInvalidArchive) {
			r.Status = StatusInvalid
			r.Reason = err.Error()
		} else {
			r.Status = StatusError
			r.Error = err.Error()
		}
		r.Elapsed = time.Since(start)
		return r
	}

	if verr := validateBeforeExtract(info, opts); verr != nil {
		r.Status = StatusLimitReached
		r.LimitReached = limitName(verr)
		r.Reason = verr.Error()
		r.err = verr
		r.Elapsed = time.Since(start)
		return r
	}

	zipReader, err := zip.NewReader(zr, archiveSize)
	if err != nil {
		r.Status = StatusInvalid
		r.Reason = err.Error()
		r.err = err
		r.Elapsed = time.Since(start)
		return r
	}

	err = extract(ctx, zipReader, opts, &r)
	r.Elapsed = time.Since(start)

	if err != nil {
		if opts.CleanOnFail {
			_ = os.RemoveAll(opts.DestDir)
		}

		r.err = err
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			r.Status = StatusTimeout
			r.LimitReached = "timeout"
			r.Reason = "extraction timed out"
		} else if isLimitError(err) {
			r.Status = StatusLimitReached
			r.LimitReached = limitName(err)
			r.Reason = err.Error()
		} else {
			r.Status = StatusError
			r.Error = err.Error()
		}
	}

	if r.BytesProduced > 0 && archiveSize > 0 {
		r.Ratio = float64(r.BytesProduced) / float64(archiveSize)
	}

	return r
}

// openArchive opens path for reading and reports its size. The caller owns the
// returned file and must close it: Windows refuses to delete a file with a live
// handle, so a leak here strands every archive the caller extracted.
func openArchive(path string) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if st.IsDir() {
		f.Close()
		return nil, 0, fmt.Errorf("%w: %s is a directory", ErrInvalidArchive, path)
	}

	return f, st.Size(), nil
}

func validateBeforeExtract(info *archive.Info, opts Options) error {
	limits := opts.Limits

	if info.DeclaredSize > limits.MaxOutputBytes {
		return fmt.Errorf("%w: declared size %d exceeds max %d", ErrByteLimitHit, info.DeclaredSize, limits.MaxOutputBytes)
	}
	if limits.MaxExpansionRatio > 0 && info.ExpansionRatio > limits.MaxExpansionRatio {
		return fmt.Errorf("%w: declared expansion %.1fx exceeds limit %.1fx", ErrRatioLimitHit, info.ExpansionRatio, limits.MaxExpansionRatio)
	}
	if info.FileCount > limits.MaxFiles {
		return fmt.Errorf("%w: file count %d exceeds max %d", ErrFileLimitHit, info.FileCount, limits.MaxFiles)
	}
	if info.MaxDepth > limits.MaxDepth {
		return fmt.Errorf("%w: max depth %d exceeds limit %d", ErrDepthLimitHit, info.MaxDepth, limits.MaxDepth)
	}
	if len(info.NestedArchives) > limits.MaxNesting {
		return fmt.Errorf("%w: nested archives %d exceeds limit %d", ErrNestingHit, len(info.NestedArchives), limits.MaxNesting)
	}

	// Visit every entry so OnEntry hears about all of them, not just the
	// first offender; the archive is still refused in full on the first one.
	var firstErr error
	for _, e := range info.Entries {
		if e.IsDir {
			continue
		}
		err := unsafeEntryError(e.Name)
		if err == nil {
			continue
		}
		if opts.OnEntry != nil {
			opts.OnEntry(e.Name, err)
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// unsafeEntryError reports why an entry name must not be extracted, or nil.
// Reserved Windows device names (CON, NUL, COM1, ...) are refused only on
// Windows: elsewhere aux.txt or com1.log are ordinary filenames.
func unsafeEntryError(name string) error {
	if archive.Escapes(name) {
		return fmt.Errorf("%w: %s", ErrUnsafePath, name)
	}
	for _, issue := range archive.PathIssues(name) {
		switch issue {
		case archive.PathControl:
			return fmt.Errorf("%w: control character in %s", ErrUnsafePath, name)
		case archive.PathReserved:
			if runtime.GOOS == "windows" {
				return fmt.Errorf("%w: reserved device name in %s", ErrUnsafePath, name)
			}
		}
	}
	return nil
}

func extract(ctx context.Context, zr *zip.Reader, opts Options, r *Result) error {
	if err := os.MkdirAll(opts.DestDir, 0755); err != nil {
		return err
	}

	for _, f := range zr.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if f.FileInfo().IsDir() {
			continue
		}

		if err := extractFile(ctx, f, opts, r); err != nil {
			return err
		}

		r.FilesProcessed++
		if r.FilesProcessed > opts.Limits.MaxFiles {
			return fmt.Errorf("%w: processed %d files", ErrFileLimitHit, r.FilesProcessed)
		}
	}

	return nil
}

func extractFile(ctx context.Context, f *zip.File, opts Options, r *Result) (err error) {
	defer func() {
		if err != nil && opts.OnEntry != nil {
			opts.OnEntry(f.Name, err)
		}
	}()

	if err := unsafeEntryError(f.Name); err != nil {
		return err
	}

	if !archive.Supported(f.Method) {
		return fmt.Errorf("unsupported compression method %s for %s", archive.MethodName(f.Method), f.Name)
	}

	// Depth is measured on the archive-relative entry name, not the resolved
	// destination path: DestDir's own depth must never count against a
	// caller's MaxDepth, or the same archive trips a different limit
	// depending only on where it happens to be extracted.
	depth := archive.Depth(f.Name)
	if depth > opts.Limits.MaxDepth {
		return fmt.Errorf("%w: depth %d for %s", ErrDepthLimitHit, depth, f.Name)
	}

	dest := filepath.Join(opts.DestDir, filepath.FromSlash(f.Name))
	destDir := filepath.Dir(dest)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	w := &limitWriter{
		w:              out,
		limit:          opts.Limits.MaxOutputBytes,
		total:          &r.BytesProduced,
		ratioLimit:     opts.Limits.MaxExpansionRatio,
		compressedSize: int64(f.CompressedSize64),
	}

	if _, err := io.Copy(w, rc); err != nil {
		return err
	}

	return out.Close()
}

type limitWriter struct {
	w     io.Writer
	limit int64
	total *int64

	// Per-entry expansion ratio: the entry's own declared compressed size
	// against bytes actually produced from it so far. This catches a
	// tighter ratio limit than MaxOutputBytes would, and it is what makes
	// MaxExpansionRatio an enforced limit rather than a number the generator
	// honours and the extractor ignores.
	ratioLimit     float64
	compressedSize int64
	written        int64
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if *lw.total+int64(len(p)) > lw.limit {
		return 0, fmt.Errorf("%w: would exceed %d bytes", ErrByteLimitHit, lw.limit)
	}
	if lw.ratioLimit > 0 && lw.compressedSize > 0 {
		projected := lw.written + int64(len(p))
		if float64(projected)/float64(lw.compressedSize) > lw.ratioLimit {
			return 0, fmt.Errorf("%w: would exceed %.1fx", ErrRatioLimitHit, lw.ratioLimit)
		}
	}
	n, err := lw.w.Write(p)
	*lw.total += int64(n)
	lw.written += int64(n)
	return n, err
}

func isLimitError(err error) bool {
	return errors.Is(err, ErrByteLimitHit) ||
		errors.Is(err, ErrRatioLimitHit) ||
		errors.Is(err, ErrFileLimitHit) ||
		errors.Is(err, ErrDepthLimitHit) ||
		errors.Is(err, ErrNestingHit) ||
		errors.Is(err, ErrUnsafePath)
}

func limitName(err error) string {
	switch {
	case errors.Is(err, ErrByteLimitHit):
		return "bytes"
	case errors.Is(err, ErrRatioLimitHit):
		return "ratio"
	case errors.Is(err, ErrFileLimitHit):
		return "files"
	case errors.Is(err, ErrDepthLimitHit):
		return "depth"
	case errors.Is(err, ErrNestingHit):
		return "nesting"
	case errors.Is(err, ErrUnsafePath):
		return "path"
	default:
		return "unknown"
	}
}
