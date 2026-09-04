// Package extractor implements bounded, fail-safe ZIP extraction
package extractor

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// Sink receives extracted file contents. The extractor enforces its byte and
// ratio limits on the writer it gets back from File regardless of which Sink
// implementation is in use.
type Sink interface {
	// File is called once per entry that survives validation, in the order
	// entries appear in the archive. mode is the entry's declared file mode.
	File(name string, mode fs.FileMode) (io.WriteCloser, error)
}

// Rollbacker is implemented by a Sink that can undo everything it has
// written so far. Extract calls Rollback when opts.CleanOnFail is set and
// extraction is aborted partway through. A Sink with nothing to roll back
// (DiscardSink, or a custom Sink over a store with no delete) need not
// implement it; CleanOnFail then simply has nothing to do.
type Rollbacker interface {
	Rollback() error
}

// DirSink writes each entry under dest on local disk, creating directories
// as needed. This is the extractor's original behaviour, and the sink most
// callers extracting to a real destination want.
func DirSink(dest string) Sink { return &dirSink{dest: dest} }

type dirSink struct{ dest string }

func (s *dirSink) File(name string, mode fs.FileMode) (io.WriteCloser, error) {
	dest := filepath.Join(s.dest, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return nil, err
	}
	return os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
}

func (s *dirSink) Rollback() error { return os.RemoveAll(s.dest) }

// DiscardSink writes nothing anywhere: every entry is still decompressed and
// counted against the limits, but no bytes land on any filesystem or store.
// This is validate-only extraction — proof an archive is safe to extract,
// without ever writing untrusted output.
func DiscardSink() Sink { return discardSink{} }

type discardSink struct{}

func (discardSink) File(string, fs.FileMode) (io.WriteCloser, error) {
	return nopWriteCloser{io.Discard}, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

type Options struct {
	Limits config.Limits

	// Sink is where surviving entries are written. DirSink(path) recreates
	// the extractor's original behaviour; DiscardSink() validates an archive
	// against the limits without writing anything. Required.
	Sink Sink

	// CleanOnFail, if set, asks Sink to undo whatever it wrote when
	// extraction is aborted partway through. It is a no-op for a Sink that
	// does not implement Rollbacker.
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

// Extract performs bounded extraction from r, an archive of size bytes,
// writing surviving entries to opts.Sink under the constraints in
// opts.Limits. The context can carry a timeout; extraction stops immediately
// when ctx is canceled.
//
// Extract reports failure in the returned Result's Status rather than as an
// error: a refused archive is a verdict, not a malfunction. Use Result.Err
// to get the underlying sentinel for errors.Is.
func Extract(ctx context.Context, r io.ReaderAt, size int64, opts Options) Result {
	start := time.Now()

	if opts.Sink == nil {
		res := Result{Status: StatusError, Error: "extractor: Options.Sink is required"}
		res.Elapsed = time.Since(start)
		return res
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		res := Result{Status: StatusInvalid, err: fmt.Errorf("%w: %v", archive.ErrInvalidArchive, err)}
		res.Reason = res.err.Error()
		res.Elapsed = time.Since(start)
		return res
	}
	info := archive.Summarize(zr, size)

	res := ExtractParsed(ctx, size, info, zr, opts)
	res.Elapsed = time.Since(start) // supersede ExtractParsed's own timing: include the parse above
	return res
}

// ExtractParsed is Extract for a caller that has already parsed the archive
// (Guard is the one today) and does not want to pay for a second central-
// directory parse. info and zr must describe the same archive of size bytes.
// Most callers want Extract or ExtractFile instead.
func ExtractParsed(ctx context.Context, size int64, info *archive.Info, zr *zip.Reader, opts Options) Result {
	start := time.Now()
	res := Result{Status: StatusPass}

	if opts.Sink == nil {
		res.Status = StatusError
		res.Error = "extractor: Options.Sink is required"
		res.Elapsed = time.Since(start)
		return res
	}

	if verr := validateBeforeExtract(info, opts); verr != nil {
		res.Status = StatusLimitReached
		res.LimitReached = limitName(verr)
		res.Reason = verr.Error()
		res.err = verr
		res.Elapsed = time.Since(start)
		return res
	}

	err := extract(ctx, zr, opts, &res)
	res.Elapsed = time.Since(start)

	if err != nil {
		if opts.CleanOnFail {
			if rb, ok := opts.Sink.(Rollbacker); ok {
				_ = rb.Rollback()
			}
		}

		res.err = err
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			res.Status = StatusTimeout
			res.LimitReached = "timeout"
			res.Reason = "extraction timed out"
		} else if isLimitError(err) {
			res.Status = StatusLimitReached
			res.LimitReached = limitName(err)
			res.Reason = err.Error()
		} else {
			res.Status = StatusError
			res.Error = err.Error()
		}
	}

	if res.BytesProduced > 0 && size > 0 {
		res.Ratio = float64(res.BytesProduced) / float64(size)
	}

	return res
}

// ExtractFile is Extract over the archive at path: it opens path, reports
// its size, and closes it when extraction finishes. Most callers with an
// archive already on local disk want this.
func ExtractFile(ctx context.Context, path string, opts Options) Result {
	start := time.Now()

	f, size, err := openArchive(path)
	if err != nil {
		r := Result{err: err}
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
	defer f.Close()

	r := Extract(ctx, f, size, opts)
	r.Elapsed = time.Since(start)
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
	// destination path: a sink's own path depth must never count against a
	// caller's MaxDepth, or the same archive trips a different limit
	// depending only on where it happens to be extracted.
	depth := archive.Depth(f.Name)
	if depth > opts.Limits.MaxDepth {
		return fmt.Errorf("%w: depth %d for %s", ErrDepthLimitHit, depth, f.Name)
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := opts.Sink.File(f.Name, f.Mode())
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
