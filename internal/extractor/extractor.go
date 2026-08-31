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
	"strings"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

var (
	ErrInvalidArchive = errors.New("invalid archive")
	ErrUnsafePath     = errors.New("unsafe path")
	ErrByteLimitHit   = errors.New("byte limit exceeded")
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
}

type Options struct {
	Limits      config.Limits
	DestDir     string
	CleanOnFail bool
}

// Extract performs bounded extraction of archivePath into opts.DestDir under the
// constraints in opts.Limits. The context can carry a timeout; extraction stops
// immediately when ctx is canceled.
func Extract(ctx context.Context, archivePath string, opts Options) Result {
	start := time.Now()
	r := Result{Status: StatusPass}

	zr, archiveSize, err := openArchive(archivePath)
	if err != nil {
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

	info, err := archive.Read(zr, archiveSize)
	if err != nil {
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

	if verr := validateBeforeExtract(info, opts.Limits); verr != nil {
		r.Status = StatusLimitReached
		r.LimitReached = limitName(verr)
		r.Reason = verr.Error()
		r.Elapsed = time.Since(start)
		return r
	}

	zipReader, err := zip.NewReader(zr, archiveSize)
	if err != nil {
		r.Status = StatusInvalid
		r.Reason = err.Error()
		r.Elapsed = time.Since(start)
		return r
	}

	err = extract(ctx, zipReader, opts, &r)
	r.Elapsed = time.Since(start)

	if err != nil {
		if opts.CleanOnFail {
			_ = os.RemoveAll(opts.DestDir)
		}

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

func openArchive(path string) (io.ReaderAt, int64, error) {
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

func validateBeforeExtract(info *archive.Info, limits config.Limits) error {
	if info.DeclaredSize > limits.MaxOutputBytes {
		return fmt.Errorf("%w: declared size %d exceeds max %d", ErrByteLimitHit, info.DeclaredSize, limits.MaxOutputBytes)
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

	for _, e := range info.Entries {
		if e.IsDir {
			continue
		}
		if archive.Escapes(e.Name) {
			return fmt.Errorf("%w: %s", ErrUnsafePath, e.Name)
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

func extractFile(ctx context.Context, f *zip.File, opts Options, r *Result) error {
	if archive.Escapes(f.Name) {
		return fmt.Errorf("%w: %s", ErrUnsafePath, f.Name)
	}

	if !archive.Supported(f.Method) {
		return fmt.Errorf("unsupported compression method %s for %s", archive.MethodName(f.Method), f.Name)
	}

	dest := filepath.Join(opts.DestDir, filepath.FromSlash(f.Name))
	destDir := filepath.Dir(dest)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	depth := strings.Count(filepath.Clean(dest), string(filepath.Separator))
	if depth > opts.Limits.MaxDepth {
		return fmt.Errorf("%w: depth %d for %s", ErrDepthLimitHit, depth, f.Name)
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
		w:     out,
		limit: opts.Limits.MaxOutputBytes,
		total: &r.BytesProduced,
	}

	_, err = io.Copy(w, rc)
	if err != nil {
		return err
	}

	return out.Close()
}

type limitWriter struct {
	w     io.Writer
	limit int64
	total *int64
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if *lw.total+int64(len(p)) > lw.limit {
		return 0, fmt.Errorf("%w: would exceed %d bytes", ErrByteLimitHit, lw.limit)
	}
	n, err := lw.w.Write(p)
	*lw.total += int64(n)
	return n, err
}

func isLimitError(err error) bool {
	return errors.Is(err, ErrByteLimitHit) ||
		errors.Is(err, ErrFileLimitHit) ||
		errors.Is(err, ErrDepthLimitHit) ||
		errors.Is(err, ErrNestingHit) ||
		errors.Is(err, ErrUnsafePath)
}

func limitName(err error) string {
	switch {
	case errors.Is(err, ErrByteLimitHit):
		return "bytes"
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
