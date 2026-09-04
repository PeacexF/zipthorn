package extractor_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/extractor"
	"github.com/PeacexF/zipthorn/internal/generator"
)

func TestExtract_Pass(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 2048,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusPass {
		t.Errorf("status = %s, want PASS; reason: %s", r.Status, r.Reason)
	}
	if r.FilesProcessed == 0 {
		t.Errorf("no files processed")
	}
	if r.BytesProduced == 0 {
		t.Errorf("no bytes produced")
	}
}

func TestExtract_ByteLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 10 * 1024 * 1024,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    8192,
			MaxExpansionRatio: 1000,
			MaxFiles:          1000,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Errorf("status = %s, want LIMIT_REACHED", r.Status)
	}
	if r.LimitReached != "bytes" {
		t.Errorf("limit reached = %s, want bytes", r.LimitReached)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("dest dir should be cleaned up on failure")
	}
}

func TestExtract_FileLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 16384,
		FileCount:    100,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          10,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Errorf("status = %s, want LIMIT_REACHED", r.Status)
	}
	if r.LimitReached != "files" {
		t.Errorf("limit reached = %s, want files", r.LimitReached)
	}
}

func TestExtract_Timeout(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 100 * 1024,
		FileCount:    10,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(2 * time.Millisecond)

	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusTimeout {
		t.Errorf("status = %s, want TIMEOUT", r.Status)
	}
	if r.LimitReached != "timeout" {
		t.Errorf("limit reached = %s, want timeout", r.LimitReached)
	}
}

func TestExtract_InvalidArchive(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "bad.zip")
	dest := filepath.Join(tmp, "out")

	if err := os.WriteFile(archive, []byte("not a zip"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusInvalid {
		t.Errorf("status = %s, want INVALID_ARCHIVE", r.Status)
	}
}

func TestExtract_DepthLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileDepth,
		DeclaredSize: 2048,
		FileCount:    5,
		Depth:        20,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          1000,
			MaxDepth:          10,
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	ctx := context.Background()
	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Errorf("status = %s, want LIMIT_REACHED", r.Status)
	}
	if r.LimitReached != "depth" {
		t.Errorf("limit reached = %s, want depth", r.LimitReached)
	}
}

func TestExtract_CleanupPreserved(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 16384,
		FileCount:    50,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          100,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: false,
	}

	ctx := context.Background()
	r := extractor.ExtractFile(ctx, archive, opts)

	if r.Status != extractor.StatusPass && r.Status != extractor.StatusLimitReached {
		t.Logf("status = %s (unexpected but not critical for this test)", r.Status)
	}

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		t.Errorf("dest dir should exist when CleanOnFail=false, got: %v", err)
	}
}

// TestExtract_DepthLimit_ArchiveRelative regresses a bug where depth was
// measured against filepath.Clean(DestDir/entry) instead of the entry name
// alone, so extracting a shallow archive into a deep destination tripped the
// depth limit for reasons that had nothing to do with the archive's shape.
func TestExtract_DepthLimit_ArchiveRelative(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	// Several extra levels below tmp so the destination's own path length
	// cannot be mistaken for a shallow one.
	dest := filepath.Join(tmp, "a", "b", "c", "d", "e", "f", "g", "h", "out")

	spec := generator.Spec{
		Profile:      generator.ProfileDepth,
		DeclaredSize: 2048,
		FileCount:    1,
		Depth:        2, // archive-relative depth: d01/d02/leaf.txt
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	destDepth := strings.Count(filepath.Clean(dest), string(filepath.Separator))
	if destDepth <= 6 {
		t.Fatalf("test destination not deep enough to prove the regression: depth %d", destDepth)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    1024 * 1024,
			MaxExpansionRatio: 1000,
			MaxFiles:          10,
			MaxDepth:          6, // archive-relative depth (2) fits; DestDir's own depth does not
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	r := extractor.ExtractFile(context.Background(), archive, opts)

	if r.Status != extractor.StatusPass {
		t.Errorf("status = %s, want PASS (depth must be archive-relative, not measured against DestDir); reason: %s", r.Status, r.Reason)
	}
}

// TestExtract_RatioLimit regresses MaxExpansionRatio being honoured by the
// generator and registered as a CLI flag but never actually checked by the
// extractor.
func TestExtract_RatioLimit(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 2 * 1024 * 1024,
		FileCount:    1,
		Ratio:        100,
		Seed:         42,
		Limits: config.Limits{
			MaxOutputBytes:    64 * 1024 * 1024,
			MaxExpansionRatio: 1000, // generous at generation time
			MaxFiles:          10,
			MaxDepth:          32,
			MaxNesting:        4,
		},
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    64 * 1024 * 1024, // generous: byte cap must not be what trips this
			MaxExpansionRatio: 20,               // tight: well below the ~100x the archive achieves
			MaxFiles:          10,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	r := extractor.ExtractFile(context.Background(), archive, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Fatalf("status = %s, want LIMIT_REACHED; reason: %s", r.Status, r.Reason)
	}
	if r.LimitReached != "ratio" {
		t.Errorf("limit reached = %s, want ratio", r.LimitReached)
	}
	if !errors.Is(r.Err(), extractor.ErrRatioLimitHit) {
		t.Errorf("Err() = %v, want it to wrap ErrRatioLimitHit", r.Err())
	}
}

// TestExtract_Err verifies Result.Err() wraps the same sentinel that a
// caller matching on LimitReached strings would infer, so errors.Is works
// on the returned value.
func TestExtract_Err(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 10 * 1024 * 1024,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Limits{
			MaxOutputBytes:    8192, // below declared size: trips at pre-check
			MaxExpansionRatio: 1000,
			MaxFiles:          1000,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	r := extractor.ExtractFile(context.Background(), archive, opts)

	if r.Status != extractor.StatusPass && r.Err() == nil {
		t.Fatalf("Err() = nil for non-PASS status %s", r.Status)
	}
	if !errors.Is(r.Err(), extractor.ErrByteLimitHit) {
		t.Errorf("Err() = %v, want it to wrap ErrByteLimitHit", r.Err())
	}
}

// TestExtract_OnEntry verifies the observability hook fires for every entry
// pre-extraction validation refuses, even though the archive is refused as a
// whole after the first one found.
func TestExtract_OnEntry(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"ok.txt", "../escape.txt", "also/../../escape2.txt"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create entry %s: %v", name, err)
		}
		w.Write([]byte("x"))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	f.Close()

	var rejected []string
	opts := extractor.Options{
		Limits:      config.Default().Limits,
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
		OnEntry: func(name string, err error) {
			if err != nil {
				rejected = append(rejected, name)
			}
		},
	}

	r := extractor.ExtractFile(context.Background(), path, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Fatalf("status = %s, want LIMIT_REACHED; reason: %s", r.Status, r.Reason)
	}
	if len(rejected) != 2 {
		t.Errorf("OnEntry reported %d rejected entries, want 2: %v", len(rejected), rejected)
	}
}

// TestExtract_ControlCharacterRejected verifies an entry name containing a
// control character is refused rather than silently extracted, on every
// platform (unlike the reserved-device-name check, which only matters on
// Windows).
func TestExtract_ControlCharacterRejected(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "out")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("bad\x01name.txt")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	w.Write([]byte("x"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	f.Close()

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	r := extractor.ExtractFile(context.Background(), path, opts)

	if r.Status != extractor.StatusLimitReached {
		t.Fatalf("status = %s, want LIMIT_REACHED; reason: %s", r.Status, r.Reason)
	}
	if !errors.Is(r.Err(), extractor.ErrUnsafePath) {
		t.Errorf("Err() = %v, want it to wrap ErrUnsafePath", r.Err())
	}
}

// TestExtract_ReaderBased proves Extract works directly off an in-memory
// archive, with no file ever created on disk for the archive itself. This is
// the shape an upload handler holding a multipart.File or bytes.Reader needs
// and previously had to spill to a temp file to get.
func TestExtract_ReaderBased(t *testing.T) {
	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 4096,
		FileCount:    10,
		FileSize:     64,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	var buf bytes.Buffer
	if _, err := generator.Generate(&buf, spec); err != nil {
		t.Fatalf("generate: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	r := bytes.NewReader(buf.Bytes())

	opts := extractor.Options{
		Limits:      config.Default().Limits,
		Sink:        extractor.DirSink(dest),
		CleanOnFail: true,
	}

	result := extractor.Extract(context.Background(), r, int64(buf.Len()), opts)

	if result.Status != extractor.StatusPass {
		t.Fatalf("status = %s, want PASS; reason: %s", result.Status, result.Reason)
	}
	if result.FilesProcessed != 10 {
		t.Errorf("files processed = %d, want 10", result.FilesProcessed)
	}
}

// TestExtract_DiscardSink proves DiscardSink extracts (and enforces every
// limit) without writing anything anywhere: the validate-only mode LIB.md
// calls out as the most-wanted reason to have a Sink abstraction at all.
func TestExtract_DiscardSink(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 4096,
		FileCount:    10,
		FileSize:     64,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	opts := extractor.Options{
		Limits: config.Default().Limits,
		Sink:   extractor.DiscardSink(),
	}

	result := extractor.ExtractFile(context.Background(), archive, opts)

	if result.Status != extractor.StatusPass {
		t.Fatalf("status = %s, want PASS; reason: %s", result.Status, result.Reason)
	}
	if result.BytesProduced == 0 {
		t.Error("DiscardSink should still count bytes decompressed, just not write them")
	}

	// Nothing beyond the source archive itself should exist in tmp: a
	// DiscardSink extraction must not create any output on disk.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "test.zip" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("DiscardSink wrote something to disk: %v", names)
	}
}

// TestExtractParsed_MatchesExtract proves ExtractParsed — the entry point
// Guard uses to avoid a second central-directory parse — produces the same
// outcome as Extract given the same archive and options, just fed an
// already-parsed *archive.Info and *zip.Reader instead of parsing them
// itself.
func TestExtractParsed_MatchesExtract(t *testing.T) {
	spec := generator.Spec{
		Profile:      generator.ProfileFileCount,
		DeclaredSize: 4096,
		FileCount:    10,
		FileSize:     64,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	var buf bytes.Buffer
	if _, err := generator.Generate(&buf, spec); err != nil {
		t.Fatalf("generate: %v", err)
	}
	data := buf.Bytes()

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	info := archive.Summarize(zr, int64(len(data)))

	opts := extractor.Options{
		Limits: config.Default().Limits,
		Sink:   extractor.DiscardSink(),
	}

	viaParsed := extractor.ExtractParsed(context.Background(), int64(len(data)), info, zr, opts)
	viaExtract := extractor.Extract(context.Background(), bytes.NewReader(data), int64(len(data)), opts)

	if viaParsed.Status != viaExtract.Status {
		t.Errorf("Status: ExtractParsed = %s, Extract = %s", viaParsed.Status, viaExtract.Status)
	}
	if viaParsed.FilesProcessed != viaExtract.FilesProcessed {
		t.Errorf("FilesProcessed: ExtractParsed = %d, Extract = %d", viaParsed.FilesProcessed, viaExtract.FilesProcessed)
	}
	if viaParsed.BytesProduced != viaExtract.BytesProduced {
		t.Errorf("BytesProduced: ExtractParsed = %d, Extract = %d", viaParsed.BytesProduced, viaExtract.BytesProduced)
	}
}
