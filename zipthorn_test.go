package zipthorn_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PeacexF/zipthorn"
)

// fixture generates an archive through the public API and returns its path.
func fixture(t *testing.T, s zipthorn.Spec) string {
	t.Helper()

	if s.Limits == (zipthorn.Limits{}) {
		s.Limits = zipthorn.DefaultConfig().Limits
	}

	var buf bytes.Buffer
	if _, err := zipthorn.Generate(&buf, s); err != nil {
		t.Fatalf("Generate(%s): %v", s.Profile, err)
	}

	path := filepath.Join(t.TempDir(), s.Profile+".zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The embedding story the package exists for: generate a fixture, inspect it,
// assess it, and extract it under limits — without touching internal packages.
func TestEmbeddedWorkflow(t *testing.T) {
	path := fixture(t, zipthorn.Spec{Profile: zipthorn.ProfileRatio, Seed: 7})

	info, err := zipthorn.InspectFile(path)
	if err != nil {
		t.Fatalf("InspectFile: %v", err)
	}
	if info.DeclaredSize <= info.CompressedSize {
		t.Errorf("ratio fixture should expand: declared %d, compressed %d",
			info.DeclaredSize, info.CompressedSize)
	}

	a := zipthorn.Detect(info, zipthorn.DefaultConfig().Thresholds)
	if a.Recommendation != zipthorn.Reject {
		t.Errorf("recommendation = %s, want %s", a.Recommendation, zipthorn.Reject)
	}
	var sawRatio bool
	for _, in := range a.Indicators {
		if in.ID == zipthorn.HighCompressionRatio {
			sawRatio = true
		}
	}
	if !sawRatio {
		t.Errorf("expected %s among %+v", zipthorn.HighCompressionRatio, a.Indicators)
	}

	// A limit well under the declared size must stop the extraction.
	limits := zipthorn.DefaultConfig().Limits
	limits.MaxOutputBytes = 64 * zipthorn.KB

	res := zipthorn.ExtractFile(context.Background(), path, zipthorn.ExtractOptions{
		Limits:      limits,
		Sink:        zipthorn.DirSink(filepath.Join(t.TempDir(), "out")),
		CleanOnFail: true,
	})
	if res.Status != zipthorn.StatusLimitReached {
		t.Errorf("status = %s, want %s (reason: %s)", res.Status, zipthorn.StatusLimitReached, res.Reason)
	}
}

func TestExtractPassesWithinLimits(t *testing.T) {
	path := fixture(t, zipthorn.Spec{
		Profile: zipthorn.ProfileFileCount, Seed: 3, FileCount: 20, FileSize: 128,
	})

	dest := filepath.Join(t.TempDir(), "out")
	res := zipthorn.ExtractFile(context.Background(), path, zipthorn.ExtractOptions{
		Limits:      zipthorn.DefaultConfig().Limits,
		Sink:        zipthorn.DirSink(dest),
		CleanOnFail: true,
	})
	if res.Status != zipthorn.StatusPass {
		t.Fatalf("status = %s, want %s (reason: %s, error: %s)",
			res.Status, zipthorn.StatusPass, res.Reason, res.Error)
	}
	if res.FilesProcessed != 20 {
		t.Errorf("files processed = %d, want 20", res.FilesProcessed)
	}
}

// TestReaderBasedAPI proves Inspect and Extract work directly off bytes in
// memory, with DiscardSink validating the archive without writing anything —
// the shape an upload handler needs without spilling untrusted input to disk
// first.
func TestReaderBasedAPI(t *testing.T) {
	var buf bytes.Buffer
	if _, err := zipthorn.Generate(&buf, zipthorn.Spec{
		Profile: zipthorn.ProfileFileCount, Seed: 9, FileCount: 5, FileSize: 64,
		Limits: zipthorn.DefaultConfig().Limits,
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data := buf.Bytes()

	info, err := zipthorn.Inspect(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.FileCount != 5 {
		t.Errorf("FileCount = %d, want 5", info.FileCount)
	}

	res := zipthorn.Extract(context.Background(), bytes.NewReader(data), int64(len(data)), zipthorn.ExtractOptions{
		Limits: zipthorn.DefaultConfig().Limits,
		Sink:   zipthorn.DiscardSink(),
	})
	if res.Status != zipthorn.StatusPass {
		t.Fatalf("status = %s, want %s (reason: %s)", res.Status, zipthorn.StatusPass, res.Reason)
	}
	if res.BytesProduced == 0 {
		t.Error("DiscardSink should still count decompressed bytes")
	}
}

func TestExtractHonoursContextDeadline(t *testing.T) {
	path := fixture(t, zipthorn.Spec{
		Profile: zipthorn.ProfileFileCount, Seed: 1, FileCount: 5000, FileSize: 512,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done before extraction starts

	res := zipthorn.ExtractFile(ctx, path, zipthorn.ExtractOptions{
		Limits:      zipthorn.DefaultConfig().Limits,
		Sink:        zipthorn.DirSink(filepath.Join(t.TempDir(), "out")),
		CleanOnFail: true,
	})
	if res.Status != zipthorn.StatusTimeout {
		t.Errorf("status = %s, want %s", res.Status, zipthorn.StatusTimeout)
	}
	if res.Elapsed > time.Minute {
		t.Errorf("a canceled extraction should return promptly, took %s", res.Elapsed)
	}
}

func TestGenerateFailsClosedOnLimits(t *testing.T) {
	limits := zipthorn.DefaultConfig().Limits
	limits.MaxOutputBytes = 1 * zipthorn.KB

	var buf bytes.Buffer
	_, err := zipthorn.Generate(&buf, zipthorn.Spec{
		Profile:      zipthorn.ProfileRatio,
		DeclaredSize: 64 * zipthorn.MB,
		Limits:       limits,
	})
	if !errors.Is(err, zipthorn.ErrLimitExceeded) {
		t.Fatalf("err = %v, want ErrLimitExceeded", err)
	}
	if buf.Len() != 0 {
		t.Errorf("a refused generation wrote %d bytes; it must write none", buf.Len())
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	spec := zipthorn.Spec{
		Profile: zipthorn.ProfileMixed, Seed: 42,
		Limits: zipthorn.DefaultConfig().Limits,
	}

	var first, second bytes.Buffer
	if _, err := zipthorn.Generate(&first, spec); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := zipthorn.Generate(&second, spec); err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("same seed and spec must produce byte-identical archives")
	}
}

func TestInspectRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.zip")
	if err := os.WriteFile(path, []byte("not a zip at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := zipthorn.InspectFile(path); !errors.Is(err, zipthorn.ErrInvalidArchive) {
		t.Errorf("err = %v, want ErrInvalidArchive", err)
	}
}

func TestPathHelpers(t *testing.T) {
	if !zipthorn.Escapes("../../etc/passwd") {
		t.Error("traversal must be reported as escaping")
	}
	if zipthorn.Escapes("docs/notes.txt") {
		t.Error("an ordinary relative path must not be reported as escaping")
	}
	if len(zipthorn.PathIssues("/abs/path")) == 0 {
		t.Error("an absolute path should raise an issue")
	}
	if !zipthorn.SupportedMethod(0) || !zipthorn.SupportedMethod(8) {
		t.Error("store and deflate must be supported")
	}
	if zipthorn.SupportedMethod(12) {
		t.Error("bzip2 must not be reported as supported")
	}
}

func TestPolicyAccessors(t *testing.T) {
	names := zipthorn.Policies()
	if len(names) == 0 {
		t.Fatal("Policies() returned nothing")
	}

	p, err := zipthorn.GetPolicy(zipthorn.PolicyStrict)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	def, err := zipthorn.GetPolicy(zipthorn.PolicyDefault)
	if err != nil {
		t.Fatalf("GetPolicy(default): %v", err)
	}
	if p.Thresholds.FileCount >= def.Thresholds.FileCount {
		t.Errorf("strict file_count (%d) should be below default (%d)",
			p.Thresholds.FileCount, def.Thresholds.FileCount)
	}

	if _, err := zipthorn.GetPolicy("no-such-policy"); err == nil {
		t.Error("an unknown policy must be an error")
	}
}

func TestDetectWithPolicy(t *testing.T) {
	path := fixture(t, zipthorn.Spec{
		Profile: zipthorn.ProfileFileCount, Seed: 5, FileCount: 2000, FileSize: 64,
	})

	info, err := zipthorn.InspectFile(path)
	if err != nil {
		t.Fatalf("InspectFile: %v", err)
	}

	// 2000 entries is under the default file-count threshold but over strict's.
	strict, err := zipthorn.DetectWithPolicy(info, zipthorn.PolicyStrict)
	if err != nil {
		t.Fatalf("DetectWithPolicy: %v", err)
	}
	permissive, err := zipthorn.DetectWithPolicy(info, zipthorn.PolicyPermissive)
	if err != nil {
		t.Fatalf("DetectWithPolicy: %v", err)
	}
	if strict.Score <= permissive.Score {
		t.Errorf("strict score (%d) should exceed permissive (%d)", strict.Score, permissive.Score)
	}
}

func TestLoadConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("limits:\n  max_files: 250\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := zipthorn.LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg.Limits.MaxFiles != 250 {
		t.Errorf("max_files = %d, want 250", cfg.Limits.MaxFiles)
	}
	// Unmentioned keys keep their defaults.
	if cfg.Limits.MaxDepth != zipthorn.DefaultConfig().Limits.MaxDepth {
		t.Error("an unmentioned key should keep its default")
	}
}
