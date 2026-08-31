package malformed_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/cli"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/detector"
)

// TestTruncatedArchive verifies handling of incomplete ZIP files
func TestTruncatedArchive(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "truncated.zip")

	// Create valid archive then truncate it
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	fw, _ := zw.Create("test.txt")
	fw.Write([]byte("content"))
	zw.Close()

	// Write only first half
	truncated := buf.Bytes()[:len(buf.Bytes())/2]
	if err := os.WriteFile(path, truncated, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Inspect should fail safely
	_, err := archive.Open(path)
	if err == nil {
		t.Error("expected error for truncated archive")
	}

	// CLI should not panic
	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"inspect", path}, &stdout, &stderr)
	if code == cli.ExitOK {
		t.Error("inspect should fail on truncated archive")
	}
}

// TestEmptyFile verifies handling of empty files
func TestEmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "empty.zip")

	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := archive.Open(path)
	if err == nil {
		t.Error("expected error for empty file")
	}

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"inspect", path}, &stdout, &stderr)
	if code == cli.ExitOK {
		t.Error("inspect should fail on empty file")
	}
}

// TestNotAZip verifies handling of non-ZIP data
func TestNotAZip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "not.zip")

	if err := os.WriteFile(path, []byte("This is not a ZIP file at all"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := archive.Open(path)
	if err == nil {
		t.Error("expected error for non-ZIP file")
	}

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"inspect", path}, &stdout, &stderr)
	if code == cli.ExitOK {
		t.Error("inspect should fail on non-ZIP file")
	}
}

// TestInvalidCentralDirectory verifies handling of corrupted central directory
func TestInvalidCentralDirectory(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "badcentral.zip")

	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	fw, _ := zw.Create("test.txt")
	fw.Write([]byte("content"))
	zw.Close()

	data := buf.Bytes()
	// Corrupt central directory signature
	for i := len(data) - 100; i < len(data)-4; i++ {
		if data[i] == 0x50 && data[i+1] == 0x4b && data[i+2] == 0x01 && data[i+3] == 0x02 {
			data[i] = 0xFF
			break
		}
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := archive.Open(path)
	if err == nil {
		t.Error("expected error for corrupted central directory")
	}
}

// TestDuplicateEntries verifies detection of duplicate filenames
func TestDuplicateEntries(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "dupes.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for i := 0; i < 3; i++ {
		fw, _ := zw.Create("duplicate.txt")
		fw.Write([]byte("content"))
	}
	zw.Close()

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if len(info.Duplicates) == 0 {
		t.Error("expected duplicates to be detected")
	}

	// Detect should flag this
	th := detector.Assess(info, config.Default().Thresholds)
	foundDupe := false
	for _, ind := range th.Indicators {
		if strings.Contains(ind.ID, "DUPLICATE") {
			foundDupe = true
			break
		}
	}
	if !foundDupe {
		t.Error("detector should flag duplicate entries")
	}
}

// TestPathTraversal verifies detection of traversal attempts
func TestPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "traversal.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)

	// Add entries with traversal attempts
	dangerousPaths := []string{
		"../etc/passwd",
		"../../root/.ssh/id_rsa",
		"subdir/../../escape.txt",
		"/absolute/path.txt",
		`..\..\windows\system32\config`,
	}

	for _, p := range dangerousPaths {
		fw, _ := zw.Create(p)
		fw.Write([]byte("malicious"))
	}
	zw.Close()

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Detector should flag path issues
	th := detector.Assess(info, config.Default().Thresholds)
	if len(th.Indicators) == 0 {
		t.Error("detector should flag path traversal attempts")
	}

	// Test command should reject unsafe paths
	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", path}, &stdout, &stderr)
	if code == cli.ExitOK {
		t.Error("test should reject archives with path traversal")
	}
}

// TestReservedNames verifies detection of Windows reserved names
func TestReservedNames(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "reserved.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)

	reservedNames := []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}
	for _, name := range reservedNames {
		fw, _ := zw.Create(name)
		fw.Write([]byte("test"))
	}
	zw.Close()

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Check that path issues are detected
	hasReserved := false
	for _, entry := range info.Entries {
		issues := archive.PathIssues(entry.Name)
		for _, issue := range issues {
			if issue == archive.PathReserved {
				hasReserved = true
				break
			}
		}
	}
	if !hasReserved {
		t.Error("expected reserved names to be flagged")
	}
}

// TestControlCharacters verifies detection of control chars in filenames
func TestControlCharacters(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "control.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	fw, _ := zw.Create("file\x00null.txt")
	fw.Write([]byte("test"))
	fw, _ = zw.Create("file\x1btab.txt")
	fw.Write([]byte("test"))
	zw.Close()

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	hasControl := false
	for _, entry := range info.Entries {
		issues := archive.PathIssues(entry.Name)
		for _, issue := range issues {
			if issue == archive.PathControl {
				hasControl = true
				break
			}
		}
	}
	if !hasControl {
		t.Error("expected control characters to be flagged")
	}
}

// TestZeroByteFiles verifies handling of zero-byte entries
func TestZeroByteFiles(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "zero.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for i := 0; i < 100; i++ {
		fw, _ := zw.Create("empty.txt")
		fw.Write([]byte{}) // zero bytes
	}
	zw.Close()

	// Should parse without panic
	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if info.FileCount != 100 {
		t.Errorf("expected 100 files, got %d", info.FileCount)
	}
}

// TestDeepNesting verifies handling of deeply nested directories
func TestDeepNesting(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "deep.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)

	// Create very deep path
	deepPath := strings.Repeat("a/", 100) + "file.txt"
	fw, _ := zw.Create(deepPath)
	fw.Write([]byte("deep"))
	zw.Close()

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if info.MaxDepth < 100 {
		t.Errorf("expected depth >= 100, got %d", info.MaxDepth)
	}

	// Detect should flag this
	th := detector.Assess(info, config.Default().Thresholds)
	if th.Recommendation != detector.Reject && th.Recommendation != detector.Review {
		t.Error("detector should flag excessive depth")
	}
}

// TestMixedSlashesInPaths verifies handling of mixed path separators
func TestMixedSlashesInPaths(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mixed.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	fw, _ := zw.Create(`dir\subdir/file.txt`)
	fw.Write([]byte("mixed"))
	zw.Close()

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	hasBackslash := false
	for _, entry := range info.Entries {
		issues := archive.PathIssues(entry.Name)
		for _, issue := range issues {
			if issue == archive.PathBackslash {
				hasBackslash = true
				break
			}
		}
	}
	if !hasBackslash {
		t.Error("expected backslash to be flagged")
	}
}

// TestNoPanicOnMalformed ensures no panics on any malformed input
func TestNoPanicOnMalformed(t *testing.T) {
	malformedData := [][]byte{
		{},
		{0xFF, 0xFF, 0xFF, 0xFF},
		[]byte("PK\x03\x04"),
		[]byte("PK\x03\x04" + strings.Repeat("\x00", 100)),
		[]byte(strings.Repeat("random garbage", 1000)),
	}

	for i, data := range malformedData {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on malformed data: %v", r)
				}
			}()

			tmp := t.TempDir()
			path := filepath.Join(tmp, "bad.zip")
			os.WriteFile(path, data, 0644)

			// Should not panic
			_, _ = archive.Open(path)

			var stdout, stderr bytes.Buffer
			cli.Main([]string{"inspect", path}, &stdout, &stderr)
		})
	}
}

// buildRawZip writes an archive whose entries bypass the writer's own
// bookkeeping, so headers can declare things the data does not support.
func buildRawZip(t *testing.T, name string, build func(*zip.Writer)) string {
	t.Helper()

	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	build(zw)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestUnsupportedMethod covers entries compressed with a method the extractor
// cannot decode. Inspection must still report the archive, and extraction must
// refuse rather than produce an empty or corrupt file.
func TestUnsupportedMethod(t *testing.T) {
	const bzip2Method uint16 = 12

	payload := []byte("not really bzip2 data")
	path := buildRawZip(t, "unsupported.zip", func(zw *zip.Writer) {
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name:               "payload.bin",
			Method:             bzip2Method,
			CompressedSize64:   uint64(len(payload)),
			UncompressedSize64: uint64(len(payload)),
		})
		if err != nil {
			t.Fatalf("CreateRaw: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})

	// Metadata is readable, and the method is reported as unsupported.
	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("inspect should read metadata for an unsupported method: %v", err)
	}
	if archive.Supported(bzip2Method) {
		t.Fatal("method 12 should not be reported as supported")
	}
	if len(info.Entries) != 1 || info.Entries[0].Method != bzip2Method {
		t.Fatalf("entry method = %+v, want method %d", info.Entries, bzip2Method)
	}

	var stdout, stderr bytes.Buffer
	if code := cli.Main([]string{"inspect", path}, &stdout, &stderr); code != cli.ExitOK {
		t.Errorf("inspect = %d, want %d (stderr: %s)", code, cli.ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unsupported") {
		t.Errorf("inspect should flag the method as unsupported:\n%s", stdout.String())
	}

	// Extraction must fail closed rather than write a bogus file.
	stdout.Reset()
	stderr.Reset()
	dest := filepath.Join(t.TempDir(), "out")
	if code := cli.Main([]string{"test", "--dest", dest, path}, &stdout, &stderr); code == cli.ExitOK {
		t.Errorf("test should refuse an unsupported method:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dest, "payload.bin")); err == nil {
		t.Error("a refused entry must not be left on disk")
	}
}

// TestConflictingMetadata covers a central directory that disagrees with the
// data it points at: the declared uncompressed size is inflated far beyond what
// the entry can actually produce. Detection reads the declaration, so it must
// not be fooled into treating the lie as harmless, and extraction must not
// trust it either.
func TestConflictingMetadata(t *testing.T) {
	payload := []byte("sixteen bytes!!!")
	path := buildRawZip(t, "conflicting.zip", func(zw *zip.Writer) {
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name:               "payload.bin",
			Method:             zip.Store,
			CompressedSize64:   uint64(len(payload)),
			UncompressedSize64: 4 << 30, // 4GB declared against 16 stored bytes
			CRC32:              0,
		})
		if err != nil {
			t.Fatalf("CreateRaw: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})

	info, err := archive.Open(path)
	if err != nil {
		t.Fatalf("inspect should read a self-contradictory central directory: %v", err)
	}
	if info.DeclaredSize != 4<<30 {
		t.Errorf("declared size = %d, want the header's 4GB claim", info.DeclaredSize)
	}

	// The declaration alone is enough to reject: a scanner that believes it
	// would allocate 4GB for a 16-byte entry.
	a := detector.Assess(info, config.Default().Thresholds)
	if a.Recommendation != detector.Reject {
		t.Errorf("recommendation = %s, want %s for a 4GB declaration",
			a.Recommendation, detector.Reject)
	}

	var stdout, stderr bytes.Buffer
	if code := cli.Main([]string{"detect", path}, &stdout, &stderr); code != cli.ExitRisk {
		t.Errorf("detect = %d, want %d (stderr: %s)", code, cli.ExitRisk, stderr.String())
	}

	// Extraction must stop on the declared size rather than trust it and then
	// discover the truth mid-copy.
	stdout.Reset()
	stderr.Reset()
	dest := filepath.Join(t.TempDir(), "out")
	code := cli.Main([]string{"test", "--dest", dest, path}, &stdout, &stderr)
	if code == cli.ExitOK {
		t.Errorf("test should refuse a 4GB declaration:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "LIMIT_REACHED") {
		t.Errorf("test should report a limit, got:\n%s", stdout.String())
	}
}

// TestConflictingCRC covers metadata that lies about content rather than size:
// the stored CRC does not match the bytes. Extraction must surface the
// corruption instead of silently writing bad data.
func TestConflictingCRC(t *testing.T) {
	payload := []byte("payload with a deliberately wrong checksum")
	path := buildRawZip(t, "badcrc.zip", func(zw *zip.Writer) {
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name:               "payload.bin",
			Method:             zip.Store,
			CompressedSize64:   uint64(len(payload)),
			UncompressedSize64: uint64(len(payload)),
			CRC32:              0xDEADBEEF,
		})
		if err != nil {
			t.Fatalf("CreateRaw: %v", err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})

	if _, err := archive.Open(path); err != nil {
		t.Fatalf("inspect should read metadata despite a bad CRC: %v", err)
	}

	var stdout, stderr bytes.Buffer
	dest := filepath.Join(t.TempDir(), "out")
	if code := cli.Main([]string{"test", "--dest", dest, path}, &stdout, &stderr); code == cli.ExitOK {
		t.Errorf("test should not pass an entry whose CRC does not match:\n%s", stdout.String())
	}
	// The failure must be the checksum, not an incidental limit trip.
	if !strings.Contains(stdout.String()+stderr.String(), "checksum") {
		t.Errorf("failure should name the checksum, got:\n%s%s", stdout.String(), stderr.String())
	}
}
