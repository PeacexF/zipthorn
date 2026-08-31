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
