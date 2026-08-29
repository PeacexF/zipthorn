package cli_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/cli"
)

// writeZip builds a small archive on disk and returns its path.
func writeZip(t *testing.T, names ...string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("Create(%q): %v", n, err)
		}
		if !strings.HasSuffix(n, "/") {
			if _, err := w.Write(bytes.Repeat([]byte("zipthorn"), 256)); err != nil {
				t.Fatalf("Write(%q): %v", n, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	p := filepath.Join(t.TempDir(), "fixture.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInspectHumanOutput(t *testing.T) {
	p := writeZip(t, "docs/notes.txt", "a/b/c/deep.txt")

	code, stdout, stderr := run(t, "inspect", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d (stderr: %s)", code, cli.ExitOK, stderr)
	}
	for _, want := range []string{"Archive", "Compressed:", "Declared output:", "Expansion:", "Files:", "Max depth:", "Compression", "2 entries"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
}

func TestInspectJSON(t *testing.T) {
	p := writeZip(t, "docs/notes.txt", "a/b/c/deep.txt")

	code, stdout, _ := run(t, "inspect", "--json", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}

	var got struct {
		Path           string  `json:"path"`
		ArchiveSize    int64   `json:"archive_size"`
		DeclaredSize   int64   `json:"declared_size"`
		ExpansionRatio float64 `json:"expansion_ratio"`
		FileCount      int64   `json:"file_count"`
		MaxDepth       int     `json:"max_depth"`
		Entries        []any   `json:"entries"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}

	if got.Path != p {
		t.Errorf("path = %q, want %q", got.Path, p)
	}
	if got.FileCount != 2 {
		t.Errorf("file_count = %d, want 2", got.FileCount)
	}
	if got.MaxDepth != 3 {
		t.Errorf("max_depth = %d, want 3", got.MaxDepth)
	}
	if got.ExpansionRatio <= 0 || got.DeclaredSize <= 0 || got.ArchiveSize <= 0 {
		t.Errorf("sizes/ratio not populated: %+v", got)
	}
	// Entries are verbose-only, so the default report must stay bounded.
	if len(got.Entries) != 0 {
		t.Errorf("entries present without --verbose: %d", len(got.Entries))
	}
}

func TestInspectVerboseIncludesEntries(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")

	code, stdout, _ := run(t, "inspect", "--verbose", "--json", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d", code)
	}
	var got struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Name != "docs/notes.txt" {
		t.Errorf("entries = %+v", got.Entries)
	}

	_, human, _ := run(t, "inspect", "--verbose", p)
	if !strings.Contains(human, "docs/notes.txt") {
		t.Errorf("verbose output missing entry list:\n%s", human)
	}
}

func TestInspectQuietIsOneLine(t *testing.T) {
	p := writeZip(t, "a.txt")

	code, stdout, _ := run(t, "inspect", "--quiet", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d", code)
	}
	if n := strings.Count(strings.TrimSpace(stdout), "\n"); n != 0 {
		t.Errorf("quiet output should be one line, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "files") {
		t.Errorf("quiet output = %q", stdout)
	}
}

// Declared size and file count are exact regardless of compression, so they
// pin down the human formatting: units, one decimal, and digit grouping.
func TestInspectFormatsNumbers(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range 1000 {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:   fmt.Sprintf("f%04d.bin", i),
			Method: zip.Store,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, 1536)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(t.TempDir(), "many.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stdout, _ := run(t, "inspect", p)
	for _, want := range []string{"Declared output:  1.5 MB", "Files:            1,000"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
}

func TestInspectEmptyArchive(t *testing.T) {
	p := writeZip(t)

	code, stdout, _ := run(t, "inspect", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}
	if !strings.Contains(stdout, "Expansion:        n/a") {
		t.Errorf("an empty archive should not report an expansion ratio:\n%s", stdout)
	}
}

func TestInspectRequiresOneArgument(t *testing.T) {
	for _, args := range [][]string{{"inspect"}, {"inspect", "a.zip", "b.zip"}} {
		code, _, _ := run(t, args...)
		if code != cli.ExitUsage {
			t.Errorf("%v: code = %d, want %d", args, code, cli.ExitUsage)
		}
	}
}

func TestInspectMissingFile(t *testing.T) {
	code, _, stderr := run(t, "inspect", filepath.Join(t.TempDir(), "absent.zip"))
	if code != cli.ExitError {
		t.Fatalf("code = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(stderr, "inspect") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestInspectMalformedArchive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.zip")
	if err := os.WriteFile(p, []byte("not a zip at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t, "inspect", p)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d", code, cli.ExitRisk)
	}
	if !strings.Contains(stderr, "invalid zip archive") {
		t.Errorf("stderr = %q", stderr)
	}
}
