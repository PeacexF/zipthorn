package cli_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/cli"
)

// writeRawZip builds an archive from explicit headers so entry names that the
// zip.Writer would sanitize can still reach the detector.
func writeRawZip(t *testing.T, names ...string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.CreateRaw(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatalf("CreateRaw(%q): %v", n, err)
		}
		if _, err := w.Write(nil); err != nil {
			t.Fatalf("Write(%q): %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	p := filepath.Join(t.TempDir(), "raw.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// bombZip is highly compressible, so it trips the ratio rule on real metadata.
func bombZip(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("payload.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 8<<20)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(t.TempDir(), "bomb.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectCleanArchiveIsAccepted(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")

	code, stdout, stderr := run(t, "detect", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d (stderr: %s)", code, cli.ExitOK, stderr)
	}
	for _, want := range []string{"Risk", "Compression:", "File count:", "Nesting:", "Paths:", "Recommendation: ACCEPT", "Score: 0/100"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output missing %q:\n%s", want, stdout)
		}
	}
}

// A rejection is a policy signal, so it exits non-zero without an error line.
func TestDetectRejectionExitsWithRiskCode(t *testing.T) {
	p := bombZip(t)

	code, stdout, stderr := run(t, "detect", p)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d\n%s", code, cli.ExitRisk, stdout)
	}
	if !strings.Contains(stdout, "Recommendation: REJECT") {
		t.Errorf("output missing the rejection:\n%s", stdout)
	}
	if !strings.Contains(stdout, "HIGH_COMPRESSION_RATIO") {
		t.Errorf("output missing the triggered indicator:\n%s", stdout)
	}
	if stderr != "" {
		t.Errorf("a verdict must not print an error: %q", stderr)
	}
}

func TestDetectTraversalIsRejected(t *testing.T) {
	p := writeRawZip(t, "../../etc/passwd", "ok.txt")

	code, stdout, _ := run(t, "detect", p)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d\n%s", code, cli.ExitRisk, stdout)
	}
	if !strings.Contains(stdout, "PATH_TRAVERSAL") {
		t.Errorf("output missing PATH_TRAVERSAL:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Paths:            HIGH") {
		t.Errorf("paths category should be HIGH:\n%s", stdout)
	}
}

func TestDetectJSON(t *testing.T) {
	p := bombZip(t)

	code, stdout, _ := run(t, "detect", "--json", p)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d", code, cli.ExitRisk)
	}

	var got struct {
		Path           string `json:"path"`
		Level          string `json:"level"`
		Score          int    `json:"score"`
		Recommendation string `json:"recommendation"`
		Categories     []struct {
			Name  string `json:"name"`
			Level string `json:"level"`
		} `json:"categories"`
		Indicators []struct {
			ID        string  `json:"id"`
			Level     string  `json:"level"`
			Value     float64 `json:"value"`
			Threshold float64 `json:"threshold"`
		} `json:"indicators"`
		Features struct {
			ExpansionRatio float64 `json:"expansion_ratio"`
			FileCount      int64   `json:"file_count"`
		} `json:"features"`
		Thresholds struct {
			ExpansionRatio float64 `json:"expansion_ratio"`
		} `json:"thresholds"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}

	if got.Path != p || got.Recommendation != "REJECT" || got.Level != "HIGH" {
		t.Errorf("assessment = %+v", got)
	}
	if len(got.Categories) != 4 {
		t.Errorf("categories = %+v, want 4", got.Categories)
	}
	if len(got.Indicators) == 0 {
		t.Fatal("no indicators reported")
	}
	if got.Indicators[0].ID != "HIGH_COMPRESSION_RATIO" || got.Indicators[0].Threshold <= 0 {
		t.Errorf("indicators[0] = %+v", got.Indicators[0])
	}
	if got.Score <= 0 || got.Features.ExpansionRatio <= 0 || got.Thresholds.ExpansionRatio <= 0 {
		t.Errorf("score/features/thresholds not populated: %+v", got)
	}
}

func TestDetectQuietIsOneLine(t *testing.T) {
	p := bombZip(t)

	code, stdout, _ := run(t, "detect", "--quiet", p)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d", code)
	}
	if n := strings.Count(strings.TrimSpace(stdout), "\n"); n != 0 {
		t.Errorf("quiet output should be one line, got:\n%s", stdout)
	}
	if !strings.HasPrefix(stdout, "REJECT HIGH score ") {
		t.Errorf("quiet output = %q", stdout)
	}
}

func TestDetectVerboseShowsEvidence(t *testing.T) {
	p := writeRawZip(t, "../../etc/passwd")

	_, plain, _ := run(t, "detect", p)
	if strings.Contains(plain, "etc/passwd") {
		t.Errorf("entry names should stay behind --verbose:\n%s", plain)
	}

	_, verbose, _ := run(t, "detect", "--verbose", p)
	if !strings.Contains(verbose, "../../etc/passwd") {
		t.Errorf("verbose output missing evidence:\n%s", verbose)
	}
}

// Thresholds are policy, so the same archive can be accepted or rejected
// depending on the environment being modelled.
func TestDetectThresholdFlags(t *testing.T) {
	p := bombZip(t)

	code, _, stderr := run(t, "detect", "--threshold-ratio", "100000", p)
	if code != cli.ExitOK {
		t.Fatalf("a raised ratio threshold should accept: code = %d (%s)", code, stderr)
	}

	code, stdout, _ := run(t, "detect", "--threshold-files", "1", p)
	if code != cli.ExitRisk || !strings.Contains(stdout, "EXCESSIVE_FILE_COUNT") {
		t.Errorf("a lowered file threshold should trigger:\ncode = %d\n%s", code, stdout)
	}
}

func TestDetectSizeThresholdAcceptsUnits(t *testing.T) {
	p := writeZip(t, "a.txt")

	for _, size := range []string{"1", "1KB", "1.5 MB", "2GiB"} {
		code, _, stderr := run(t, "detect", "--threshold-size", size, p)
		if code != cli.ExitOK && code != cli.ExitRisk {
			t.Errorf("--threshold-size %q: code = %d (%s)", size, code, stderr)
		}
	}

	code, _, _ := run(t, "detect", "--threshold-size", "12 bananas", p)
	if code != cli.ExitUsage {
		t.Errorf("an unparseable size should be a usage error, got %d", code)
	}
}

func TestDetectRequiresOneArgument(t *testing.T) {
	for _, args := range [][]string{{"detect"}, {"detect", "a.zip", "b.zip"}} {
		code, _, _ := run(t, args...)
		if code != cli.ExitUsage {
			t.Errorf("%v: code = %d, want %d", args, code, cli.ExitUsage)
		}
	}
}

func TestDetectMalformedArchive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.zip")
	if err := os.WriteFile(p, []byte("not a zip at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t, "detect", p)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d", code, cli.ExitRisk)
	}
	if !strings.Contains(stderr, "invalid zip archive") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestDetectMissingFile(t *testing.T) {
	code, _, _ := run(t, "detect", filepath.Join(t.TempDir(), "absent.zip"))
	if code != cli.ExitError {
		t.Errorf("code = %d, want %d", code, cli.ExitError)
	}
}
