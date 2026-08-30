package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/cli"
)

func outPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestCreateWritesArchive(t *testing.T) {
	path := outPath(t, "fixture.zip")
	code, stdout, stderr := run(t, "create", "--profile", "ratio",
		"--declared-size", "1MB", "--output", path)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d (stderr: %s)", code, cli.ExitOK, stderr)
	}
	if !strings.Contains(stdout, "Expansion") {
		t.Errorf("stdout missing report:\n%s", stdout)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() == 0 {
		t.Fatal("wrote an empty archive")
	}

	// The fixture must survive the tool's own reader.
	if code, _, stderr := run(t, "inspect", path); code != cli.ExitOK {
		t.Fatalf("inspect: code = %d (stderr: %s)", code, stderr)
	}
}

func TestCreateJSON(t *testing.T) {
	path := outPath(t, "fixture.zip")
	code, stdout, _ := run(t, "create", "--json", "--profile", "metadata", "--output", path)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}

	var res struct {
		Path         string  `json:"path"`
		Profile      string  `json:"profile"`
		DeclaredSize int64   `json:"declared_size"`
		Ratio        float64 `json:"expansion_ratio"`
		FileCount    int64   `json:"file_count"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("decoding %q: %v", stdout, err)
	}
	if res.Profile != "metadata" || res.Path != path || res.FileCount == 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestCreateDetectsAsUnsafe(t *testing.T) {
	path := outPath(t, "bomb.zip")
	if code, _, stderr := run(t, "create", "--profile", "ratio",
		"--declared-size", "4MB", "--output", path); code != cli.ExitOK {
		t.Fatalf("create: code = %d (stderr: %s)", code, stderr)
	}

	code, stdout, _ := run(t, "detect", path)
	if code != cli.ExitRisk {
		t.Fatalf("detect: code = %d, want %d", code, cli.ExitRisk)
	}
	if !strings.Contains(stdout, "HIGH_COMPRESSION_RATIO") {
		t.Errorf("detect did not flag the fixture:\n%s", stdout)
	}
}

func TestCreateSameSeedIsReproducible(t *testing.T) {
	dir := t.TempDir()
	var archives [2][]byte
	for i, name := range []string{"a.zip", "b.zip"} {
		path := filepath.Join(dir, name)
		if code, _, stderr := run(t, "create", "--profile", "mixed", "--seed", "99",
			"--declared-size", "512KB", "--output", path); code != cli.ExitOK {
			t.Fatalf("create %s: code = %d (stderr: %s)", name, code, stderr)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		archives[i] = data
	}
	if string(archives[0]) != string(archives[1]) {
		t.Error("same seed produced different archives")
	}
}

func TestCreateRequiresOutput(t *testing.T) {
	code, _, stderr := run(t, "create", "--profile", "ratio")
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(stderr, "--output is required") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestCreateRejectsUnknownProfile(t *testing.T) {
	path := outPath(t, "fixture.zip")
	code, _, stderr := run(t, "create", "--profile", "nope", "--output", path)
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(stderr, "unknown profile") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a refused profile left an output file behind")
	}
}

func TestCreateLeavesNoFileWhenLimitExceeded(t *testing.T) {
	path := outPath(t, "fixture.zip")
	code, _, stderr := run(t, "create", "--profile", "ratio",
		"--declared-size", "64MB", "--max-output", "1MB", "--output", path)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d", code, cli.ExitRisk)
	}
	if !strings.Contains(stderr, "safety limit exceeded") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a refused generation left an output file behind")
	}
}

func TestCreateHonoursMaxExpansionSuffix(t *testing.T) {
	path := outPath(t, "fixture.zip")
	code, _, stderr := run(t, "create", "--profile", "ratio", "--ratio", "40x",
		"--max-expansion", "20x", "--declared-size", "1MB", "--output", path)
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d (stderr: %s)", code, cli.ExitRisk, stderr)
	}
}

func TestCreateWillNotOverwriteWithoutForce(t *testing.T) {
	path := outPath(t, "fixture.zip")
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t, "create", "--profile", "depth", "--output", path)
	if code != cli.ExitError {
		t.Fatalf("code = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("stderr = %q", stderr)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "existing" {
		t.Errorf("existing file was modified: %q (%v)", data, err)
	}

	if code, _, stderr := run(t, "create", "--profile", "depth", "--force", "--output", path); code != cli.ExitOK {
		t.Fatalf("--force: code = %d (stderr: %s)", code, stderr)
	}
}

func TestCreateQuiet(t *testing.T) {
	path := outPath(t, "fixture.zip")
	code, stdout, _ := run(t, "create", "--quiet", "--profile", "depth", "--output", path)
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}
	if lines := strings.Count(strings.TrimSpace(stdout), "\n"); lines != 0 {
		t.Errorf("quiet output spans %d lines:\n%s", lines+1, stdout)
	}
}
