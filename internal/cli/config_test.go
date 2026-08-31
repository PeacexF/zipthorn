package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/cli"
)

func configFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// configReport is the shape every config-carrying command adds to its JSON.
type configReport struct {
	Limits struct {
		MaxFiles int64 `json:"max_files"`
	} `json:"limits"`
	Thresholds struct {
		Depth int `json:"depth"`
	} `json:"thresholds"`
	Sources struct {
		Files  []string `json:"files"`
		Fields []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Origin struct {
				Layer  string `json:"layer"`
				Source string `json:"source"`
			} `json:"origin"`
		} `json:"fields"`
	} `json:"sources"`
}

func decodeConfig(t *testing.T, stdout string) configReport {
	t.Helper()
	var envelope struct {
		Config configReport `json:"config"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, stdout)
	}
	return envelope.Config
}

func originFor(t *testing.T, r configReport, key string) (layer, source, value string) {
	t.Helper()
	for _, f := range r.Sources.Fields {
		if f.Key == key {
			return f.Origin.Layer, f.Origin.Source, f.Value
		}
	}
	t.Fatalf("no field %q in config report", key)
	return "", "", ""
}

func TestJSONCarriesEffectiveConfig(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "thresholds:\n  depth: 3\n")

	code, stdout, stderr := run(t, "--config", cfg, "detect", "--json", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d (stderr: %s)", code, stderr)
	}

	got := decodeConfig(t, stdout)
	if got.Thresholds.Depth != 3 {
		t.Errorf("thresholds.depth = %d, want 3", got.Thresholds.Depth)
	}
	if len(got.Sources.Files) != 1 || got.Sources.Files[0] != cfg {
		t.Errorf("sources.files = %v, want [%s]", got.Sources.Files, cfg)
	}

	layer, source, _ := originFor(t, got, "thresholds.depth")
	if layer != "file" || source != cfg {
		t.Errorf("depth origin = %s/%s, want file/%s", layer, source, cfg)
	}
	if layer, _, _ := originFor(t, got, "thresholds.nesting"); layer != "default" {
		t.Errorf("untouched nesting origin = %s, want default", layer)
	}
}

// The whole point of the provenance record: a flag the user typed is credited
// to the flag, and a flag they left alone leaves the file's value attributed to
// the file.
func TestFlagOverrideIsAttributedToTheFlag(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "thresholds:\n  depth: 3\n  file_count: 42\n")

	code, stdout, stderr := run(t, "--config", cfg, "detect", "--json", "--threshold-depth", "9", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d (stderr: %s)", code, stderr)
	}

	got := decodeConfig(t, stdout)
	if got.Thresholds.Depth != 9 {
		t.Errorf("thresholds.depth = %d, want the flag's 9", got.Thresholds.Depth)
	}

	if layer, _, value := originFor(t, got, "thresholds.depth"); layer != "flag" || value != "9" {
		t.Errorf("depth origin = %s value = %s, want flag/9", layer, value)
	}
	if layer, source, value := originFor(t, got, "thresholds.file_count"); layer != "file" || source != cfg || value != "42" {
		t.Errorf("file_count origin = %s/%s value = %s, want file/%s/42", layer, source, value, cfg)
	}
}

// A named policy replaces the configured thresholds outright, so the report
// must not keep crediting the file for values the policy overrode.
func TestPolicySupersedesConfiguredThresholds(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "thresholds:\n  depth: 3\nlimits:\n  max_files: 77\n")

	code, stdout, stderr := run(t, "--config", cfg, "detect", "--json", "--policy", "strict", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d (stderr: %s)", code, stderr)
	}

	got := decodeConfig(t, stdout)
	if layer, source, _ := originFor(t, got, "thresholds.depth"); layer != "policy" || source != "strict" {
		t.Errorf("depth origin = %s/%s, want policy/strict", layer, source)
	}
	// Limits are not a policy's business; the file still owns them.
	if layer, _, value := originFor(t, got, "limits.max_files"); layer != "file" || value != "77" {
		t.Errorf("max_files origin = %s value = %s, want file/77", layer, value)
	}
}

func TestVerbosePrintsConfigProvenance(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "limits:\n  max_files: 77\n")

	code, stdout, stderr := run(t, "--config", cfg, "detect", "--verbose", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d (stderr: %s)", code, stderr)
	}

	for _, want := range []string{"Configuration", cfg, "limits.max_files", "77", "thresholds.nesting", "default"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("verbose output missing %q:\n%s", want, stdout)
		}
	}
}

// Without --verbose the config block stays out of the human report.
func TestNonVerboseOmitsConfigProvenance(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")

	code, stdout, _ := run(t, "detect", p)
	if code != cli.ExitOK {
		t.Fatalf("code = %d", code)
	}
	if strings.Contains(stdout, "limits.max_output_bytes") {
		t.Errorf("non-verbose output leaked the config block:\n%s", stdout)
	}
}

// --config must work in both spellings and on either side of the subcommand.
func TestConfigFlagSpellings(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "limits:\n  max_files: 77\n")

	forms := [][]string{
		{"--config", cfg, "detect", "--json", p},
		{"--config=" + cfg, "detect", "--json", p},
		{"detect", "--json", "--config", cfg, p},
		{"detect", "--json", "--config=" + cfg, p},
	}

	for _, args := range forms {
		code, stdout, stderr := run(t, args...)
		if code != cli.ExitOK {
			t.Fatalf("%v: code = %d (stderr: %s)", args, code, stderr)
		}
		if got := decodeConfig(t, stdout); got.Limits.MaxFiles != 77 {
			t.Errorf("%v: max_files = %d, want 77", args, got.Limits.MaxFiles)
		}
	}
}

func TestConfigFlagWithoutValueIsAUsageError(t *testing.T) {
	code, _, stderr := run(t, "detect", "--config")
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(stderr, "needs an argument") {
		t.Errorf("stderr should explain the missing value, got: %s", stderr)
	}
}

func TestMissingExplicitConfigFails(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	missing := filepath.Join(t.TempDir(), "absent.yaml")

	code, _, stderr := run(t, "--config", missing, "detect", p)
	if code == cli.ExitOK {
		t.Fatal("an explicit --config that does not exist must fail")
	}
	if !strings.Contains(stderr, "absent.yaml") {
		t.Errorf("error should name the missing file, got: %s", stderr)
	}
}

func TestMalformedConfigFailsClosed(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "limits:\n  max_files: not-a-number\n")

	code, _, stderr := run(t, "--config", cfg, "detect", p)
	if code == cli.ExitOK {
		t.Fatal("a malformed config must not fall back to defaults")
	}
	if !strings.Contains(stderr, "max_files") {
		t.Errorf("error should name the offending key, got: %s", stderr)
	}
}

func TestUnknownConfigKeyFailsClosed(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")
	cfg := configFile(t, "limits:\n  max_bananas: 3\n")

	code, _, stderr := run(t, "--config", cfg, "detect", p)
	if code == cli.ExitOK {
		t.Fatal("an unknown config key must fail closed")
	}
	if !strings.Contains(stderr, "max_bananas") {
		t.Errorf("error should name the unknown key, got: %s", stderr)
	}
}

// test and create resolve the same config, so their JSON carries it too.
func TestOtherCommandsCarryConfig(t *testing.T) {
	cfg := configFile(t, "limits:\n  max_files: 77\n")

	t.Run("test", func(t *testing.T) {
		p := writeZip(t, "docs/notes.txt")
		code, stdout, stderr := run(t, "--config", cfg, "test", "--json", p)
		if code != cli.ExitOK {
			t.Fatalf("code = %d (stderr: %s)", code, stderr)
		}
		if got := decodeConfig(t, stdout); got.Limits.MaxFiles != 77 {
			t.Errorf("max_files = %d, want 77", got.Limits.MaxFiles)
		}
	})

	t.Run("create", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "fixture.zip")
		code, stdout, stderr := run(t, "--config", cfg, "create", "--json", "--output", out)
		if code != cli.ExitOK {
			t.Fatalf("code = %d (stderr: %s)", code, stderr)
		}
		if got := decodeConfig(t, stdout); got.Limits.MaxFiles != 77 {
			t.Errorf("max_files = %d, want 77", got.Limits.MaxFiles)
		}
	})
}
