package integration_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/cli"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/generator"
)

// TestCreateInspect verifies create → inspect flow
func TestCreateInspect(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	var stdout, stderr bytes.Buffer

	// Create archive
	code := cli.Main([]string{
		"create",
		"--output", archive,
		"--profile", "ratio",
		"--declared-size", "8KB",
		"--files", "5",
		"--seed", "42",
	}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("create failed: code=%d, stderr=%s", code, stderr.String())
	}

	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("archive not created: %v", err)
	}

	// Inspect archive
	stdout.Reset()
	stderr.Reset()

	code = cli.Main([]string{"inspect", archive}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("inspect failed: code=%d, stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Files:") {
		t.Errorf("inspect output missing Files field: %s", out)
	}
	if !strings.Contains(out, "Declared output:") {
		t.Errorf("inspect output missing Declared output field: %s", out)
	}
}

// TestCreateDetect verifies create → detect flow
func TestCreateDetect(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	var stdout, stderr bytes.Buffer

	// Create a pathological archive
	code := cli.Main([]string{
		"create",
		"--output", archive,
		"--profile", "ratio",
		"--declared-size", "10MB",
		"--files", "3",
		"--seed", "99",
	}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("create failed: code=%d, stderr=%s", code, stderr.String())
	}

	// Detect risks
	stdout.Reset()
	stderr.Reset()

	code = cli.Main([]string{"detect", archive}, &stdout, &stderr)

	// Should either pass or flag as risky depending on thresholds
	if code != cli.ExitOK && code != cli.ExitRisk {
		t.Fatalf("detect failed: code=%d, stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Risk") {
		t.Errorf("detect output missing Risk section: %s", out)
	}
	if !strings.Contains(out, "Recommendation") {
		t.Errorf("detect output missing Recommendation: %s", out)
	}
}

// TestCreateTest verifies create → test flow
func TestCreateTest(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "extracted")

	var stdout, stderr bytes.Buffer

	// Create archive
	code := cli.Main([]string{
		"create",
		"--output", archive,
		"--profile", "ratio",
		"--declared-size", "4KB",
		"--files", "3",
		"--seed", "42",
	}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("create failed: code=%d, stderr=%s", code, stderr.String())
	}

	// Test extraction
	stdout.Reset()
	stderr.Reset()

	code = cli.Main([]string{"test", "--dest", dest, archive}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("test failed: code=%d, stderr=%s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "PASS") {
		t.Errorf("test output should show PASS: %s", out)
	}

	// Verify files were extracted
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("extraction dest not created: %v", err)
	}
}

// TestCreateInspectDetectTest verifies full pipeline
func TestCreateInspectDetectTest(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "pipeline.zip")

	var stdout, stderr bytes.Buffer

	// Create
	code := cli.Main([]string{
		"create",
		"--output", archive,
		"--profile", "file-count",
		"--declared-size", "16KB",
		"--files", "50",
		"--seed", "123",
	}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Fatalf("create failed: code=%d", code)
	}

	// Inspect
	stdout.Reset()
	stderr.Reset()
	code = cli.Main([]string{"inspect", "--json", archive}, &stdout, &stderr)
	if code != cli.ExitOK {
		t.Fatalf("inspect failed: code=%d", code)
	}
	if !strings.Contains(stdout.String(), `"file_count"`) {
		t.Errorf("inspect JSON missing file_count")
	}

	// Detect
	stdout.Reset()
	stderr.Reset()
	code = cli.Main([]string{"detect", "--json", archive}, &stdout, &stderr)
	if code != cli.ExitOK && code != cli.ExitRisk {
		t.Fatalf("detect failed: code=%d", code)
	}
	if !strings.Contains(stdout.String(), `"recommendation"`) {
		t.Errorf("detect JSON missing recommendation")
	}

	// Test
	stdout.Reset()
	stderr.Reset()
	code = cli.Main([]string{"test", "--json", archive}, &stdout, &stderr)
	if code != cli.ExitOK {
		t.Fatalf("test failed: code=%d", code)
	}
	if !strings.Contains(stdout.String(), `"status"`) {
		t.Errorf("test JSON missing status")
	}
}

// TestAllProfiles verifies all profiles work end-to-end
func TestAllProfiles(t *testing.T) {
	profiles := []string{"ratio", "file-count", "nested", "depth", "metadata", "mixed"}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			tmp := t.TempDir()
			archive := filepath.Join(tmp, profile+".zip")

			var stdout, stderr bytes.Buffer
			args := []string{
				"create",
				"--output", archive,
				"--profile", profile,
				"--seed", "42",
			}

			if profile == "depth" {
				args = append(args, "--depth", "5")
			}
			if profile == "nested" {
				args = append(args, "--nesting", "2")
			}

			code := cli.Main(args, &stdout, &stderr)
			if code != cli.ExitOK {
				t.Fatalf("create %s failed: code=%d, stderr=%s", profile, code, stderr.String())
			}

			// Verify with inspect
			stdout.Reset()
			stderr.Reset()
			code = cli.Main([]string{"inspect", archive}, &stdout, &stderr)
			if code != cli.ExitOK {
				t.Errorf("inspect %s failed: code=%d", profile, code)
			}
		})
	}
}

// TestDeterministicGeneration verifies same seed produces identical archives
func TestDeterministicGeneration(t *testing.T) {
	tmp := t.TempDir()
	archive1 := filepath.Join(tmp, "a.zip")
	archive2 := filepath.Join(tmp, "b.zip")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 4096,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}

	f1, err := os.Create(archive1)
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	_, err = generator.Generate(f1, spec)
	f1.Close()
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}

	f2, err := os.Create(archive2)
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	_, err = generator.Generate(f2, spec)
	f2.Close()
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}

	data1, err := os.ReadFile(archive1)
	if err != nil {
		t.Fatalf("read a: %v", err)
	}

	data2, err := os.ReadFile(archive2)
	if err != nil {
		t.Fatalf("read b: %v", err)
	}

	if !bytes.Equal(data1, data2) {
		t.Errorf("archives differ with same seed")
	}
}
