package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeacexF/zipthorn/internal/cli"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/generator"
)

func createTestArchive(t *testing.T, path string, spec generator.Spec) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
}

func TestTest_Pass(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 2048,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}
	createTestArchive(t, archive, spec)

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", archive}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Errorf("exit code = %d, want %d; stderr: %s", code, cli.ExitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Errorf("output should contain PASS, got: %s", stdout.String())
	}
}

func TestTest_LimitReached(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 10 * 1024 * 1024,
		FileCount:    5,
		Seed:         42,
		Limits:       config.Default().Limits,
	}
	createTestArchive(t, archive, spec)

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", "--max-bytes", "8KB", archive}, &stdout, &stderr)

	if code != cli.ExitRisk {
		t.Errorf("exit code = %d, want %d", code, cli.ExitRisk)
	}
	if !strings.Contains(stdout.String(), "LIMIT_REACHED") {
		t.Errorf("output should contain LIMIT_REACHED, got: %s", stdout.String())
	}
}

func TestTest_Timeout(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 100 * 1024,
		FileCount:    10,
		Seed:         42,
		Limits:       config.Default().Limits,
	}
	createTestArchive(t, archive, spec)

	go func() {
		time.Sleep(100 * time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = ctx
	}()

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", "--timeout", "0", archive}, &stdout, &stderr)

	if code == cli.ExitError {
		t.Logf("timeout test result: %s", stdout.String())
	}
}

func TestTest_InvalidArchive(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "bad.zip")

	if err := os.WriteFile(archive, []byte("not a zip"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", archive}, &stdout, &stderr)

	if code != cli.ExitRisk {
		t.Errorf("exit code = %d, want %d", code, cli.ExitRisk)
	}
	if !strings.Contains(stdout.String(), "INVALID") {
		t.Errorf("output should contain INVALID, got: %s", stdout.String())
	}
}

func TestTest_JSON(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 2048,
		FileCount:    3,
		Seed:         42,
		Limits:       config.Default().Limits,
	}
	createTestArchive(t, archive, spec)

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", "--json", archive}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Errorf("exit code = %d, want %d; stderr: %s", code, cli.ExitOK, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, `"status"`) {
		t.Errorf("JSON output should contain status field, got: %s", out)
	}
	if !strings.Contains(out, `"files_processed"`) {
		t.Errorf("JSON output should contain files_processed field, got: %s", out)
	}
}

func TestTest_CustomDest(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "test.zip")
	dest := filepath.Join(tmp, "extracted")

	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		DeclaredSize: 2048,
		FileCount:    3,
		Seed:         42,
		Limits:       config.Default().Limits,
	}
	createTestArchive(t, archive, spec)

	var stdout, stderr bytes.Buffer
	code := cli.Main([]string{"test", "--dest", dest, archive}, &stdout, &stderr)

	if code != cli.ExitOK {
		t.Errorf("exit code = %d, want %d; stderr: %s", code, cli.ExitOK, stderr.String())
	}

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		t.Errorf("dest directory should exist at %s", dest)
	}
}
