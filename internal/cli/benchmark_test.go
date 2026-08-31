package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/generator"
)

func TestBenchmarkCommand(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create test archive
	spec := generator.Spec{
		Profile:   generator.ProfileRatio,
		Seed:      42,
		FileCount: 5,
		FileSize:  1024,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runBenchmark: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "zipthorn") {
		t.Errorf("output missing header")
	}
	if !strings.Contains(out, "Archive") {
		t.Errorf("output missing archive section")
	}
	if !strings.Contains(out, "Performance") {
		t.Errorf("output missing performance section")
	}
	if !strings.Contains(out, "Memory") {
		t.Errorf("output missing memory section")
	}
	if !strings.Contains(out, "Result") {
		t.Errorf("output missing result section")
	}
}

func TestBenchmarkJSON(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create test archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 3,
		FileSize:  512,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"--json", archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runBenchmark: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json decode: %v", err)
	}

	if _, ok := result["status"]; !ok {
		t.Error("json missing status field")
	}
	if _, ok := result["wall_time_nanos"]; !ok {
		t.Error("json missing wall_time_nanos field")
	}
	if _, ok := result["throughput_mbps"]; !ok {
		t.Error("json missing throughput_mbps field")
	}
}

func TestBenchmarkMultipleRuns(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create test archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 3,
		FileSize:  100,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"--runs", "3", archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runBenchmark: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Benchmark (3 runs)") {
		t.Errorf("output missing benchmark runs header")
	}
	if !strings.Contains(out, "Mean wall time") {
		t.Errorf("output missing mean wall time")
	}
	if !strings.Contains(out, "Individual Runs") {
		t.Errorf("output missing individual runs section")
	}
	if !strings.Contains(out, "Run 1:") {
		t.Errorf("output missing run 1")
	}
	if !strings.Contains(out, "Run 3:") {
		t.Errorf("output missing run 3")
	}
}

func TestBenchmarkMultipleRunsJSON(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create test archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 2,
		FileSize:  100,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"--json", "--runs", "2", archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runBenchmark: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json decode: %v", err)
	}

	runs, ok := result["runs"].([]interface{})
	if !ok {
		t.Fatal("json missing runs array")
	}
	if len(runs) != 2 {
		t.Errorf("got %d runs, want 2", len(runs))
	}

	if _, ok := result["aggregate"]; !ok {
		t.Error("json missing aggregate field")
	}
}

func TestBenchmarkWithLimits(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create test archive
	spec := generator.Spec{
		Profile:      generator.ProfileRatio,
		Seed:         42,
		DeclaredSize: 5 * 1024 * 1024, // 5MB
		FileCount:    50,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"--max-bytes", "1MB", archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runBenchmark: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "LIMIT_REACHED") {
		t.Errorf("expected LIMIT_REACHED status, got: %s", out)
	}
}

func TestBenchmarkNoArchive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{}

	err := runBenchmark(args, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for no archive")
	}
	if ce, ok := err.(*CodedError); !ok || ce.Code != ExitUsage {
		t.Errorf("expected ExitUsage, got %v", err)
	}
}

func TestBenchmarkNonexistentArchive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"/nonexistent/archive.zip"}

	err := runBenchmark(args, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for nonexistent archive")
	}
	if ce, ok := err.(*CodedError); !ok || ce.Code != ExitError {
		t.Errorf("expected ExitError, got %v", err)
	}
}

func TestBenchmarkInvalidRuns(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")

	// Create test archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 2,
		FileSize:  100,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"--runs", "0", archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for runs=0")
	}
	if ce, ok := err.(*CodedError); !ok || ce.Code != ExitUsage {
		t.Errorf("expected ExitUsage, got %v", err)
	}
}

func TestBenchmarkDestDir(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "test.zip")
	destDir := filepath.Join(tmp, "extract")

	// Create test archive
	spec := generator.Spec{
		Profile:   generator.ProfileFileCount,
		Seed:      42,
		FileCount: 2,
		FileSize:  100,
	}

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = generator.Generate(f, spec)
	f.Close()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"--dest", destDir, archivePath}

	err = runBenchmark(args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runBenchmark: %v", err)
	}

	// Verify dest dir was used
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		t.Error("dest dir should exist after successful extraction")
	}
}
