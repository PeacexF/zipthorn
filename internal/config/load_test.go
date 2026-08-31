package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PeacexF/zipthorn/internal/config"
)

func TestLoadMissingFiles(t *testing.T) {
	// Missing files should not error - just return defaults
	cfg, err := config.Load()
	if err != nil {
		t.Errorf("Load with missing files should not error: %v", err)
	}

	defaults := config.Default()
	if cfg.Limits.MaxOutputBytes != defaults.Limits.MaxOutputBytes {
		t.Errorf("missing files should return defaults")
	}
}

func TestLoadFromExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	content := `limits:
  max_output_bytes: 128MB
  max_files: 5000

thresholds:
  expansion_ratio: 75x
  file_count: 8000
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := config.LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if cfg.Limits.MaxOutputBytes != 128*config.MB {
		t.Errorf("max_output_bytes = %d, want %d", cfg.Limits.MaxOutputBytes, 128*config.MB)
	}
	if cfg.Limits.MaxFiles != 5000 {
		t.Errorf("max_files = %d, want 5000", cfg.Limits.MaxFiles)
	}
	if cfg.Thresholds.ExpansionRatio != 75 {
		t.Errorf("expansion_ratio = %f, want 75", cfg.Thresholds.ExpansionRatio)
	}
	if cfg.Thresholds.FileCount != 8000 {
		t.Errorf("file_count = %d, want 8000", cfg.Thresholds.FileCount)
	}
}

func TestParseSizes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"512", 512},
		{"8KB", 8 * config.KB},
		{"8 KB", 8 * config.KB},
		{"1.5MB", int64(1.5 * float64(config.MB))},
		{"2GiB", 2 * config.GB},
		{"100 M", 100 * config.MB},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "config.yaml")

			content := "limits:\n  max_output_bytes: " + tt.input + "\n"
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}

			cfg, err := config.LoadFrom(path)
			if err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}

			if cfg.Limits.MaxOutputBytes != tt.want {
				t.Errorf("got %d, want %d", cfg.Limits.MaxOutputBytes, tt.want)
			}
		})
	}
}

func TestParseRatios(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"100", 100},
		{"50x", 50},
		{"1.5x", 1.5},
		{"75", 75},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "config.yaml")

			content := "thresholds:\n  expansion_ratio: " + tt.input + "\n"
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}

			cfg, err := config.LoadFrom(path)
			if err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}

			if cfg.Thresholds.ExpansionRatio != tt.want {
				t.Errorf("got %f, want %f", cfg.Thresholds.ExpansionRatio, tt.want)
			}
		})
	}
}

func TestUnknownSection(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	content := `unknown_section:
  key: value
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := config.LoadFrom(path)
	if err == nil {
		t.Error("expected error for unknown section")
	}
}

func TestUnknownKey(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	content := `limits:
  unknown_key: 123
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := config.LoadFrom(path)
	if err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestMalformedFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"no colon", "limits\n  bad line"},
		{"key outside section", "max_files: 100"},
		{"invalid size", "limits:\n  max_output_bytes: notasize"},
		{"invalid ratio", "thresholds:\n  expansion_ratio: bad"},
		{"negative value", "limits:\n  max_files: -100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "config.yaml")

			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}

			_, err := config.LoadFrom(path)
			if err == nil {
				t.Errorf("expected error for malformed content: %s", tt.content)
			}
		})
	}
}

func TestCommentsAndEmptyLines(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	content := `# This is a comment

limits:
  # Another comment
  max_files: 1000

  max_depth: 20

thresholds:
  expansion_ratio: 25
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := config.LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if cfg.Limits.MaxFiles != 1000 {
		t.Errorf("max_files = %d, want 1000", cfg.Limits.MaxFiles)
	}
	if cfg.Limits.MaxDepth != 20 {
		t.Errorf("max_depth = %d, want 20", cfg.Limits.MaxDepth)
	}
	if cfg.Thresholds.ExpansionRatio != 25 {
		t.Errorf("expansion_ratio = %f, want 25", cfg.Thresholds.ExpansionRatio)
	}
}

func TestAllFields(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	content := `limits:
  max_output_bytes: 512MB
  max_expansion_ratio: 200x
  max_files: 20000
  max_depth: 64
  max_nesting: 8

thresholds:
  expansion_ratio: 100x
  declared_size: 2GB
  file_count: 15000
  depth: 32
  nesting: 4
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := config.LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if cfg.Limits.MaxOutputBytes != 512*config.MB {
		t.Errorf("max_output_bytes wrong")
	}
	if cfg.Limits.MaxExpansionRatio != 200 {
		t.Errorf("max_expansion_ratio wrong")
	}
	if cfg.Limits.MaxFiles != 20000 {
		t.Errorf("max_files wrong")
	}
	if cfg.Limits.MaxDepth != 64 {
		t.Errorf("max_depth wrong")
	}
	if cfg.Limits.MaxNesting != 8 {
		t.Errorf("max_nesting wrong")
	}

	if cfg.Thresholds.ExpansionRatio != 100 {
		t.Errorf("expansion_ratio wrong")
	}
	if cfg.Thresholds.DeclaredSize != 2*config.GB {
		t.Errorf("declared_size wrong")
	}
	if cfg.Thresholds.FileCount != 15000 {
		t.Errorf("file_count wrong")
	}
	if cfg.Thresholds.Depth != 32 {
		t.Errorf("depth wrong")
	}
	if cfg.Thresholds.Nesting != 4 {
		t.Errorf("nesting wrong")
	}
}

func TestPrecedence(t *testing.T) {
	tmp := t.TempDir()

	// Create two config files with different values
	file1 := filepath.Join(tmp, "first.yaml")
	content1 := "limits:\n  max_files: 1000\n"
	if err := os.WriteFile(file1, []byte(content1), 0644); err != nil {
		t.Fatalf("write file1: %v", err)
	}

	file2 := filepath.Join(tmp, "second.yaml")
	content2 := "limits:\n  max_files: 2000\n"
	if err := os.WriteFile(file2, []byte(content2), 0644); err != nil {
		t.Fatalf("write file2: %v", err)
	}

	// Load first file
	cfg, err := config.LoadFrom(file1)
	if err != nil {
		t.Fatalf("LoadFrom file1: %v", err)
	}
	if cfg.Limits.MaxFiles != 1000 {
		t.Errorf("after file1: max_files = %d, want 1000", cfg.Limits.MaxFiles)
	}

	// Load second file - should override
	cfg, err = config.LoadFrom(file2)
	if err != nil {
		t.Fatalf("LoadFrom file2: %v", err)
	}
	if cfg.Limits.MaxFiles != 2000 {
		t.Errorf("after file2: max_files = %d, want 2000", cfg.Limits.MaxFiles)
	}
}
