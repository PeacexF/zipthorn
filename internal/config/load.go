package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Resolve reads configuration from the standard file hierarchy and records
// which layer supplied each field.
// Precedence (each layer overrides the previous):
//  1. Default()
//  2. ~/.zipthorn/config.yaml (if present)
//  3. ./.zipthorn.config.yaml (if present)
//
// A missing file is not an error. A malformed file or unknown key fails closed.
func Resolve() (*Resolved, error) {
	r := newResolved()

	if home, err := os.UserHomeDir(); err == nil {
		globalPath := filepath.Join(home, filepath.FromSlash(GlobalFileName))
		if err := r.apply(globalPath, LayerGlobal, false); err != nil {
			return r, err
		}
	}

	if err := r.apply(LocalFileName, LayerLocal, false); err != nil {
		return r, err
	}

	return r, nil
}

// ResolveFrom reads configuration from a specific file, skipping discovery.
// The file must exist; a missing file is an error.
func ResolveFrom(path string) (*Resolved, error) {
	r := newResolved()
	if err := r.apply(path, LayerFile, true); err != nil {
		return r, err
	}
	return r, nil
}

// apply layers one file over r. When required is false a missing file is
// skipped; every other failure is reported.
func (r *Resolved) apply(path, layer string, required bool) error {
	origin := Origin{Layer: layer, Source: path}
	err := loadFile(path, &r.Config, func(key string) { r.mark(key, origin) })
	switch {
	case err == nil:
		r.files = append(r.files, path)
		return nil
	case os.IsNotExist(err) && !required:
		return nil
	default:
		return fmt.Errorf("%s: %w", path, err)
	}
}

// Load reads configuration from the standard file hierarchy.
// It is Resolve without the provenance record.
func Load() (Config, error) {
	r, err := Resolve()
	return r.Config, err
}

// LoadFrom reads configuration from a specific file path.
// The file must exist; a missing file is an error.
func LoadFrom(path string) (Config, error) {
	r, err := ResolveFrom(path)
	return r.Config, err
}

func loadFile(path string, cfg *Config, seen func(key string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	var section string

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section header
		if strings.HasSuffix(line, ":") && !strings.Contains(line, " ") {
			section = strings.TrimSuffix(line, ":")
			if section != "limits" && section != "thresholds" {
				return fmt.Errorf("line %d: unknown section %q", lineNum, section)
			}
			continue
		}

		// Key-value pair
		key, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("line %d: expected key:value, got %q", lineNum, line)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if section == "" {
			return fmt.Errorf("line %d: key %q outside of section", lineNum, key)
		}

		if err := setField(section, key, value, cfg); err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
		if seen != nil {
			seen(section + "." + key)
		}
	}

	return scanner.Err()
}

func setField(section, key, value string, cfg *Config) error {
	switch section {
	case "limits":
		return setLimitField(key, value, &cfg.Limits)
	case "thresholds":
		return setThresholdField(key, value, &cfg.Thresholds)
	default:
		return fmt.Errorf("unknown section %q", section)
	}
}

func setLimitField(key, value string, limits *Limits) error {
	switch key {
	case "max_output_bytes":
		v, err := parseSize(value)
		if err != nil {
			return err
		}
		limits.MaxOutputBytes = v
	case "max_expansion_ratio":
		v, err := parseRatio(value)
		if err != nil {
			return err
		}
		limits.MaxExpansionRatio = v
	case "max_files":
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid max_files %q", value)
		}
		limits.MaxFiles = v
	case "max_depth":
		v, err := strconv.Atoi(value)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid max_depth %q", value)
		}
		limits.MaxDepth = v
	case "max_nesting":
		v, err := strconv.Atoi(value)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid max_nesting %q", value)
		}
		limits.MaxNesting = v
	default:
		return fmt.Errorf("unknown limits key %q", key)
	}
	return nil
}

func setThresholdField(key, value string, thresholds *Thresholds) error {
	switch key {
	case "expansion_ratio":
		v, err := parseRatio(value)
		if err != nil {
			return err
		}
		thresholds.ExpansionRatio = v
	case "declared_size":
		v, err := parseSize(value)
		if err != nil {
			return err
		}
		thresholds.DeclaredSize = v
	case "file_count":
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid file_count %q", value)
		}
		thresholds.FileCount = v
	case "depth":
		v, err := strconv.Atoi(value)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid depth %q", value)
		}
		thresholds.Depth = v
	case "nesting":
		v, err := strconv.Atoi(value)
		if err != nil || v < 0 {
			return fmt.Errorf("invalid nesting %q", value)
		}
		thresholds.Nesting = v
	default:
		return fmt.Errorf("unknown thresholds key %q", key)
	}
	return nil
}

// parseSize reads byte sizes like "8MB", "1.5GiB", "512"
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}

	digits, unit := s[:i], strings.ToUpper(strings.TrimSpace(s[i:]))

	multipliers := map[string]int64{
		"":    1,
		"B":   1,
		"K":   KB,
		"KB":  KB,
		"KIB": KB,
		"M":   MB,
		"MB":  MB,
		"MIB": MB,
		"G":   GB,
		"GB":  GB,
		"GIB": GB,
	}

	mult, ok := multipliers[unit]
	if digits == "" || !ok {
		return 0, fmt.Errorf("invalid size %q", s)
	}

	v, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}

	return int64(v * float64(mult)), nil
}

// parseRatio reads ratios like "100x", "50", "1.5x"
func parseRatio(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.ToLower(s), "x")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid ratio %q", s)
	}
	return v, nil
}
