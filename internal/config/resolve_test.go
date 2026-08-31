package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/config"
)

func writeConfigFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func originOf(t *testing.T, r *config.Resolved, key string) config.Origin {
	t.Helper()
	for _, f := range r.Fields() {
		if f.Key == key {
			return f.Origin
		}
	}
	t.Fatalf("no field %q in report", key)
	return config.Origin{}
}

func TestResolveDefaultsCarryDefaultOrigin(t *testing.T) {
	r, err := config.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, f := range r.Fields() {
		if f.Value == "" {
			t.Errorf("%s has no rendered value", f.Key)
		}
	}
	if got := len(r.Fields()); got != len(config.Keys) {
		t.Errorf("Fields() = %d entries, want %d", got, len(config.Keys))
	}
}

func TestResolveFromRecordsFileOrigin(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config.yaml",
		"limits:\n  max_files: 5000\nthresholds:\n  depth: 4\n")

	r, err := config.ResolveFrom(path)
	if err != nil {
		t.Fatalf("ResolveFrom: %v", err)
	}

	if o := originOf(t, r, "limits.max_files"); o.Layer != config.LayerFile || o.Source != path {
		t.Errorf("max_files origin = %+v, want file layer from %s", o, path)
	}
	if o := originOf(t, r, "thresholds.depth"); o.Layer != config.LayerFile {
		t.Errorf("depth origin = %+v, want file layer", o)
	}
	// A key the file never mentions stays attributed to the built-in defaults.
	if o := originOf(t, r, "limits.max_depth"); o.Layer != config.LayerDefault {
		t.Errorf("max_depth origin = %+v, want default layer", o)
	}

	if files := r.Files(); len(files) != 1 || files[0] != path {
		t.Errorf("Files() = %v, want [%s]", files, path)
	}
}

func TestResolveFromMissingFileIsAnError(t *testing.T) {
	_, err := config.ResolveFrom(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("ResolveFrom on a missing file should error")
	}
}

func TestOverriddenListsOnlyChangedFields(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config.yaml", "limits:\n  max_files: 77\n")

	r, err := config.ResolveFrom(path)
	if err != nil {
		t.Fatalf("ResolveFrom: %v", err)
	}

	over := r.Overridden()
	if len(over) != 1 {
		t.Fatalf("Overridden() = %d fields, want 1: %+v", len(over), over)
	}
	if over[0].Key != "limits.max_files" || over[0].Value != "77" {
		t.Errorf("Overridden()[0] = %+v, want limits.max_files=77", over[0])
	}
}

func TestMarkFlagWinsOverFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config.yaml", "limits:\n  max_files: 5000\n")

	r, err := config.ResolveFrom(path)
	if err != nil {
		t.Fatalf("ResolveFrom: %v", err)
	}
	if o := originOf(t, r, "limits.max_files"); o.Layer != config.LayerFile {
		t.Fatalf("precondition: max_files origin = %+v", o)
	}

	r.MarkFlag("limits.max_files")
	if o := originOf(t, r, "limits.max_files"); o.Layer != config.LayerFlag {
		t.Errorf("after MarkFlag, origin = %+v, want flag layer", o)
	}

	// An unknown key must not add a phantom field to the report.
	r.MarkFlag("limits.nonsense")
	if got := len(r.Fields()); got != len(config.Keys) {
		t.Errorf("Fields() = %d entries after unknown MarkFlag, want %d", got, len(config.Keys))
	}
}

func TestSetThresholdsReplacesWholeSection(t *testing.T) {
	r, err := config.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	r.SetThresholds(config.Thresholds{
		ExpansionRatio: 20, DeclaredSize: 100 * config.MB,
		FileCount: 1000, Depth: 8, Nesting: 1,
	}, config.LayerPolicy, "strict")

	for _, f := range r.Fields() {
		want := config.LayerDefault
		if strings.HasPrefix(f.Key, "thresholds.") {
			want = config.LayerPolicy
		}
		if f.Origin.Layer != want {
			t.Errorf("%s origin layer = %q, want %q", f.Key, f.Origin.Layer, want)
		}
	}
	if r.Config.Thresholds.FileCount != 1000 {
		t.Errorf("file_count = %d, want 1000", r.Config.Thresholds.FileCount)
	}
}

func TestResolvedJSONCarriesValuesAndSources(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config.yaml", "limits:\n  max_output_bytes: 8MB\n")

	r, err := config.ResolveFrom(path)
	if err != nil {
		t.Fatalf("ResolveFrom: %v", err)
	}

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got struct {
		Limits  config.Limits `json:"limits"`
		Sources struct {
			Files  []string       `json:"files"`
			Fields []config.Field `json:"fields"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Limits.MaxOutputBytes != 8*config.MB {
		t.Errorf("max_output_bytes = %d, want %d", got.Limits.MaxOutputBytes, 8*config.MB)
	}
	if len(got.Sources.Files) != 1 || got.Sources.Files[0] != path {
		t.Errorf("sources.files = %v, want [%s]", got.Sources.Files, path)
	}
	if len(got.Sources.Fields) != len(config.Keys) {
		t.Errorf("sources.fields = %d, want %d", len(got.Sources.Fields), len(config.Keys))
	}
}

// Rendered values must round-trip: what a report prints has to be something a
// config file can say back.
func TestFieldValuesReparse(t *testing.T) {
	dir := t.TempDir()
	r, err := config.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var body strings.Builder
	section := ""
	for _, f := range r.Fields() {
		s, name, _ := strings.Cut(f.Key, ".")
		if s != section {
			body.WriteString(s + ":\n")
			section = s
		}
		body.WriteString("  " + name + ": " + f.Value + "\n")
	}

	path := writeConfigFile(t, dir, "roundtrip.yaml", body.String())
	back, err := config.LoadFrom(path)
	if err != nil {
		t.Fatalf("reparse rendered values: %v\n%s", err, body.String())
	}
	if back != config.Default() {
		t.Errorf("round-trip changed the config:\ngot  %+v\nwant %+v", back, config.Default())
	}
}
