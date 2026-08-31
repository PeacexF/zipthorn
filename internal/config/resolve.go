package config

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Layer names a configuration source, ordered by increasing precedence.
const (
	LayerDefault = "default"
	LayerGlobal  = "global"
	LayerLocal   = "local"
	LayerFile    = "file" // an explicit --config path, which replaces discovery
	LayerFlag    = "flag"
	LayerPolicy  = "policy" // a named detection policy, which supersedes thresholds
)

// GlobalFileName is the per-user config file, resolved against the home directory.
const GlobalFileName = ".zipthorn/config.yaml"

// LocalFileName is the per-directory config file, resolved against the working directory.
const LocalFileName = ".zipthorn.config.yaml"

// Origin records which layer supplied a field's effective value. Source names
// the layer's instance: a config file's path, or a named policy.
type Origin struct {
	Layer  string `json:"layer"`
	Source string `json:"source,omitempty"`
}

func (o Origin) String() string {
	if o.Source == "" {
		return o.Layer
	}
	return o.Layer + " (" + o.Source + ")"
}

// Field is one configuration key with its effective value and where it came from.
type Field struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Origin Origin `json:"origin"`
}

// Resolved is a Config plus the provenance of every field. It answers not just
// what the effective policy is but which layer decided each part of it.
type Resolved struct {
	Config  Config
	origins map[string]Origin
	files   []string
}

// Keys lists every configuration field in report order. The names match the
// file syntax exactly, so a reported key can be pasted straight into a config.
var Keys = []string{
	"limits.max_output_bytes",
	"limits.max_expansion_ratio",
	"limits.max_files",
	"limits.max_depth",
	"limits.max_nesting",
	"thresholds.expansion_ratio",
	"thresholds.declared_size",
	"thresholds.file_count",
	"thresholds.depth",
	"thresholds.nesting",
}

func newResolved() *Resolved {
	origins := make(map[string]Origin, len(Keys))
	for _, k := range Keys {
		origins[k] = Origin{Layer: LayerDefault}
	}
	return &Resolved{Config: Default(), origins: origins}
}

// Files lists the config files that were read, in the order they were applied.
func (r *Resolved) Files() []string { return append([]string(nil), r.files...) }

// Origin reports which layer supplied key's effective value.
func (r *Resolved) Origin(key string) Origin { return r.origins[key] }

// MarkFlag records that a CLI flag overrode key. Unknown keys are ignored so a
// caller's flag table cannot silently corrupt the report.
func (r *Resolved) MarkFlag(key string) {
	if _, ok := r.origins[key]; ok {
		r.origins[key] = Origin{Layer: LayerFlag}
	}
}

func (r *Resolved) mark(key string, o Origin) {
	if _, ok := r.origins[key]; ok {
		r.origins[key] = o
	}
}

// SetThresholds replaces every threshold at once and credits them all to the
// same source. A named detection policy supersedes the configured thresholds
// rather than merging with them, so its provenance is all-or-nothing.
func (r *Resolved) SetThresholds(t Thresholds, layer, name string) {
	r.Config.Thresholds = t
	for _, k := range Keys {
		if strings.HasPrefix(k, "thresholds.") {
			r.origins[k] = Origin{Layer: layer, Source: name}
		}
	}
}

// Fields renders every field in Keys order, with values spelled the way a
// config file would write them.
func (r *Resolved) Fields() []Field {
	fields := make([]Field, 0, len(Keys))
	for _, k := range Keys {
		fields = append(fields, Field{Key: k, Value: r.value(k), Origin: r.origins[k]})
	}
	return fields
}

// Overridden returns only the fields that some layer changed from the default.
func (r *Resolved) Overridden() []Field {
	var fields []Field
	for _, f := range r.Fields() {
		if f.Origin.Layer != LayerDefault {
			fields = append(fields, f)
		}
	}
	return fields
}

func (r *Resolved) value(key string) string {
	l, t := r.Config.Limits, r.Config.Thresholds
	switch key {
	case "limits.max_output_bytes":
		return FormatSize(l.MaxOutputBytes)
	case "limits.max_expansion_ratio":
		return FormatRatio(l.MaxExpansionRatio)
	case "limits.max_files":
		return strconv.FormatInt(l.MaxFiles, 10)
	case "limits.max_depth":
		return strconv.Itoa(l.MaxDepth)
	case "limits.max_nesting":
		return strconv.Itoa(l.MaxNesting)
	case "thresholds.expansion_ratio":
		return FormatRatio(t.ExpansionRatio)
	case "thresholds.declared_size":
		return FormatSize(t.DeclaredSize)
	case "thresholds.file_count":
		return strconv.FormatInt(t.FileCount, 10)
	case "thresholds.depth":
		return strconv.Itoa(t.Depth)
	case "thresholds.nesting":
		return strconv.Itoa(t.Nesting)
	}
	return ""
}

// MarshalJSON emits the effective values alongside a sources block, so an
// automated consumer can see both the policy and who set it.
func (r *Resolved) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Limits     Limits     `json:"limits"`
		Thresholds Thresholds `json:"thresholds"`
		Sources    struct {
			Files  []string `json:"files"`
			Fields []Field  `json:"fields"`
		} `json:"sources"`
	}{
		Limits:     r.Config.Limits,
		Thresholds: r.Config.Thresholds,
		Sources: struct {
			Files  []string `json:"files"`
			Fields []Field  `json:"fields"`
		}{Files: r.Files(), Fields: r.Fields()},
	})
}

// FormatSize spells a byte count the way the config parser reads it back.
func FormatSize(n int64) string {
	units := []struct {
		mult int64
		name string
	}{{GB, "GB"}, {MB, "MB"}, {KB, "KB"}}
	for _, u := range units {
		if n >= u.mult && n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.name
		}
	}
	return strconv.FormatInt(n, 10)
}

// FormatRatio spells a ratio the way the config parser reads it back.
func FormatRatio(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	return s + "x"
}
