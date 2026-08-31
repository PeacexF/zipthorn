package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/PeacexF/zipthorn/internal/config"
)

// loadConfig resolves configuration, honouring the global --config flag. The
// result carries provenance so commands can report where each value came from.
func loadConfig() (*config.Resolved, error) {
	if globalConfigPath != "" {
		res, err := config.ResolveFrom(globalConfigPath)
		if err != nil {
			return nil, fmt.Errorf("loading config from %s: %w", globalConfigPath, err)
		}
		return res, nil
	}

	res, err := config.Resolve()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return res, nil
}

// markFlagOverrides records that an explicitly-set flag won over the file
// layers. flag.Visit reports only flags the user actually typed, so a flag left
// unset never claims credit for a configured value.
func markFlagOverrides(fs *flag.FlagSet, res *config.Resolved, keys map[string]string) {
	fs.Visit(func(f *flag.Flag) {
		if key, ok := keys[f.Name]; ok {
			res.MarkFlag(key)
		}
	})
}

// limitFlagKeys maps a command's limit flags onto config keys. Commands share
// the config key names but spell the byte and ratio flags differently.
func limitFlagKeys(bytes, ratio string) map[string]string {
	return map[string]string{
		bytes:         "limits.max_output_bytes",
		ratio:         "limits.max_expansion_ratio",
		"max-files":   "limits.max_files",
		"max-depth":   "limits.max_depth",
		"max-nesting": "limits.max_nesting",
	}
}

var thresholdFlagKeys = map[string]string{
	"threshold-ratio":   "thresholds.expansion_ratio",
	"threshold-size":    "thresholds.declared_size",
	"threshold-files":   "thresholds.file_count",
	"threshold-depth":   "thresholds.depth",
	"threshold-nesting": "thresholds.nesting",
}

// writeConfig renders the effective configuration and its provenance. It is the
// --verbose companion to the config block carried in --json output.
func writeConfig(w io.Writer, res *config.Resolved) {
	section(w, "Configuration")

	files := res.Files()
	if len(files) == 0 {
		field(w, "Files", "none (built-in defaults)")
	}
	for i, p := range files {
		label := "Files"
		if i > 0 {
			label = ""
		}
		field(w, label, p)
	}

	fmt.Fprintln(w)
	for _, f := range res.Fields() {
		fmt.Fprintf(w, "  %-28s %-12s %s\n", f.Key, f.Value, f.Origin)
	}
}

// configEnvelope merges a command's payload with the effective configuration so
// JSON consumers get the result and the policy that produced it in one object.
type configEnvelope struct {
	payload any
	config  *config.Resolved
}

func withConfig(payload any, res *config.Resolved) any {
	return configEnvelope{payload: payload, config: res}
}

func (e configEnvelope) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(e.payload)
	if err != nil {
		return nil, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		// A non-object payload cannot carry a config key; emit it unchanged.
		return raw, nil
	}

	cfg, err := json.Marshal(e.config)
	if err != nil {
		return nil, err
	}
	fields["config"] = cfg

	return json.Marshal(fields)
}
