# Configuration

zipthorn's behavior is controlled by resource limits and detection thresholds. These can be configured through files or CLI flags.

## Configuration Precedence

Configuration is resolved in the following order, with each layer overriding the previous:

1. **Built-in defaults** — defined in code
2. **`~/.zipthorn/config.yaml`** — global, per-user configuration
3. **`./.zipthorn.config.yaml`** — local, per-directory configuration
4. **CLI flags** — highest priority, override all files

Both files are optional. A missing file is not an error. A malformed file or unknown key fails immediately with an error message.

## File Format

Configuration files use a simple YAML subset with two sections: `limits` and `thresholds`.

```yaml
limits:
  max_output_bytes: 256MB
  max_expansion_ratio: 100x
  max_files: 10000
  max_depth: 32
  max_nesting: 4

thresholds:
  expansion_ratio: 50x
  declared_size: 1GB
  file_count: 10000
  depth: 16
  nesting: 2
```

### Limits

Limits bound any operation that generates or extracts archive data. When a limit is exceeded, the operation stops immediately.

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `max_output_bytes` | size | Maximum bytes to extract or generate | `256MB` |
| `max_expansion_ratio` | ratio | Maximum expansion (declared / compressed) | `100x` |
| `max_files` | int | Maximum number of files to process | `10000` |
| `max_depth` | int | Maximum directory nesting depth | `32` |
| `max_nesting` | int | Maximum archive-within-archive levels | `4` |

### Thresholds

Thresholds are the detection engine's decision boundaries. Each value is the point at or above which a characteristic is treated as HIGH risk.

| Key | Type | Description | Default |
|-----|------|-------------|---------|
| `expansion_ratio` | ratio | Expansion ratio treated as HIGH risk | `50x` |
| `declared_size` | size | Declared output size treated as HIGH risk | `1GB` |
| `file_count` | int | File count treated as HIGH risk | `10000` |
| `depth` | int | Directory depth treated as HIGH risk | `16` |
| `nesting` | int | Nested archive count treated as HIGH risk | `2` |

### Size Format

Sizes accept the following units (all are binary, so `KB` = 1024 bytes):

- `B` — bytes (default if no unit)
- `K`, `KB`, `KiB` — kilobytes (1024 bytes)
- `M`, `MB`, `MiB` — megabytes (1024 KB)
- `G`, `GB`, `GiB` — gigabytes (1024 MB)

Fractional values are supported: `1.5MB`, `0.5GB`

Examples: `512`, `8KB`, `1.5MB`, `2GiB`

### Ratio Format

Ratios can be written as:

- Plain number: `100`
- With suffix: `100x`

Fractional values are supported: `1.5x`, `75.5`

## File Locations

### Global Configuration

`~/.zipthorn/config.yaml`

Per-user settings that apply to all zipthorn invocations unless overridden by a local config or CLI flags.

### Local Configuration

`./.zipthorn.config.yaml`

Project-specific settings. Place this in your project root to define limits and thresholds for that project.

This is useful for CI pipelines or projects that need stricter/looser limits than the global defaults.

## Overriding with CLI Flags

Every config field has a corresponding CLI flag. Flags always take precedence over file configuration.

### Limits Flags

```bash
zipthorn test --max-bytes 128MB \
              --max-ratio 50x \
              --max-files 5000 \
              --max-depth 16 \
              --max-nesting 2 \
              archive.zip
```

### Thresholds Flags

```bash
zipthorn detect --threshold-ratio 75x \
                --threshold-size 2GB \
                --threshold-files 20000 \
                --threshold-depth 32 \
                --threshold-nesting 4 \
                archive.zip
```

## Custom Configuration File

Use `--config <path>` to load a specific configuration file and skip the standard discovery:

```bash
zipthorn test --config ./custom.yaml archive.zip
```

This is useful for testing multiple configurations or managing different security profiles.

## Examples

### Strict Security Profile

For high-security environments:

```yaml
limits:
  max_output_bytes: 64MB
  max_expansion_ratio: 10x
  max_files: 1000
  max_depth: 8
  max_nesting: 1

thresholds:
  expansion_ratio: 5x
  declared_size: 32MB
  file_count: 500
  depth: 4
  nesting: 0
```

### Permissive Development Profile

For local development or testing:

```yaml
limits:
  max_output_bytes: 1GB
  max_expansion_ratio: 1000x
  max_files: 100000
  max_depth: 128
  max_nesting: 10

thresholds:
  expansion_ratio: 500x
  declared_size: 10GB
  file_count: 50000
  depth: 64
  nesting: 5
```

### CI Pipeline Profile

For continuous integration:

```yaml
limits:
  max_output_bytes: 128MB
  max_expansion_ratio: 50x
  max_files: 5000
  max_depth: 16
  max_nesting: 2

thresholds:
  expansion_ratio: 25x
  declared_size: 256MB
  file_count: 2500
  depth: 8
  nesting: 1
```

## Validation

Configuration files are validated on load:

- Unknown sections trigger an error
- Unknown keys trigger an error
- Invalid values (negative numbers, malformed sizes/ratios) trigger an error
- Comments (lines starting with `#`) are ignored
- Empty lines are ignored

This fail-closed approach ensures typos and mistakes are caught immediately rather than silently falling back to defaults.

## Viewing Effective Configuration

The commands that consume configuration — `create`, `detect`, `test`, and
`benchmark` — can report the values they resolved and which layer supplied each
one. (`inspect` reads no policy, so it has no configuration to report.)

With `--verbose`:

```bash
zipthorn detect --verbose --threshold-depth 4 archive.zip
```

```text
Configuration
  Files:            .zipthorn.config.yaml

  limits.max_output_bytes      256MB        default
  limits.max_expansion_ratio   100x         default
  limits.max_files             500          local (.zipthorn.config.yaml)
  limits.max_depth             32           default
  limits.max_nesting           4            default
  thresholds.expansion_ratio   20x          local (.zipthorn.config.yaml)
  thresholds.declared_size     1GB          default
  thresholds.file_count        10000        default
  thresholds.depth             4            flag
  thresholds.nesting           2            default
```

`Files` lists the config files that were actually read, in the order they were
applied. Each field then names its winning layer:

| Layer | Meaning |
|-------|---------|
| `default` | No file or flag touched this field; it holds the built-in default |
| `global` | Set by `~/.zipthorn/config.yaml` |
| `local` | Set by `./.zipthorn.config.yaml` |
| `file` | Set by the file named in `--config` |
| `flag` | Set by a CLI flag the user typed |
| `policy` | Set by a named `--policy`, which supersedes the whole `thresholds` section |

A flag left unset never appears as `flag`, so the report distinguishes a value
you configured from one you merely accepted.

The rendered values use the same spellings the config file accepts, so any line
of the report can be pasted back into a config file.

### In JSON

`--json` carries the same record under a `config` key:

```bash
zipthorn detect --json archive.zip
```

```json
{
  "recommendation": "REJECT",
  "config": {
    "limits": { "max_files": 500, "...": "..." },
    "thresholds": { "depth": 4, "...": "..." },
    "sources": {
      "files": [".zipthorn.config.yaml"],
      "fields": [
        {
          "key": "thresholds.depth",
          "value": "4",
          "origin": { "layer": "flag" }
        },
        {
          "key": "limits.max_files",
          "value": "500",
          "origin": { "layer": "local", "source": ".zipthorn.config.yaml" }
        }
      ]
    }
  }
}
```

`sources.fields` always lists every field, so a CI job can assert on the whole
effective policy rather than only the parts that were overridden.
