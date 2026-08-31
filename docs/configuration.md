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

Use `--verbose` or `--json` to see the effective configuration after all layers are applied:

```bash
zipthorn inspect --verbose archive.zip
```

This shows which values came from defaults, files, or flags.
