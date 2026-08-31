# zipthorn

**ZIP archive security research and defensive testing toolkit written in Go.**

zipthorn is a CLI for generating, analyzing, detecting, and safely testing pathological ZIP archives.

The goal is to help developers and security researchers answer a simple question:

> **What happens when my system receives a malicious or pathological archive?**

It is designed for testing crawlers, archive extractors, upload services, malware scanners, document-processing pipelines, and other software that handles untrusted ZIP files.

> [!WARNING]
> ZIP archives can consume significant CPU, memory, storage, and I/O resources when processed by vulnerable software. Only test systems you own or have explicit authorization to test.

See [DISCLAIMER.md](DISCLAIMER.md) for the full disclaimer.

---

## Features

* Generate controlled pathological ZIP fixtures
* Analyze ZIP archives without extracting them
* Detect suspicious archive characteristics
* Safely test archive extraction with resource limits
* Measure compression and extraction behavior
* Generate reproducible test fixtures
* JSON output for automation and CI
* Pure Go implementation
* Standard-library-first architecture
* No external services required

---

## Installation

### From source

```bash
git clone https://github.com/PeacexF/zipthorn.git
cd zipthorn

go build -o zipthorn ./cmd/zipthorn
```

Or install directly:

```bash
go install github.com/PeacexF/zipthorn/cmd/zipthorn@latest
```

---

## Usage

```text
zipthorn <command> [options]
```

Available commands:

```text
create       Generate a controlled test archive
inspect      Analyze an archive
detect       Assess archive risk
test         Safely test archive extraction
policy       Show detection policy details
benchmark    Measure archive extraction performance
fuzz         Generate fuzz fixtures for testing
```

Run:

```bash
zipthorn --help
```

for the complete CLI reference.

---

## Configuration

zipthorn supports configuration files to set default resource limits and detection thresholds.

Configuration is resolved in order of precedence:

1. Built-in defaults
2. `~/.zipthorn/config.yaml` (global, per-user)
3. `./.zipthorn.config.yaml` (local, per-directory)
4. CLI flags (highest priority)

Example configuration:

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

Both files are optional. Missing files use built-in defaults. Malformed files or unknown keys fail immediately.

See [docs/configuration.md](docs/configuration.md) for the complete configuration reference.

---

## Create

Generate a controlled pathological archive:

```bash
zipthorn create --profile ratio --output test.zip
```

Available profiles include:

```text
ratio
file-count
nested
depth
metadata
mixed
fuzz
```

Generation is bounded by configurable safety limits.

Example:

```bash
zipthorn create \
  --profile ratio \
  --output test.zip \
  --max-output 10MB \
  --max-expansion 100x
```

The generator is intended to produce **test fixtures**, not uncontrolled payloads.

---

## Inspect

Analyze an archive without extracting it:

```bash
zipthorn inspect test.zip
```

Example output:

```text
zipthorn

Archive
  Compressed:       8.2 MB
  Declared output:  512 MB
  Expansion:        62.4x
  Files:            10,000
  Max depth:        8

Compression
  DEFLATE:          10,000 entries

Risk
  Compression:      HIGH
  File count:       MEDIUM
  Nesting:          LOW
  Paths:             LOW

Recommendation: REVIEW
```

JSON output:

```bash
zipthorn inspect test.zip --json
```

---

## Detect

Run the archive through the detection engine:

```bash
zipthorn detect test.zip
```

The detector evaluates characteristics such as:

* Compression ratio
* Declared uncompressed size
* File count
* Directory depth
* Archive nesting
* Path traversal
* Duplicate entries
* Suspicious metadata

Example:

```text
Risk assessment: HIGH

Triggered rules:
  HIGH_COMPRESSION_RATIO
  EXCESSIVE_FILE_COUNT

Recommendation: REJECT
```

Detection thresholds can be configured for different environments.

### Detection Policies

zipthorn includes named detection policies with pre-configured thresholds for common use cases:

```bash
# List available policies
zipthorn policy --list

# Inspect a specific policy
zipthorn policy strict
```

Available policies:

* **default** - Balanced detection suitable for general use
* **strict** - Conservative thresholds for untrusted sources
* **permissive** - Relaxed thresholds for known-safe sources
* **web** - Tuned for user-uploaded content in web applications
* **ci** - Suitable for CI/CD artifact inspection

Use a policy with the detect command:

```bash
# Use strict policy for untrusted uploads
zipthorn detect --policy strict upload.zip

# Use permissive policy for internal artifacts
zipthorn detect --policy permissive build-artifact.zip
```

Policies control detection thresholds and can disable specific rules. For example, the `ci` policy disables duplicate entry detection since build artifacts often contain duplicates.

---

## Safe Testing

`test` is intended to exercise archive-processing behavior while enforcing explicit limits.

```bash
zipthorn test test.zip \
  --max-bytes 256MB \
  --max-files 10000 \
  --max-depth 10 \
  --timeout 5s
```

Possible results:

```text
PASS
LIMIT_REACHED
TIMEOUT
INVALID_ARCHIVE
ERROR
```

The test runner tracks resource consumption and stops processing when configured limits are reached.

This makes it useful for testing whether a crawler or archive processor **fails safely instead of exhausting the host system**.

---

## Detection Model

zipthorn separates archive parsing from security policy.

Conceptually:

```text
             ZIP Archive
                  │
                  ▼
           Metadata Scanner
                  │
                  ▼
          Feature Extraction
                  │
                  ▼
            Risk Rules
                  │
                  ▼
          Risk Assessment
                  │
                  ▼
           Recommendation
```

This allows detection thresholds to be adapted to the environment.

For example, a malware scanner and a web crawler may have very different acceptable limits.

---

## Defensive Use Cases

zipthorn can be used to test:

### Web Crawlers

Verify that crawlers do not recursively extract dangerous archives or exhaust worker resources.

### Upload Services

Test whether uploaded archives are rejected when they exceed configured limits.

### Document Processing

Validate resource limits around systems that automatically unpack user-provided documents.

### Malware Scanners

Create reproducible pathological fixtures for scanner testing.

### Archive Libraries

Compare how different ZIP implementations handle suspicious archives.

### CI Security Tests

Keep pathological archives as regression fixtures and verify that resource limits remain enforced.


---

## License

See [LICENSE](LICENSE).
