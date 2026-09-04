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

To load one specific file and skip discovery entirely:

```bash
zipthorn detect upload.zip --config ./ci-policy.yaml
```

To see the effective policy and which layer decided each part of it, add
`--verbose`:

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

The same record rides along in `--json` under a `config` key, with a `sources`
block naming the file or layer behind every field.

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

Output:

```text
zipthorn

Created
  Path:             test.zip
  Profile:          ratio
  Seed:             1

Archive
  Compressed:       486.7 KB
  Declared output:  32 MB
  Expansion:        67.3x
  Files:            1
  Directories:      1
  Max depth:        1
  Archive nesting:  0
```

Generation **fails closed**: if a profile would exceed `--max-output` or
`--max-expansion`, nothing is written and the command exits 3. Passing the same
`--seed` and parameters reproduces a byte-identical archive.

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
  Path:             test.zip
  Compressed:       486.7 KB
  Declared output:  32 MB
  Expansion:        67.3x
  Files:            1
  Directories:      1
  Max depth:        1

Compression
  STORE:            1 entry
  DEFLATE:          1 entry

Notes
  Comment:          22 bytes
```

`inspect` reports what the archive *claims*; it never extracts and never judges.
Use `detect` for the verdict.

Add `--verbose` for a per-entry listing, `--quiet` for a single summary line, or
`--json` for structured output:

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
zipthorn

Archive
  Path:             test.zip
  Compressed:       486.7 KB
  Declared output:  32 MB
  Expansion:        67.3x
  Files:            1
  Max depth:        1

Risk
  Compression:      HIGH
  File count:       LOW
  Nesting:          LOW
  Paths:            LOW

Indicators
  HIGH   HIGH_COMPRESSION_RATIO   archive expands 67.3x against a 50x threshold

Score: 30/100
Recommendation: REJECT
```

A `REJECT` exits with status 3. That is a verdict, not a failure, so it prints no
error line — see [Exit codes](#exit-codes).

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
  --timeout 5
```

`--timeout` is a whole number of seconds; `0` means no timeout.

Example output:

```text
zipthorn

Archive
  Path:             test.zip

Result
  Status:           LIMIT_REACHED
  Elapsed:          38.5µs
  Files processed:  0
  Bytes produced:   0 B
  Limit reached:    bytes
  Reason:           byte limit exceeded: declared size 33554432 exceeds max 8388608
```

Possible statuses:

```text
PASS
LIMIT_REACHED
TIMEOUT
INVALID_ARCHIVE
ERROR
```

The test runner validates the whole central directory against the limits before
writing anything, then enforces them again as bytes land. Partial output is
removed on failure unless `--no-clean` is given.

This makes it useful for testing whether a crawler or archive processor **fails safely instead of exhausting the host system**.

---

## Exit codes

Every command uses the same convention, so `zipthorn` composes in shell pipelines
and CI gates.

| Code | Meaning |
|---|---|
| 0 | Success — archive accepted, or the operation completed |
| 1 | Error — something went wrong (I/O, unreadable config) |
| 2 | Usage — bad flags or arguments |
| 3 | Risk — archive rejected, a limit was reached, or the input was not a valid archive |
| 4 | Unsupported — the requested operation is not available |

Code 3 is a **verdict, not a crash**: it is what a CI gate should key on, and it
is printed without an error line.

```bash
if ! zipthorn detect --policy strict upload.zip --quiet; then
  echo "rejected"
fi
```

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

## Library use

The CLI is a thin shell over an embeddable Go API. The same inspection,
detection, extraction, and generation are importable:

```bash
go get github.com/PeacexF/zipthorn
```

A gate for an upload path — inspect, assess, and only then extract:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/PeacexF/zipthorn"
)

func main() {
	cfg := zipthorn.DefaultConfig()

	info, err := zipthorn.InspectFile("upload.zip")
	if err != nil {
		log.Fatal(err) // unparseable is a rejection, not a retry
	}

	if a := zipthorn.Detect(info, cfg.Thresholds); a.Recommendation == zipthorn.Reject {
		for _, ind := range a.Indicators {
			fmt.Printf("%s: %s\n", ind.ID, ind.Detail)
		}
		return
	}

	res := zipthorn.ExtractFile(context.Background(), "upload.zip", zipthorn.ExtractOptions{
		Limits:      cfg.Limits,
		Sink:        zipthorn.DirSink("./out"),
		CleanOnFail: true,
	})
	fmt.Println(res.Status, res.BytesProduced)
}
```

Detection never extracts, so it is safe to run on untrusted input. `ExtractFile`
reports refusal in `res.Status` rather than as an error, mirroring the CLI.

`Inspect` and `Extract` also take an `io.ReaderAt` directly — for an upload
held in memory, streamed from `multipart.File`, or read from an object store,
there is no need to spill it to a temp file first. `DiscardSink()` extracts
under the same limits without writing any output, which is the right choice
when the only question is "is this safe", not "give me the files".

Named policies, bounded fixture generation, and benchmarking are all reachable
too — see the [package documentation](https://pkg.go.dev/github.com/PeacexF/zipthorn)
and [docs/architecture.md](docs/architecture.md).

---

## License

See [LICENSE](LICENSE).
