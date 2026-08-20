# zipbomb

**ZIP archive security research and defensive testing toolkit written in Go.**

zipbomb is a CLI for generating, analyzing, detecting, and safely testing pathological ZIP archives.

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
git clone https://github.com/PeacexF/zipbomb.git
cd zipbomb

go build -o zipbomb ./cmd/zipbomb
```

Or install directly:

```bash
go install github.com/PeacexF/zipbomb/cmd/zipbomb@latest
```

---

## Usage

```text
zipbomb <command> [options]
```

Available commands:

```text
create       Generate a controlled test archive
inspect      Analyze an archive
detect       Assess archive risk
test         Safely test archive extraction
benchmark    Benchmark archive processing
fuzz         Generate varied pathological fixtures
```

Run:

```bash
zipbomb --help
```

for the complete CLI reference.

---

## Create

Generate a controlled pathological archive:

```bash
zipbomb create --profile ratio --output test.zip
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
zipbomb create \
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
zipbomb inspect test.zip
```

Example output:

```text
zipbomb

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
zipbomb inspect test.zip --json
```

---

## Detect

Run the archive through the detection engine:

```bash
zipbomb detect test.zip
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

---

## Safe Testing

`test` is intended to exercise archive-processing behavior while enforcing explicit limits.

```bash
zipbomb test test.zip \
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

## Benchmarking

Measure archive-processing behavior:

```bash
zipbomb benchmark test.zip
```

Metrics can include:

* Wall-clock time
* CPU time
* Extraction throughput
* Files per second
* Bytes processed
* Compression ratio
* Memory usage
* Allocations

JSON output makes benchmark results suitable for CI and regression testing.

---

## Fuzzing

Generate varied pathological fixtures:

```bash
zipbomb fuzz --output ./fixtures
```

The fuzzing engine varies archive characteristics such as:

* File counts
* File sizes
* Compression ratios
* Directory depth
* Nesting
* Names
* Metadata
* Entry ordering

A deterministic seed can be used to reproduce a particular fixture.

---

## Detection Model

zipbomb separates archive parsing from security policy.

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

zipbomb can be used to test:

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

## Architecture

zipbomb is intentionally small and written entirely in Go.

```text
zipbomb/
├── cmd/
│   └── zipbomb/
│       └── main.go
├── internal/
│   ├── archive/
│   ├── generator/
│   ├── detector/
│   ├── extractor/
│   ├── benchmark/
│   └── config/
├── profiles/
├── testdata/
├── tests/
├── README.md
├── PLAN.md
├── DISCLAIMER.md
├── LICENSE
├── go.mod
└── go.sum
```

The implementation prefers the Go standard library, particularly:

```text
archive/zip
compress/flate
io
os
path/filepath
encoding/json
context
time
runtime
testing
```

---

## Development

Run tests:

```bash
go test ./...
```

Run the race detector:

```bash
go test -race ./...
```

Run static analysis:

```bash
go vet ./...
```

Build:

```bash
go build ./cmd/zipbomb
```

Run fuzz tests:

```bash
go test -fuzz=Fuzz ./...
```

---

## Roadmap

### MVP

* [ ] CLI foundation
* [ ] `create`
* [ ] `inspect`
* [ ] `detect`
* [ ] `test`
* [ ] Compression-ratio analysis
* [ ] File-count analysis
* [ ] Path validation
* [ ] Resource limits
* [ ] JSON output
* [ ] Unit tests
* [ ] Integration tests

### Future

* [ ] `benchmark`
* [ ] `fuzz`
* [ ] More archive-structure heuristics
* [ ] Configurable detection policies
* [ ] Extended malformed-archive corpus
* [ ] Cross-platform release binaries
* [ ] CI benchmark regression testing
* [ ] Library API for embedding zipbomb functionality

See [PLAN.md](PLAN.md) for the detailed development plan.

---

## Security

If you discover a vulnerability in zipbomb itself, please report it responsibly.

When using zipbomb to test third-party software, ensure that you have explicit authorization before performing resource-exhaustion testing.

For more information, see [DISCLAIMER.md](DISCLAIMER.md).

---

## License

See [LICENSE](LICENSE).
