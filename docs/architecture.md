# Architecture

zipthorn is a single Go binary over a small set of cohesive packages. The
organising rule is that **parsing, policy, and action are separate**: the ZIP
parser never decides what is dangerous, the detector never extracts, and the
extractor never invents a limit.

## Package layout

```text
zipthorn.go              public API — the embeddable surface
cmd/zipthorn/main.go     entry point; wires version info and exits
internal/
  cli/                   argument parsing, output rendering, exit codes
  archive/               ZIP metadata parsing and path analysis
  detector/              feature extraction, risk rules, named policies
  generator/             bounded, deterministic fixture generation
  extractor/             bounded, fail-safe extraction
  benchmark/             extraction performance measurement
  config/                limits, thresholds, file loading, provenance
tests/
  integration/           create → inspect / detect / test flows
  malformed/             hostile and self-contradictory archives
```

Everything under `internal/` is free to change. `zipthorn.go` is the stable
surface: it re-exports the internal types as aliases, so an embedding
application gets the same types the CLI uses without depending on the internal
layout.

## Data flow

```text
                       ┌───────────────┐
      archive file ───▶│ archive.Read  │  central directory only; never extracts
                       └───────┬───────┘
                               │ archive.Info
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
     ┌──────────────┐  ┌───────────────┐  ┌──────────────┐
     │ cli inspect  │  │ detector      │  │ extractor    │
     │ report as-is │  │ Extract→rules │  │ validate→    │
     └──────────────┘  │ →score→verdict│  │ bounded copy │
                       └───────┬───────┘  └──────┬───────┘
                               │                 │
                     Assessment│                 │Result
                               ▼                 ▼
                          REVIEW / REJECT   PASS / LIMIT_REACHED /
                                            TIMEOUT / INVALID_ARCHIVE
```

`config.Config` feeds the detector (as `Thresholds`) and the extractor and
generator (as `Limits`). No package invents its own numbers.

## Layer responsibilities

### `internal/archive`

Reads the central directory through `archive/zip` and reports what the archive
*claims*: sizes, ratios, entry and directory counts, depth, compression methods,
duplicates, nested-archive candidates, and per-entry path issues.

It makes no judgements. A 4GB declared size and a traversal path are both facts
here; whether either is acceptable is the detector's business.

Path analysis (`PathIssues`, `Escapes`) lives here because it is a property of
the name, not of a policy. `Escapes` is the one check an extractor must never
skip.

### `internal/detector`

A three-stage pipeline:

1. **Feature extraction** (`Extract`) reduces `archive.Info` to the scalar
   `Features` the rules operate on, with bounded evidence samples so a hostile
   archive cannot make the report itself enormous.
2. **Rules** each map features and thresholds to a level and a score. Rules are
   independent and individually disableable, which is what named policies use.
3. **Scoring and recommendation** aggregate per-category levels into a capped
   score and a `REVIEW`/`REJECT` verdict.

Named policies (`default`, `strict`, `permissive`, `web`, `ci`) are preset
threshold sets plus a disabled-rule list. A policy supersedes the configured
thresholds outright rather than merging with them — a half-applied security
policy is worse than either policy alone.

### `internal/extractor`

Bounded extraction in two phases:

**Before writing anything**, the whole central directory is validated against
the limits: declared size, file count, depth, archive nesting, and every entry
path. An archive that fails here produces no filesystem output at all.

**While extracting**, the same limits are enforced again as bytes land, because
the declaration cannot be trusted — the point of the pre-check is to reject
cheaply, not to establish truth. A `limitWriter` refuses the write that *would*
cross the byte limit rather than truncating after the fact, and the context is
checked between entries so a timeout stops promptly.

On failure, partial output is removed unless the caller opts out. Refusal is
reported in `Result.Status`, not as an error: a rejected archive is a verdict,
not a malfunction.

### `internal/generator`

Deterministic, bounded fixture generation. A plan is computed from the profile
and spec first, checked against the limits, and only then written — so an
over-budget request writes nothing rather than being cut off mid-archive.

Given the same seed and parameters, output is byte-identical, which is what
makes generated fixtures usable as regression tests.

### `internal/config`

The single home for policy numbers. `Default()` is the only place defaults are
written down.

Configuration resolves lowest-precedence-first: defaults, then
`~/.zipthorn/config.yaml`, then `./.zipthorn.config.yaml`, then CLI flags. A
missing file is not an error; a malformed file or an unknown key is, and it
fails closed rather than falling back to defaults — a security tool that
silently runs on the wrong policy is worse than one that refuses to start.

The parser is hand-rolled over a flat `key: value` subset. The schema is two
maps of scalars, so a real YAML dependency would buy nothing and cost the
project its dependency-free build.

`Resolved` carries the provenance of every field alongside the values, which is
what lets `--verbose` and `--json` report not just the effective policy but
which layer decided each part of it.

### `internal/cli`

Argument parsing, rendering, and exit codes. Commands share a flag set (`--json`,
`--quiet`, `--verbose`), a config loader, and one output helper that renders
either a human report or JSON from the same value.

Two things happen here that the Go `flag` package does not do by default:

- **Argument permutation** — `flag` stops at the first operand, which would
  silently ignore `zipthorn test archive.zip --max-bytes 64MB`. Operands are
  moved after the flags before parsing.
- **Flag provenance** — after parsing, `flag.Visit` reports only the flags the
  user actually typed, so a flag left unset never claims credit for a value that
  came from a config file.

## Design invariants

These are the rules the code is written to hold. Each one is enforced by tests.

**Policy lives in configuration, not in code.** No command, rule, or profile
hardcodes a threshold at its call site. `config.Default()` is the only source of
defaults.

**Detection never extracts.** Everything in `detect` reads the central directory
only, so it is safe to run on fully untrusted input.

**Fail closed.** Generation that would exceed its budget writes nothing.
Extraction that hits a limit stops and cleans up. A malformed config aborts the
command.

**Parsing successfully is not a safety signal.** A well-formed archive can still
declare 4GB of output from 16 stored bytes; the malformed-archive corpus exists
to keep that distinction honest.

**Refusal is a verdict, not a crash.** Exit code 3 and `Result.Status` carry
rejections; error paths are reserved for things that actually went wrong.

**Bounded reporting.** Samples and evidence lists are capped, so an archive with
a million bad paths produces a report of constant size.

## Testing

Tests are black-box: they live in external `_test` packages and exercise the
exported API, never internal implementation.

- **Unit tests** per package cover ratio math, size accounting, each detection
  rule at its threshold boundary, every extraction limit, and generator
  determinism.
- **Integration tests** (`tests/integration`) run the real command flows:
  `create → inspect`, `create → detect`, `create → test`, and every profile.
- **The malformed corpus** (`tests/malformed`) covers truncated archives,
  invalid central directories, path traversal, reserved and control-character
  names, deep nesting, unsupported compression methods, and metadata that
  contradicts the data it describes. Every case must fail safely: no panic, no
  unbounded work.
- **Fuzz targets** (`go test -fuzz=Fuzz`) cover the generator and the extractor.
- **Race** — CI runs the whole suite under `-race` on Linux, macOS, and Windows.
