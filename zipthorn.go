// Package zipthorn is the embeddable API for the zipthorn archive
// security-testing toolkit: inspect a ZIP's metadata without extracting it,
// assess its risk, extract it under hard resource limits, and generate bounded
// pathological fixtures to test other extractors with.
//
// The command-line tool is a thin shell over exactly these calls, so anything
// the CLI reports is reachable from Go.
//
// A typical gate in an upload path inspects, assesses, and only then extracts:
//
//	info, err := zipthorn.Inspect("upload.zip")
//	if err != nil {
//		return err // unparseable is a rejection, not a retry
//	}
//	if a := zipthorn.Detect(info, zipthorn.DefaultConfig().Thresholds); a.Recommendation == zipthorn.Reject {
//		return fmt.Errorf("rejected: %v", a.Indicators)
//	}
//	res := zipthorn.Extract(ctx, "upload.zip", zipthorn.ExtractOptions{
//		Limits:      zipthorn.DefaultConfig().Limits,
//		DestDir:     dest,
//		CleanOnFail: true,
//	})
//
// Detection never extracts, so it is safe to run on untrusted input. Extraction
// validates the whole central directory against the limits before writing
// anything, then enforces them again as bytes land.
package zipthorn

import (
	"context"
	"io"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/benchmark"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/detector"
	"github.com/PeacexF/zipthorn/internal/extractor"
	"github.com/PeacexF/zipthorn/internal/generator"
)

// Configuration.
type (
	// Config is the resource limits and detection thresholds that govern every
	// operation. Policy lives here, never at a call site.
	Config = config.Config

	// Limits bound any operation that generates or extracts archive data.
	Limits = config.Limits

	// Thresholds are the detection engine's decision boundaries: the point at
	// or above which a characteristic is treated as HIGH risk.
	Thresholds = config.Thresholds
)

// Byte-size constants, matching the binary units the config files accept.
const (
	KB = config.KB
	MB = config.MB
	GB = config.GB
)

// DefaultConfig returns the built-in limits and thresholds. It is the only
// place defaults are defined.
func DefaultConfig() Config { return config.Default() }

// LoadConfig reads ~/.zipthorn/config.yaml then ./.zipthorn.config.yaml over
// the defaults, each layer overriding the last. A missing file is not an error;
// a malformed file or an unknown key is.
func LoadConfig() (Config, error) { return config.Load() }

// LoadConfigFile reads exactly one config file over the defaults, skipping
// discovery. The file must exist.
func LoadConfigFile(path string) (Config, error) { return config.LoadFrom(path) }

// Inspection.
type (
	// Info is the whole-archive summary produced without extracting anything.
	Info = archive.Info

	// Entry is one central-directory record.
	Entry = archive.Entry

	// MethodCount summarizes how many entries use one compression method.
	MethodCount = archive.MethodCount

	// Duplicate is a name claimed by more than one entry.
	Duplicate = archive.Duplicate

	// PathIssue names one suspicious property of an entry name.
	PathIssue = archive.PathIssue
)

// ErrInvalidArchive reports input that could not be parsed as a ZIP archive.
var ErrInvalidArchive = archive.ErrInvalidArchive

// Inspect reads an archive's central directory and reports its metadata. It
// never extracts, so it is safe on untrusted input.
func Inspect(path string) (*Info, error) { return archive.Open(path) }

// InspectReader is Inspect over an already-open reader of known size.
func InspectReader(r io.ReaderAt, size int64) (*Info, error) { return archive.Read(r, size) }

// PathIssues reports everything suspicious about an entry name.
func PathIssues(name string) []PathIssue { return archive.PathIssues(name) }

// Escapes reports whether an entry name would write outside the destination
// directory. It is the check an extractor must not skip.
func Escapes(name string) bool { return archive.Escapes(name) }

// SupportedMethod reports whether zipthorn can decompress a ZIP method.
func SupportedMethod(method uint16) bool { return archive.Supported(method) }

// Detection.
type (
	// Assessment is the detector's verdict on an archive.
	Assessment = detector.Assessment

	// Indicator is one triggered rule.
	Indicator = detector.Indicator

	// Category is one facet of the archive's risk.
	Category = detector.Category

	// Features are the archive properties the rules operate on.
	Features = detector.Features

	// PathFinding is one entry name the path rules objected to.
	PathFinding = detector.PathFinding

	// Level is a risk level: LevelLow, LevelMedium, or LevelHigh.
	Level = detector.Level

	// Policy is a named detection profile: preset thresholds plus disabled rules.
	Policy = detector.Policy
)

// Risk levels.
const (
	LevelLow    = detector.LevelLow
	LevelMedium = detector.LevelMedium
	LevelHigh   = detector.LevelHigh
)

// Recommendations.
const (
	Accept = detector.Accept
	Review = detector.Review
	Reject = detector.Reject
)

// Indicator IDs, stable across releases so callers can match on them.
const (
	HighCompressionRatio  = detector.HighCompressionRatio
	ExcessiveDeclaredSize = detector.ExcessiveDeclaredSize
	ExcessiveFileCount    = detector.ExcessiveFileCount
	DeepNesting           = detector.DeepNesting
	ArchiveRecursion      = detector.ArchiveRecursion
	PathTraversal         = detector.PathTraversal
	SuspiciousPath        = detector.SuspiciousPath
	DuplicateEntries      = detector.DuplicateEntries
)

// Named detection policies.
const (
	PolicyDefault    = detector.PolicyDefault
	PolicyStrict     = detector.PolicyStrict
	PolicyPermissive = detector.PolicyPermissive
	PolicyWeb        = detector.PolicyWeb
	PolicyCI         = detector.PolicyCI
)

// Detect assesses an archive's risk from its metadata alone.
func Detect(info *Info, t Thresholds) Assessment { return detector.Assess(info, t) }

// DetectWithPolicy assesses an archive using a named policy's thresholds and
// rule set, which supersede any configured thresholds.
func DetectWithPolicy(info *Info, policy string) (Assessment, error) {
	return detector.AssessWithPolicy(info, policy)
}

// Policies lists the available named policies.
func Policies() []string { return detector.ListPolicies() }

// GetPolicy returns a named policy's thresholds and disabled rules.
func GetPolicy(name string) (Policy, error) { return detector.GetPolicy(name) }

// Extraction.
type (
	// ExtractOptions configures a bounded extraction.
	ExtractOptions = extractor.Options

	// ExtractResult reports what a bounded extraction did and why it stopped.
	ExtractResult = extractor.Result

	// Status is an extraction outcome.
	Status = extractor.Status
)

// Extraction statuses.
const (
	StatusPass         = extractor.StatusPass
	StatusLimitReached = extractor.StatusLimitReached
	StatusTimeout      = extractor.StatusTimeout
	StatusInvalid      = extractor.StatusInvalid
	StatusError        = extractor.StatusError
)

// Limit errors, for callers that want to distinguish which bound was hit.
var (
	ErrUnsafePath    = extractor.ErrUnsafePath
	ErrByteLimitHit  = extractor.ErrByteLimitHit
	ErrRatioLimitHit = extractor.ErrRatioLimitHit
	ErrFileLimitHit  = extractor.ErrFileLimitHit
	ErrDepthLimitHit = extractor.ErrDepthLimitHit
	ErrNestingHit    = extractor.ErrNestingHit
)

// Extract unpacks an archive under hard limits, validating the central
// directory before writing anything and stopping the moment a limit is reached.
// Cancel ctx (or give it a deadline) to bound the wall-clock cost.
//
// Extract reports failure in the returned result's Status rather than as an
// error: a refused archive is a verdict, not a malfunction.
func Extract(ctx context.Context, archivePath string, opts ExtractOptions) ExtractResult {
	return extractor.Extract(ctx, archivePath, opts)
}

// Generation.
type (
	// Spec describes the fixture to generate.
	Spec = generator.Spec

	// GenerateResult describes the fixture that was generated.
	GenerateResult = generator.Result
)

// Fixture profiles.
const (
	ProfileRatio     = generator.ProfileRatio
	ProfileFileCount = generator.ProfileFileCount
	ProfileNested    = generator.ProfileNested
	ProfileDepth     = generator.ProfileDepth
	ProfileMetadata  = generator.ProfileMetadata
	ProfileMixed     = generator.ProfileMixed
	ProfileFuzz      = generator.ProfileFuzz
)

// LevelDefault selects the default deflate level.
const LevelDefault = generator.LevelDefault

// Generation errors.
var (
	ErrUnknownProfile = generator.ErrUnknownProfile
	ErrLimitExceeded  = generator.ErrLimitExceeded
)

// Profiles lists the available fixture profiles.
func Profiles() []string { return generator.Profiles() }

// Generate writes a bounded pathological fixture to w. Generation fails closed:
// if the spec would exceed Spec.Limits, nothing is written and the error wraps
// ErrLimitExceeded. A non-zero Spec.Seed makes the output byte-identical across
// runs.
func Generate(w io.Writer, s Spec) (*GenerateResult, error) { return generator.Generate(w, s) }

// Benchmarking.
type (
	// Metrics captures one extraction's performance characteristics.
	Metrics = benchmark.Metrics

	// AggregateMetrics holds statistics across repeated runs.
	AggregateMetrics = benchmark.AggregateMetrics
)

// Benchmark extracts an archive once under limits and reports its performance.
func Benchmark(ctx context.Context, archivePath string, limits Limits, destDir string, cleanOnFailure bool) (*Metrics, error) {
	return benchmark.Run(ctx, archivePath, limits, destDir, cleanOnFailure)
}

// BenchmarkRuns repeats Benchmark and returns the per-run metrics alongside
// aggregate statistics.
func BenchmarkRuns(ctx context.Context, archivePath string, limits Limits, destDir string, cleanOnFailure bool, runs int) ([]*Metrics, *AggregateMetrics, error) {
	return benchmark.RunMultiple(ctx, archivePath, limits, destDir, cleanOnFailure, runs)
}
