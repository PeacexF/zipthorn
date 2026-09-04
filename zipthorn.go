// Package zipthorn is the embeddable API for the zipthorn archive
// security-testing toolkit: inspect a ZIP's metadata without extracting it,
// assess its risk, extract it under hard resource limits, build one of your
// own under the same bounds with Writer, and generate bounded pathological
// fixtures to test other extractors with.
//
// The command-line tool is a thin shell over exactly these calls, so anything
// the CLI reports is reachable from Go.
//
// A gate for an upload path — inspect, assess, and extract under policy, all
// in one call and one pass over the archive:
//
//	opts := zipthorn.DefaultGuardOptions()
//	opts.Sink = zipthorn.DirSink(dest)
//
//	res, err := zipthorn.Guard(ctx, file, size, opts)
//	if err != nil {
//		return err // unparseable is a rejection, not a retry
//	}
//	if !res.OK() {
//		return fmt.Errorf("rejected: %s", res.Reason())
//	}
//
// Guard reads the central directory exactly once, whether or not it goes on
// to extract. Detection never extracts on its own, so it is safe to run on
// untrusted input; extraction validates the whole central directory against
// the limits before writing anything, then enforces them again as bytes
// land. Guard's Sink decides where surviving entries go — DirSink(path) for
// a real destination, or DiscardSink() (Guard's default) to validate an
// archive without writing anything at all. NamedGuardOptions("web") (or
// "strict", "permissive", "ci") is DefaultGuardOptions with a preset
// Thresholds/Disabled pair instead of DefaultConfig's, for a caller
// selecting a profile rather than tuning numbers by hand.
//
// Inspect, Detect, and Extract are exported too, for a caller that wants the
// pieces separately — most won't. All three take an io.ReaderAt directly
// (InspectFile and ExtractFile are the path-based convenience wrappers), for
// a caller holding an upload in memory or behind a non-file abstraction
// rather than a path on local disk.
//
// Every exported type here is a real struct or interface owned by this
// package, converted at the boundary from the internal packages that do the
// work. Nothing here is a type alias into internal/: renaming or restructuring
// an internal field never breaks a caller of this package.
package zipthorn

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
	"github.com/PeacexF/zipthorn/internal/detector"
	"github.com/PeacexF/zipthorn/internal/extractor"
	"github.com/PeacexF/zipthorn/internal/generator"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Limits bound any operation that generates or extracts archive data.
type Limits struct {
	MaxOutputBytes    int64   `json:"max_output_bytes"`
	MaxExpansionRatio float64 `json:"max_expansion_ratio"` // declared / compressed
	MaxFiles          int64   `json:"max_files"`
	MaxDepth          int     `json:"max_depth"`   // directory nesting
	MaxNesting        int     `json:"max_nesting"` // archive-within-archive
}

// Thresholds are the detection engine's decision boundaries: the point at
// or above which a characteristic is treated as HIGH risk.
type Thresholds struct {
	ExpansionRatio float64 `json:"expansion_ratio"`
	DeclaredSize   int64   `json:"declared_size"`
	FileCount      int64   `json:"file_count"`
	Depth          int     `json:"depth"`
	Nesting        int     `json:"nesting"`
}

// Config is the resource limits and detection thresholds that govern every
// operation. Policy lives here, never at a call site.
type Config struct {
	Limits     Limits     `json:"limits"`
	Thresholds Thresholds `json:"thresholds"`
}

func toConfig(c config.Config) Config {
	return Config{Limits: Limits(c.Limits), Thresholds: Thresholds(c.Thresholds)}
}

// Byte-size constants, matching the binary units the config files accept.
const (
	KB = config.KB
	MB = config.MB
	GB = config.GB
)

// DefaultConfig returns the built-in limits and thresholds. It is the only
// place defaults are defined.
//
// This package has no file-loading config API. Configure it directly in
// code — start from DefaultConfig and override what you need:
//
//	cfg := zipthorn.DefaultConfig()
//	cfg.Limits.MaxFiles = 500
//	cfg.Thresholds.ExpansionRatio = 20
//
// YAML file discovery (global then local, "closest wins") is a CLI feature,
// not a library one: it depends on $HOME and the working directory, which is
// invisible at the call site and unreproducible in tests. A library that
// wants file-based config should read and parse the file itself and build a
// Config from the result.
func DefaultConfig() Config { return toConfig(config.Default()) }

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

// PathIssue names one suspicious property of an entry name.
type PathIssue string

// The full set of issues PathIssues can report. Named Issue* rather than
// Path* to avoid colliding with the PathTraversal and SuspiciousPath
// indicator IDs below, which are a different namespace (rule IDs, not path
// properties) that happens to share some words.
const (
	IssueEmpty      = PathIssue(archive.PathEmpty)
	IssueNonUTF8    = PathIssue(archive.PathNonUTF8)
	IssueControl    = PathIssue(archive.PathControl)
	IssueAbsolute   = PathIssue(archive.PathAbsolute)
	IssueTraversal  = PathIssue(archive.PathTraversal)
	IssueBackslash  = PathIssue(archive.PathBackslash)
	IssueDotSegment = PathIssue(archive.PathDotSegment)
	IssueReserved   = PathIssue(archive.PathReserved)
	IssueTrailing   = PathIssue(archive.PathTrailing)
)

func toPathIssues(in []archive.PathIssue) []PathIssue {
	if in == nil {
		return nil
	}
	out := make([]PathIssue, len(in))
	for i, v := range in {
		out[i] = PathIssue(v)
	}
	return out
}

// Entry is one central-directory record.
type Entry struct {
	Name             string    `json:"name"`
	Method           uint16    `json:"method"`
	MethodName       string    `json:"method_name"`
	Level            string    `json:"level,omitempty"`
	CompressedSize   int64     `json:"compressed_size"`
	UncompressedSize int64     `json:"uncompressed_size"`
	Depth            int       `json:"depth"`
	IsDir            bool      `json:"is_dir"`
	Encrypted        bool      `json:"encrypted"`
	Modified         time.Time `json:"modified"`
	CRC32            uint32    `json:"crc32"`
	Comment          string    `json:"comment,omitempty"`
}

// MethodCount summarizes how many entries use one compression method.
type MethodCount struct {
	Method uint16 `json:"method"`
	Name   string `json:"name"`
	Count  int64  `json:"count"`
}

// Duplicate is a name claimed by more than one entry.
type Duplicate struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Info is the whole-archive summary produced without extracting anything.
type Info struct {
	Path           string        `json:"path,omitempty"`
	ArchiveSize    int64         `json:"archive_size"`
	CompressedSize int64         `json:"compressed_size"`
	DeclaredSize   int64         `json:"declared_size"`
	ExpansionRatio float64       `json:"expansion_ratio"`
	FileCount      int64         `json:"file_count"`
	DirCount       int64         `json:"dir_count"`
	MaxDepth       int           `json:"max_depth"`
	Methods        []MethodCount `json:"methods"`
	Duplicates     []Duplicate   `json:"duplicates,omitempty"`
	NestedArchives []string      `json:"nested_archives,omitempty"`
	Encrypted      bool          `json:"encrypted"`
	Comment        string        `json:"comment,omitempty"`
	Entries        []Entry       `json:"entries,omitempty"`
}

func toInfo(i *archive.Info) *Info {
	if i == nil {
		return nil
	}
	out := &Info{
		Path:           i.Path,
		ArchiveSize:    i.ArchiveSize,
		CompressedSize: i.CompressedSize,
		DeclaredSize:   i.DeclaredSize,
		ExpansionRatio: i.ExpansionRatio,
		FileCount:      i.FileCount,
		DirCount:       i.DirCount,
		MaxDepth:       i.MaxDepth,
		NestedArchives: i.NestedArchives,
		Encrypted:      i.Encrypted,
		Comment:        i.Comment,
	}
	if i.Methods != nil {
		out.Methods = make([]MethodCount, len(i.Methods))
		for idx, m := range i.Methods {
			out.Methods[idx] = MethodCount(m)
		}
	}
	if i.Duplicates != nil {
		out.Duplicates = make([]Duplicate, len(i.Duplicates))
		for idx, d := range i.Duplicates {
			out.Duplicates[idx] = Duplicate(d)
		}
	}
	if i.Entries != nil {
		out.Entries = make([]Entry, len(i.Entries))
		for idx, e := range i.Entries {
			out.Entries[idx] = Entry(e)
		}
	}
	return out
}

// toInternal converts back to the type the detection and extraction engines
// operate on. A nil *Info converts to a nil *archive.Info.
func (in *Info) toInternal() *archive.Info {
	if in == nil {
		return nil
	}
	out := &archive.Info{
		Path:           in.Path,
		ArchiveSize:    in.ArchiveSize,
		CompressedSize: in.CompressedSize,
		DeclaredSize:   in.DeclaredSize,
		ExpansionRatio: in.ExpansionRatio,
		FileCount:      in.FileCount,
		DirCount:       in.DirCount,
		MaxDepth:       in.MaxDepth,
		NestedArchives: in.NestedArchives,
		Encrypted:      in.Encrypted,
		Comment:        in.Comment,
	}
	if in.Methods != nil {
		out.Methods = make([]archive.MethodCount, len(in.Methods))
		for idx, m := range in.Methods {
			out.Methods[idx] = archive.MethodCount(m)
		}
	}
	if in.Duplicates != nil {
		out.Duplicates = make([]archive.Duplicate, len(in.Duplicates))
		for idx, d := range in.Duplicates {
			out.Duplicates[idx] = archive.Duplicate(d)
		}
	}
	if in.Entries != nil {
		out.Entries = make([]archive.Entry, len(in.Entries))
		for idx, e := range in.Entries {
			out.Entries[idx] = archive.Entry(e)
		}
	}
	return out
}

// ErrInvalidArchive reports input that could not be parsed as a ZIP archive.
var ErrInvalidArchive = archive.ErrInvalidArchive

// Inspect reads an archive's central directory from r and reports its
// metadata. It never extracts, so it is safe on untrusted input.
func Inspect(r io.ReaderAt, size int64) (*Info, error) {
	i, err := archive.Read(r, size)
	return toInfo(i), err
}

// InspectFile is Inspect over the archive at path.
func InspectFile(path string) (*Info, error) {
	i, err := archive.Open(path)
	return toInfo(i), err
}

// PathIssues reports everything suspicious about an entry name.
func PathIssues(name string) []PathIssue { return toPathIssues(archive.PathIssues(name)) }

// Escapes reports whether an entry name would write outside the destination
// directory. It is the check an extractor must not skip.
func Escapes(name string) bool { return archive.Escapes(name) }

// SupportedMethod reports whether zipthorn can decompress a ZIP method.
func SupportedMethod(method uint16) bool { return archive.Supported(method) }

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

// Level is a risk level: LevelLow, LevelMedium, or LevelHigh.
type Level int

// Risk levels, low to high.
const (
	LevelLow Level = iota
	LevelMedium
	LevelHigh
)

var levelNames = map[Level]string{LevelLow: "LOW", LevelMedium: "MEDIUM", LevelHigh: "HIGH"}

// String renders a Level as its name ("LOW", "MEDIUM", "HIGH"), or
// "LEVEL_<n>" for a value outside the three known levels.
func (l Level) String() string {
	if n, ok := levelNames[l]; ok {
		return n
	}
	return fmt.Sprintf("LEVEL_%d", int(l))
}

// MarshalJSON renders a Level as its name ("LOW", "MEDIUM", "HIGH"), matching
// what the CLI's --json output has always produced.
func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

// UnmarshalJSON parses a Level from its name, the inverse of MarshalJSON.
// It returns an error for anything other than "LOW", "MEDIUM", or "HIGH".
func (l *Level) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for lvl, name := range levelNames {
		if name == s {
			*l = lvl
			return nil
		}
	}
	return fmt.Errorf("unknown risk level %q", s)
}

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
	EncryptedEntries      = detector.EncryptedEntries
)

// Named detection policies.
const (
	PolicyDefault    = detector.PolicyDefault
	PolicyStrict     = detector.PolicyStrict
	PolicyPermissive = detector.PolicyPermissive
	PolicyWeb        = detector.PolicyWeb
	PolicyCI         = detector.PolicyCI
)

// PathFinding is one entry name the path rules objected to.
type PathFinding struct {
	Name    string      `json:"name"`
	Issues  []PathIssue `json:"issues"`
	Escapes bool        `json:"escapes"`
}

func toPathFinding(p detector.PathFinding) PathFinding {
	return PathFinding{Name: p.Name, Issues: toPathIssues(p.Issues), Escapes: p.Escapes}
}

// Features are the archive properties the rules operate on.
type Features struct {
	ArchiveSize    int64   `json:"archive_size"`
	CompressedSize int64   `json:"compressed_size"`
	DeclaredSize   int64   `json:"declared_size"`
	ExpansionRatio float64 `json:"expansion_ratio"`
	FileCount      int64   `json:"file_count"`
	DirCount       int64   `json:"dir_count"`
	MaxDepth       int     `json:"max_depth"`
	Encrypted      bool    `json:"encrypted"`

	NestedArchives  int `json:"nested_archives"`
	Duplicates      int `json:"duplicates"`
	EscapingPaths   int `json:"escaping_paths"`
	SuspiciousPaths int `json:"suspicious_paths"`

	NestedSample    []string      `json:"nested_sample,omitempty"`
	DuplicateSample []string      `json:"duplicate_sample,omitempty"`
	PathSample      []PathFinding `json:"path_sample,omitempty"`
}

func toFeatures(f detector.Features) Features {
	out := Features{
		ArchiveSize:     f.ArchiveSize,
		CompressedSize:  f.CompressedSize,
		DeclaredSize:    f.DeclaredSize,
		ExpansionRatio:  f.ExpansionRatio,
		FileCount:       f.FileCount,
		DirCount:        f.DirCount,
		MaxDepth:        f.MaxDepth,
		Encrypted:       f.Encrypted,
		NestedArchives:  f.NestedArchives,
		Duplicates:      f.Duplicates,
		EscapingPaths:   f.EscapingPaths,
		SuspiciousPaths: f.SuspiciousPaths,
		NestedSample:    f.NestedSample,
		DuplicateSample: f.DuplicateSample,
	}
	if f.PathSample != nil {
		out.PathSample = make([]PathFinding, len(f.PathSample))
		for i, p := range f.PathSample {
			out.PathSample[i] = toPathFinding(p)
		}
	}
	return out
}

// Indicator is one triggered rule.
type Indicator struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Level     Level    `json:"level"`
	Score     int      `json:"score"`
	Detail    string   `json:"detail"`
	Value     float64  `json:"value"`
	Threshold float64  `json:"threshold,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
}

func toIndicator(in detector.Indicator) Indicator {
	return Indicator{
		ID:        in.ID,
		Category:  in.Category,
		Level:     Level(in.Level),
		Score:     in.Score,
		Detail:    in.Detail,
		Value:     in.Value,
		Threshold: in.Threshold,
		Evidence:  in.Evidence,
	}
}

// Category is one facet of the archive's risk.
type Category struct {
	Name  string `json:"name"`
	Level Level  `json:"level"`
}

// Assessment is the detector's verdict on an archive.
type Assessment struct {
	Path           string      `json:"path,omitempty"`
	Level          Level       `json:"level"`
	Score          int         `json:"score"`
	Recommendation string      `json:"recommendation"`
	Categories     []Category  `json:"categories"`
	Indicators     []Indicator `json:"indicators"`
	Features       Features    `json:"features"`
	Thresholds     Thresholds  `json:"thresholds"`
}

func toAssessment(a detector.Assessment) Assessment {
	out := Assessment{
		Path:           a.Path,
		Level:          Level(a.Level),
		Score:          a.Score,
		Recommendation: a.Recommendation,
		Features:       toFeatures(a.Features),
		Thresholds:     Thresholds(a.Thresholds),
	}
	if a.Categories != nil {
		out.Categories = make([]Category, len(a.Categories))
		for i, c := range a.Categories {
			out.Categories[i] = Category{Name: c.Name, Level: Level(c.Level)}
		}
	}
	if a.Indicators != nil {
		out.Indicators = make([]Indicator, len(a.Indicators))
		for i, ind := range a.Indicators {
			out.Indicators[i] = toIndicator(ind)
		}
	}
	return out
}

// Policy is a named detection profile: preset thresholds plus disabled rules.
type Policy struct {
	Name        string
	Description string
	Thresholds  Thresholds
	Disabled    map[string]bool // rule IDs to disable
}

func toPolicy(p detector.Policy) Policy {
	return Policy{Name: p.Name, Description: p.Description, Thresholds: Thresholds(p.Thresholds), Disabled: p.Disabled}
}

// Detect assesses an archive's risk from its metadata alone.
func Detect(info *Info, t Thresholds) Assessment {
	return toAssessment(detector.Assess(info.toInternal(), config.Thresholds(t)))
}

// DetectWithPolicy assesses an archive using a named policy's thresholds and
// rule set, which supersede any configured thresholds.
func DetectWithPolicy(info *Info, policy string) (Assessment, error) {
	a, err := detector.AssessWithPolicy(info.toInternal(), policy)
	return toAssessment(a), err
}

// Policies lists the available named policies.
func Policies() []string { return detector.ListPolicies() }

// GetPolicy returns a named policy's thresholds and disabled rules.
func GetPolicy(name string) (Policy, error) {
	p, err := detector.GetPolicy(name)
	return toPolicy(p), err
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

// Status is an extraction outcome.
type Status string

// Extraction statuses.
const (
	StatusPass         = Status(extractor.StatusPass)
	StatusLimitReached = Status(extractor.StatusLimitReached)
	StatusTimeout      = Status(extractor.StatusTimeout)
	StatusInvalid      = Status(extractor.StatusInvalid)
	StatusError        = Status(extractor.StatusError)
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

// Sink receives extracted file contents. DirSink and DiscardSink are the two
// built-in implementations; a caller may implement Sink itself to extract
// into a virtual filesystem, an object store, or anywhere else that isn't a
// real directory. A type implementing Sink automatically works as an
// ExtractOptions.Sink — there is nothing to import from internal/.
type Sink interface {
	// File is called once per entry that survives validation, in the order
	// entries appear in the archive. mode is the entry's declared file mode.
	File(name string, mode fs.FileMode) (io.WriteCloser, error)
}

// Rollbacker is implemented by a Sink that can undo everything it wrote,
// which Extract calls when ExtractOptions.CleanOnFail is set and extraction
// is aborted partway through. A Sink that cannot roll back need not
// implement it; CleanOnFail is then a no-op.
type Rollbacker interface {
	Rollback() error
}

// DirSink writes each entry under dest on local disk, creating directories
// as needed.
func DirSink(dest string) Sink { return extractor.DirSink(dest) }

// DiscardSink writes nothing anywhere: every entry is still decompressed and
// counted against the limits, but no bytes land on any filesystem or store.
// This is validate-only extraction — proof an archive is safe to extract,
// without ever writing untrusted output.
func DiscardSink() Sink { return extractor.DiscardSink() }

// MemSink collects every surviving entry into memory instead of writing it
// anywhere, keyed by name in the returned EntryMap. It opens no new way to
// exceed Limits.MaxOutputBytes: every byte still passes through Extract's
// own byte and ratio checks first, exactly as it would for DirSink — MemSink
// only changes where the bytes end up once they've cleared those checks.
//
// Two entries sharing a name collide the same way DirSink's files on disk
// do: the later entry's bytes replace the earlier one's, and EntryMap ends
// up with one entry per distinct name, not one per archive entry.
//
// MemSink implements Rollbacker: when ExtractOptions.CleanOnFail is set, a
// failed extraction discards everything collected so far, the same
// guarantee DirSink gives by deleting what it wrote.
//
// Use it for archives whose contents fit comfortably in memory — a config
// bundle, a small upload processed entry-by-entry — not as a substitute for
// DirSink on anything large; nothing here double-checks that the collected
// total stays reasonable beyond whatever Limits already enforces.
func MemSink() (Sink, *EntryMap) {
	m := &EntryMap{}
	return &memSink{m: m}, m
}

// EntryMap holds the entries a MemSink collected, populated as extraction
// proceeds. Read it only after Extract or Guard returns — like every Sink,
// MemSink is written to from a single goroutine during extraction, so
// reading concurrently with an in-progress extraction is not safe.
type EntryMap struct {
	entries map[string][]byte
}

func (m *EntryMap) set(name string, b []byte) {
	if m.entries == nil {
		m.entries = make(map[string][]byte)
	}
	m.entries[name] = b
}

func (m *EntryMap) reset() { m.entries = nil }

// Bytes returns the collected content for name and whether it was present.
func (m *EntryMap) Bytes(name string) ([]byte, bool) {
	b, ok := m.entries[name]
	return b, ok
}

// Names returns every distinct name collected, sorted for deterministic
// iteration — map order is not exposed.
func (m *EntryMap) Names() []string {
	out := make([]string, 0, len(m.entries))
	for name := range m.entries {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Len returns how many distinct names were collected.
func (m *EntryMap) Len() int { return len(m.entries) }

type memSink struct{ m *EntryMap }

func (s *memSink) File(name string, _ fs.FileMode) (io.WriteCloser, error) {
	return &memEntryWriter{name: name, m: s.m}, nil
}

// Rollback discards every entry collected so far, so CleanOnFail leaves
// MemSink's caller with nothing rather than a partial result that could be
// mistaken for a complete one.
func (s *memSink) Rollback() error {
	s.m.reset()
	return nil
}

type memEntryWriter struct {
	name string
	buf  bytes.Buffer
	m    *EntryMap
}

func (w *memEntryWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func (w *memEntryWriter) Close() error {
	w.m.set(w.name, w.buf.Bytes())
	return nil
}

// ExtractOptions configures a bounded extraction.
type ExtractOptions struct {
	Limits Limits

	// Sink is where surviving entries are written. DirSink(path) recreates
	// the extractor's original behaviour; DiscardSink() validates an archive
	// against the limits without writing anything. Required.
	Sink Sink

	// CleanOnFail, if set, asks Sink to undo whatever it wrote when
	// extraction is aborted partway through. It is a no-op for a Sink that
	// does not implement Rollbacker.
	CleanOnFail bool

	// OnEntry, if set, is called once for every entry zipthorn refuses to
	// extract, with the reason. It fires for entries rejected during
	// pre-extraction path validation as well as entries that fail during
	// extraction itself. It is not called for entries that extract
	// successfully.
	OnEntry func(name string, err error)
}

func (o ExtractOptions) toInternal() extractor.Options {
	return extractor.Options{
		Limits:      config.Limits(o.Limits),
		Sink:        o.Sink,
		CleanOnFail: o.CleanOnFail,
		OnEntry:     o.OnEntry,
	}
}

// ExtractResult reports what a bounded extraction did and why it stopped.
type ExtractResult struct {
	Status         Status        `json:"status"`
	Elapsed        time.Duration `json:"elapsed_ns"`
	FilesProcessed int64         `json:"files_processed"`
	BytesProduced  int64         `json:"bytes_produced"`
	Ratio          float64       `json:"ratio"`
	LimitReached   string        `json:"limit_reached,omitempty"`
	Reason         string        `json:"reason,omitempty"`
	Error          string        `json:"error,omitempty"`

	inner extractor.Result
}

// Err returns the underlying error behind a non-PASS result, still wrapping
// whichever sentinel (ErrUnsafePath, ErrByteLimitHit, ...) caused it, so
// callers can branch with errors.Is instead of matching on Reason strings.
// It is nil when Status is StatusPass.
func (r ExtractResult) Err() error { return r.inner.Err() }

func toExtractResult(r extractor.Result) ExtractResult {
	return ExtractResult{
		Status:         Status(r.Status),
		Elapsed:        r.Elapsed,
		FilesProcessed: r.FilesProcessed,
		BytesProduced:  r.BytesProduced,
		Ratio:          r.Ratio,
		LimitReached:   r.LimitReached,
		Reason:         r.Reason,
		Error:          r.Error,
		inner:          r,
	}
}

// Extract unpacks an archive from r under hard limits, validating the
// central directory before writing anything and stopping the moment a limit
// is reached. Cancel ctx (or give it a deadline) to bound the wall-clock
// cost.
//
// Extract reports failure in the returned result's Status rather than as an
// error: a refused archive is a verdict, not a malfunction.
func Extract(ctx context.Context, r io.ReaderAt, size int64, opts ExtractOptions) ExtractResult {
	return toExtractResult(extractor.Extract(ctx, r, size, opts.toInternal()))
}

// ExtractFile is Extract over the archive at path.
func ExtractFile(ctx context.Context, path string, opts ExtractOptions) ExtractResult {
	return toExtractResult(extractor.ExtractFile(ctx, path, opts.toInternal()))
}

// ---------------------------------------------------------------------------
// Writer: bounded archive creation
// ---------------------------------------------------------------------------

// ErrWriterClosed is returned by Add or Close when called on a Writer that
// has already been closed successfully. It is never wrapped around a limit
// or safety failure — those return the same sentinels Extract uses
// (ErrUnsafePath, ErrFileLimitHit, ErrDepthLimitHit, ErrByteLimitHit).
var ErrWriterClosed = errors.New("zipthorn: writer is closed")

// Writer builds a well-formed ZIP archive one entry at a time, enforcing
// Limits as it goes rather than after the fact — the write fails the moment
// it would exceed them. Generate deliberately builds archives that fail
// zipthorn's own checks, for testing extractors with; Writer is the
// opposite case — an export endpoint bundling a user's files, a build step
// packaging an artifact, a service re-zipping entries Guard already
// cleared — where the goal is a well-formed archive whose declared
// metadata Inspect and Guard can trust on the way back in. Because Writer
// only ever streams the exact bytes it's given through real compression,
// the resulting archive's metadata is never dishonest the way a crafted one
// could be; the only thing left to enforce is that it stays within bounds.
//
// A Writer that has returned an error from Add or Close is failed: nothing
// written to the underlying io.Writer since is a valid archive (Close never
// writes a central directory once failed), and that content should be
// discarded rather than treated as a usable, if partial, ZIP.
type Writer struct {
	zw     *zip.Writer
	limits Limits
	stamp  time.Time
	files  int64
	total  int64
	closed bool
	err    error
}

// NewWriter returns a Writer that streams a ZIP archive to w, bounded by
// limits. MaxFiles caps the number of file entries (directories don't
// count, matching Info.FileCount); MaxOutputBytes caps the sum of their
// uncompressed sizes; MaxDepth caps every entry's path depth, files and
// directories alike. MaxExpansionRatio and MaxNesting have nothing to
// enforce here — a Writer only ever writes the bytes it's given, at no
// expansion, and creates no archives within the archive — so they're
// ignored.
func NewWriter(w io.Writer, limits Limits) *Writer {
	return &Writer{zw: zip.NewWriter(w), limits: limits, stamp: time.Now()}
}

// Add writes one entry named name with the given mode, copying r until EOF.
// r is ignored for a directory entry (mode.IsDir()); name gains a trailing
// "/" if it doesn't already have one. It fails, and leaves the Writer
// failed, if:
//
//   - a file entry's name would escape wherever the archive is later
//     extracted, or contains a control character (ErrUnsafePath) — the
//     same check, on the same file-entries-only basis, that Extract itself
//     applies during pre-extraction validation, so nothing this Writer
//     produces can smuggle a Zip Slip into whatever extracts it later
//   - name's path depth exceeds limits.MaxDepth (ErrDepthLimitHit)
//   - adding another file would exceed limits.MaxFiles (ErrFileLimitHit)
//   - r's content would push the running uncompressed total past
//     limits.MaxOutputBytes (ErrByteLimitHit) — checked incrementally as
//     bytes are copied, not just from a size the caller claims up front,
//     the same "fail before committing to bad state" contract Extract's
//     own byte-limit enforcement has
//
// Once Add returns an error, that error is final: it and every subsequent
// call to Add or Close return the same error without doing anything
// further.
func (w *Writer) Add(name string, mode fs.FileMode, r io.Reader) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrWriterClosed
	}

	isDir := mode.IsDir()
	if isDir && !strings.HasSuffix(name, "/") {
		name += "/"
	}

	if d := archive.Depth(name); d > w.limits.MaxDepth {
		w.err = fmt.Errorf("%w: %s is %d deep, exceeds max %d", ErrDepthLimitHit, name, d, w.limits.MaxDepth)
		return w.err
	}

	if !isDir {
		if archive.Escapes(name) {
			w.err = fmt.Errorf("%w: %s", ErrUnsafePath, name)
			return w.err
		}
		if slices.Contains(archive.PathIssues(name), archive.PathControl) {
			w.err = fmt.Errorf("%w: control character in %s", ErrUnsafePath, name)
			return w.err
		}
		if w.files >= w.limits.MaxFiles {
			w.err = fmt.Errorf("%w: adding %s would exceed max %d files", ErrFileLimitHit, name, w.limits.MaxFiles)
			return w.err
		}
	}

	h := &zip.FileHeader{Name: name, Modified: w.stamp}
	if isDir {
		h.Method = zip.Store
	} else {
		h.Method = zip.Deflate
	}
	h.SetMode(mode)

	fw, err := w.zw.CreateHeader(h)
	if err != nil {
		w.err = err
		return w.err
	}
	if isDir {
		return nil
	}

	remaining := max(w.limits.MaxOutputBytes-w.total, 0)
	// Read one byte past the budget: if r has exactly remaining bytes left,
	// CopyN reports n == remaining with an expected io.EOF; if r has more,
	// n == remaining+1 with no error, which is what actually signals the
	// overflow below. Either way, this never reads more than one byte
	// beyond what the archive is allowed to hold.
	n, err := io.CopyN(fw, r, remaining+1)
	if err != nil && err != io.EOF {
		w.err = err
		return w.err
	}
	if n > remaining {
		w.err = fmt.Errorf("%w: writing %s would exceed max %d bytes", ErrByteLimitHit, name, w.limits.MaxOutputBytes)
		return w.err
	}

	w.total += n
	w.files++
	return nil
}

// Close finalizes the archive, writing its central directory. If Add ever
// failed, Close returns that same error without writing a central
// directory — the bytes already sent to the underlying io.Writer are not,
// and will never become, a valid archive. Close is safe to call more than
// once; calls after a successful Close return nil.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.zw.Close(); err != nil {
		w.err = err
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

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

// Spec describes the fixture to generate.
type Spec struct {
	Profile      string  // one of the Profile* constants (ProfileRatio, ProfileFileCount, ...)
	Seed         int64   // deterministic seed; two Specs with the same Seed produce byte-identical output
	DeclaredSize int64   // total uncompressed bytes to generate
	FileCount    int64   // entries to generate
	FileSize     int64   // uncompressed size of one generated entry
	Ratio        float64 // target expansion of generated payloads
	Depth        int     // directory nesting
	Nesting      int     // archive-within-archive levels
	Level        int     // deflate level 1..9, or LevelDefault; 0 also means default
	Limits       Limits
}

func (s Spec) toInternal() generator.Spec {
	return generator.Spec{
		Profile:      s.Profile,
		Seed:         s.Seed,
		DeclaredSize: s.DeclaredSize,
		FileCount:    s.FileCount,
		FileSize:     s.FileSize,
		Ratio:        s.Ratio,
		Depth:        s.Depth,
		Nesting:      s.Nesting,
		Level:        s.Level,
		Limits:       config.Limits(s.Limits),
	}
}

// GenerateResult describes the fixture that was generated.
type GenerateResult struct {
	Path           string  `json:"path,omitempty"`
	Profile        string  `json:"profile"`
	Seed           int64   `json:"seed"`
	ArchiveSize    int64   `json:"archive_size"`
	DeclaredSize   int64   `json:"declared_size"`
	ExpansionRatio float64 `json:"expansion_ratio"`
	FileCount      int64   `json:"file_count"`
	DirCount       int64   `json:"dir_count"`
	MaxDepth       int     `json:"max_depth"`
	Nesting        int     `json:"nesting"`
	Limits         Limits  `json:"limits"`
}

func toGenerateResult(r *generator.Result) *GenerateResult {
	if r == nil {
		return nil
	}
	return &GenerateResult{
		Path:           r.Path,
		Profile:        r.Profile,
		Seed:           r.Seed,
		ArchiveSize:    r.ArchiveSize,
		DeclaredSize:   r.DeclaredSize,
		ExpansionRatio: r.ExpansionRatio,
		FileCount:      r.FileCount,
		DirCount:       r.DirCount,
		MaxDepth:       r.MaxDepth,
		Nesting:        r.Nesting,
		Limits:         Limits(r.Limits),
	}
}

// Profiles lists the available fixture profiles.
func Profiles() []string { return generator.Profiles() }

// Generate writes a bounded pathological fixture to w. Generation fails closed:
// if the spec would exceed Spec.Limits, nothing is written and the error wraps
// ErrLimitExceeded. A non-zero Spec.Seed makes the output byte-identical across
// runs.
func Generate(w io.Writer, s Spec) (*GenerateResult, error) {
	r, err := generator.Generate(w, s.toInternal())
	return toGenerateResult(r), err
}

// ---------------------------------------------------------------------------
// Guard: the one-call answer
// ---------------------------------------------------------------------------

// GuardOptions configures Guard: what to allow (Limits), what to call
// suspicious (Thresholds), and where surviving entries go (Sink).
type GuardOptions struct {
	Limits     Limits
	Thresholds Thresholds

	// Disabled names detection rule IDs (HighCompressionRatio,
	// DuplicateEntries, ...) to skip, the same knob a Policy's Disabled map
	// carries. A nil map disables nothing. NamedGuardOptions sets this from
	// the named Policy's own Disabled map; most callers building
	// GuardOptions by hand will leave it nil.
	Disabled map[string]bool

	// Sink is where surviving entries are written, exactly as in
	// ExtractOptions. DiscardSink() — Guard's default via
	// DefaultGuardOptions — validates the archive without writing anything;
	// set it to DirSink(path) to actually extract.
	Sink Sink

	// CleanOnFail and OnEntry behave exactly as the same-named
	// ExtractOptions fields.
	CleanOnFail bool
	OnEntry     func(name string, err error)
}

// DefaultGuardOptions returns GuardOptions built from DefaultConfig, with
// Sink defaulting to DiscardSink() — the safe default for a function whose
// job is deciding whether to trust an archive, not where to put it.
func DefaultGuardOptions() GuardOptions {
	cfg := DefaultConfig()
	return GuardOptions{Limits: cfg.Limits, Thresholds: cfg.Thresholds, Sink: DiscardSink()}
}

// NamedGuardOptions returns GuardOptions preset for a named use case — the
// same names GetPolicy uses (strict, permissive, web, ci; also default,
// equivalent to DefaultGuardOptions). Thresholds and Disabled come from the
// named Policy; Limits stays DefaultConfig's regardless of name, because
// Policy itself only ever varies Thresholds and disabled rules, never
// Limits — a Guard-side preset that started varying Limits too would be
// inventing a second, inconsistent axis of "named policy". Sink defaults to
// DiscardSink(), same as DefaultGuardOptions.
func NamedGuardOptions(name string) (GuardOptions, error) {
	p, err := GetPolicy(name)
	if err != nil {
		return GuardOptions{}, err
	}
	return GuardOptions{
		Limits:     DefaultConfig().Limits,
		Thresholds: p.Thresholds,
		Disabled:   p.Disabled,
		Sink:       DiscardSink(),
	}, nil
}

func (o GuardOptions) toExtractOptions() ExtractOptions {
	return ExtractOptions{Limits: o.Limits, Sink: o.Sink, CleanOnFail: o.CleanOnFail, OnEntry: o.OnEntry}
}

// GuardResult is the combined outcome of Guard: what the archive looked
// like, what the detector made of it, and — unless the detector rejected it
// first — what extraction did.
type GuardResult struct {
	Info       *Info
	Assessment Assessment

	// Extract is the zero ExtractResult (Status == "") when Assessment
	// rejected the archive before extraction ever ran.
	Extract ExtractResult
}

// OK reports the combined verdict: the detector did not reject the archive,
// and extraction (if it ran) reported StatusPass. A caller that only wants
// pass/fail needs nothing else from GuardResult.
func (g GuardResult) OK() bool { return g.Extract.Status == StatusPass }

// Reason explains a non-OK result in one line: the detector's leading
// indicator if it rejected the archive before extraction ran, or the
// extractor's own reason otherwise. It is empty when OK is true.
func (g GuardResult) Reason() string {
	if g.OK() {
		return ""
	}
	if g.Assessment.Recommendation == Reject {
		if len(g.Assessment.Indicators) > 0 {
			return fmt.Sprintf("%s: %s", g.Assessment.Recommendation, g.Assessment.Indicators[0].Detail)
		}
		return g.Assessment.Recommendation
	}
	return g.Extract.Reason
}

// Guard inspects, assesses, and — unless the detector rejects it — extracts
// an archive from r in one pass, reading the central directory exactly once
// rather than paying for it twice the way calling Inspect and then Extract
// would.
//
// Guard reports refusal in the returned result rather than as an error: a
// rejected or unsafe archive is a verdict, not a malfunction. The error
// return is reserved for input that could not even be parsed as a ZIP
// archive.
func Guard(ctx context.Context, r io.ReaderAt, size int64, opts GuardOptions) (GuardResult, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return GuardResult{}, fmt.Errorf("%w: %v", archive.ErrInvalidArchive, err)
	}
	info := archive.Summarize(zr, size)

	a := detector.AssessWithRules(info, config.Thresholds(opts.Thresholds), opts.Disabled)
	res := GuardResult{Info: toInfo(info), Assessment: toAssessment(a)}

	if a.Recommendation == detector.Reject {
		return res, nil
	}

	res.Extract = toExtractResult(extractor.ExtractParsed(ctx, size, info, zr, opts.toExtractOptions().toInternal()))
	return res, nil
}
