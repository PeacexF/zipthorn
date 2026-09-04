// Package archive reads ZIP metadata without extracting entry contents
package archive

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// ErrInvalidArchive reports input that could not be parsed as a ZIP archive.
var ErrInvalidArchive = errors.New("invalid zip archive")

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

// Info is the whole-archive summary
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

var methodNames = map[uint16]string{
	0:  "STORE",
	1:  "SHRINK",
	6:  "IMPLODE",
	8:  "DEFLATE",
	9:  "DEFLATE64",
	12: "BZIP2",
	14: "LZMA",
	93: "ZSTD",
	95: "XZ",
	96: "JPEG",
	97: "WAVPACK",
	98: "PPMD",
	99: "AES",
}

var nestedExts = map[string]bool{
	".zip":  true,
	".zipx": true,
	".jar":  true,
	".war":  true,
	".ear":  true,
	".apk":  true,
	".aar":  true,
	".ipa":  true,
	".xpi":  true,
	".egg":  true,
	".whl":  true,
}

func MethodName(method uint16) string {
	if n, ok := methodNames[method]; ok {
		return n
	}
	return fmt.Sprintf("METHOD_%d", method)
}

func Supported(method uint16) bool {
	return method == zip.Store || method == zip.Deflate
}

func Depth(name string) int {
	isDir := strings.HasSuffix(name, "/")
	trimmed := strings.Trim(name, "/")
	if trimmed == "" {
		return 0
	}
	d := strings.Count(trimmed, "/")
	if isDir {
		d++
	}
	return d
}

// reports declared/compressed expansion
func Ratio(declared, compressed int64) float64 {
	if compressed <= 0 || declared <= 0 {
		return 0
	}
	return float64(declared) / float64(compressed)
}

// reads the metadata of the archive at path.
func Open(name string) (*Info, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s: is a directory", name)
	}

	info, err := Read(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	info.Path = name
	return info, nil
}

// reads archive metadata from r, which must hold size bytes.
func Read(r io.ReaderAt, size int64) (*Info, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	return Summarize(zr, size), nil
}

// Summarize builds an Info from an already-parsed zip.Reader. Read is
// Summarize(zip.NewReader(r, size), size) for the common case of a reader
// that hasn't been parsed yet; a caller that needs the *zip.Reader itself
// afterwards (extraction reusing the same parse rather than paying for it
// twice) calls Summarize directly.
func Summarize(zr *zip.Reader, size int64) *Info {
	info := &Info{
		ArchiveSize: size,
		Comment:     zr.Comment,
		Entries:     make([]Entry, 0, len(zr.File)),
	}

	counts := make(map[uint16]int64)
	seen := make(map[string]int, len(zr.File))

	for _, f := range zr.File {
		e := newEntry(&f.FileHeader)
		info.Entries = append(info.Entries, e)

		info.CompressedSize = addClamped(info.CompressedSize, e.CompressedSize)
		info.DeclaredSize = addClamped(info.DeclaredSize, e.UncompressedSize)
		if e.Depth > info.MaxDepth {
			info.MaxDepth = e.Depth
		}
		if e.IsDir {
			info.DirCount++
		} else {
			info.FileCount++
			if nestedExts[strings.ToLower(path.Ext(e.Name))] {
				info.NestedArchives = append(info.NestedArchives, e.Name)
			}
		}
		if e.Encrypted {
			info.Encrypted = true
		}
		counts[e.Method]++
		seen[e.Name]++
	}

	info.ExpansionRatio = Ratio(info.DeclaredSize, size)
	info.Methods = methodSummary(counts)
	info.Duplicates = duplicates(seen)
	return info
}

func clamp64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func addClamped(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func newEntry(h *zip.FileHeader) Entry {
	e := Entry{
		Name:             h.Name,
		Method:           h.Method,
		MethodName:       MethodName(h.Method),
		CompressedSize:   clamp64(h.CompressedSize64),
		UncompressedSize: clamp64(h.UncompressedSize64),
		Depth:            Depth(h.Name),
		IsDir:            h.FileInfo().IsDir(),
		Encrypted:        h.Flags&0x1 != 0,
		Modified:         h.Modified,
		CRC32:            h.CRC32,
		Comment:          h.Comment,
	}
	if h.Method == zip.Deflate {
		e.Level = deflateLevel(h.Flags)
	}
	return e
}

// reads the general-purpose bit flag's compression hint
func deflateLevel(flags uint16) string {
	switch (flags >> 1) & 0x3 {
	case 0:
		return "normal"
	case 1:
		return "maximum"
	case 2:
		return "fast"
	default:
		return "superfast"
	}
}

func methodSummary(counts map[uint16]int64) []MethodCount {
	out := make([]MethodCount, 0, len(counts))
	for m, n := range counts {
		out = append(out, MethodCount{Method: m, Name: MethodName(m), Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func duplicates(seen map[string]int) []Duplicate {
	var out []Duplicate
	for name, n := range seen {
		if n > 1 {
			out = append(out, Duplicate{Name: name, Count: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
