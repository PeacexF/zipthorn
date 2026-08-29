package archive_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/archive"
)

type spec struct {
	name   string
	body   []byte
	method uint16
}

func build(t *testing.T, specs ...spec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, s := range specs {
		h := &zip.FileHeader{Name: s.name, Method: s.method}
		if strings.HasSuffix(s.name, "/") {
			h.SetMode(0o755 | os.ModeDir)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("CreateHeader(%q): %v", s.name, err)
		}
		if _, err := w.Write(s.body); err != nil {
			t.Fatalf("Write(%q): %v", s.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func read(t *testing.T, data []byte) *archive.Info {
	t.Helper()
	info, err := archive.Read(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return info
}

func TestCountsAndSizes(t *testing.T) {
	body := bytes.Repeat([]byte("zipthorn"), 128)
	data := build(t,
		spec{"dir/", nil, zip.Store},
		spec{"dir/a.txt", body, zip.Deflate},
		spec{"b.bin", []byte("hello"), zip.Store},
	)

	info := read(t, data)

	if info.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2", info.FileCount)
	}
	if info.DirCount != 1 {
		t.Errorf("DirCount = %d, want 1", info.DirCount)
	}
	if want := int64(len(body) + len("hello")); info.DeclaredSize != want {
		t.Errorf("DeclaredSize = %d, want %d", info.DeclaredSize, want)
	}
	if info.ArchiveSize != int64(len(data)) {
		t.Errorf("ArchiveSize = %d, want %d", info.ArchiveSize, len(data))
	}
	if info.CompressedSize >= info.DeclaredSize {
		t.Errorf("CompressedSize %d should be below DeclaredSize %d",
			info.CompressedSize, info.DeclaredSize)
	}
	if len(info.Entries) != 3 {
		t.Errorf("len(Entries) = %d, want 3", len(info.Entries))
	}
}

func TestExpansionRatioUsesArchiveSize(t *testing.T) {
	data := build(t, spec{"a.txt", bytes.Repeat([]byte("A"), 100_000), zip.Deflate})
	info := read(t, data)

	want := archive.Ratio(info.DeclaredSize, info.ArchiveSize)
	if info.ExpansionRatio != want {
		t.Errorf("ExpansionRatio = %v, want %v", info.ExpansionRatio, want)
	}
	if info.ExpansionRatio <= 1 {
		t.Errorf("highly compressible data should expand, got %v", info.ExpansionRatio)
	}
}

func TestRatio(t *testing.T) {
	tests := []struct {
		declared, compressed int64
		want                 float64
	}{
		{1000, 10, 100},
		{0, 10, 0},
		{1000, 0, 0},  // empty archive must not produce +Inf
		{1000, -1, 0}, // nor a negative ratio
		{math.MaxInt64, math.MaxInt64, 1},
	}
	for _, tt := range tests {
		if got := archive.Ratio(tt.declared, tt.compressed); got != tt.want {
			t.Errorf("Ratio(%d, %d) = %v, want %v",
				tt.declared, tt.compressed, got, tt.want)
		}
	}
}

func TestDepth(t *testing.T) {
	tests := map[string]int{
		"":                  0,
		"a.txt":             0,
		"a/b.txt":           1,
		"a/b/c/d.txt":       3,
		"a/":                1,
		"a/b/":              2,
		"/absolute/a.txt":   1,
		"a/b/c/d/e/f/g.txt": 6,
	}
	for name, want := range tests {
		if got := archive.Depth(name); got != want {
			t.Errorf("Depth(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestMaxDepth(t *testing.T) {
	info := read(t, build(t,
		spec{"shallow.txt", []byte("x"), zip.Store},
		spec{"a/b/c/deep.txt", []byte("x"), zip.Store},
	))
	if info.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", info.MaxDepth)
	}
}

func TestDuplicateDetection(t *testing.T) {
	info := read(t, build(t,
		spec{"dup.txt", []byte("one"), zip.Store},
		spec{"dup.txt", []byte("two"), zip.Store},
		spec{"dup.txt", []byte("three"), zip.Store},
		spec{"unique.txt", []byte("x"), zip.Store},
	))

	if len(info.Duplicates) != 1 {
		t.Fatalf("Duplicates = %+v, want 1 entry", info.Duplicates)
	}
	if info.Duplicates[0].Name != "dup.txt" || info.Duplicates[0].Count != 3 {
		t.Errorf("Duplicates[0] = %+v, want {dup.txt 3}", info.Duplicates[0])
	}
}

func TestNoDuplicatesReportsNone(t *testing.T) {
	info := read(t, build(t, spec{"a.txt", []byte("x"), zip.Store}))
	if len(info.Duplicates) != 0 {
		t.Errorf("Duplicates = %+v, want none", info.Duplicates)
	}
}

func TestNestedArchiveDetection(t *testing.T) {
	inner := build(t, spec{"payload.txt", []byte("x"), zip.Store})
	info := read(t, build(t,
		spec{"a/inner.ZIP", inner, zip.Store},
		spec{"lib.jar", inner, zip.Store},
		spec{"plain.txt", []byte("x"), zip.Store},
	))

	want := []string{"a/inner.ZIP", "lib.jar"}
	if len(info.NestedArchives) != len(want) {
		t.Fatalf("NestedArchives = %v, want %v", info.NestedArchives, want)
	}
	for i, n := range want {
		if info.NestedArchives[i] != n {
			t.Errorf("NestedArchives[%d] = %q, want %q", i, info.NestedArchives[i], n)
		}
	}
}

func TestMethodSummary(t *testing.T) {
	info := read(t, build(t,
		spec{"a.txt", bytes.Repeat([]byte("a"), 64), zip.Deflate},
		spec{"b.txt", bytes.Repeat([]byte("b"), 64), zip.Deflate},
		spec{"c.txt", []byte("c"), zip.Store},
	))

	if len(info.Methods) != 2 {
		t.Fatalf("Methods = %+v, want 2", info.Methods)
	}
	if info.Methods[0].Name != "DEFLATE" || info.Methods[0].Count != 2 {
		t.Errorf("Methods[0] = %+v, want DEFLATE x2 first", info.Methods[0])
	}
	if info.Methods[1].Name != "STORE" || info.Methods[1].Count != 1 {
		t.Errorf("Methods[1] = %+v, want STORE x1", info.Methods[1])
	}
}

func TestMethodNameAndSupport(t *testing.T) {
	if got := archive.MethodName(zip.Deflate); got != "DEFLATE" {
		t.Errorf("MethodName(8) = %q", got)
	}
	if got := archive.MethodName(14); got != "LZMA" {
		t.Errorf("MethodName(14) = %q", got)
	}
	if got := archive.MethodName(1234); got != "METHOD_1234" {
		t.Errorf("MethodName(1234) = %q", got)
	}
	if !archive.Supported(zip.Store) || !archive.Supported(zip.Deflate) {
		t.Error("store and deflate must be supported")
	}
	if archive.Supported(14) {
		t.Error("LZMA must not report as natively supported")
	}
}

func TestDeflateLevelRecorded(t *testing.T) {
	info := read(t, build(t,
		spec{"a.txt", bytes.Repeat([]byte("a"), 64), zip.Deflate},
		spec{"b.txt", []byte("b"), zip.Store},
	))

	if info.Entries[0].Level == "" {
		t.Error("deflate entry should carry a level")
	}
	if info.Entries[1].Level != "" {
		t.Errorf("store entry level = %q, want empty", info.Entries[1].Level)
	}
}

func TestEmptyArchive(t *testing.T) {
	info := read(t, build(t))

	if info.FileCount != 0 || info.DeclaredSize != 0 {
		t.Errorf("empty archive = %+v", info)
	}
	if info.ExpansionRatio != 0 {
		t.Errorf("ExpansionRatio = %v, want 0", info.ExpansionRatio)
	}
	if len(info.Methods) != 0 {
		t.Errorf("Methods = %+v, want none", info.Methods)
	}
}

func TestInvalidArchives(t *testing.T) {
	valid := build(t, spec{"a.txt", []byte("hello"), zip.Store})

	tests := map[string][]byte{
		"empty input":     {},
		"garbage":         []byte("this is definitely not a zip file"),
		"truncated":       valid[:len(valid)/2],
		"missing trailer": valid[:len(valid)-8],
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := archive.Read(bytes.NewReader(data), int64(len(data)))
			if !errors.Is(err, archive.ErrInvalidArchive) {
				t.Fatalf("err = %v, want ErrInvalidArchive", err)
			}
		})
	}
}

func TestOpenMissingFile(t *testing.T) {
	_, err := archive.Open(filepath.Join(t.TempDir(), "absent.zip"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if errors.Is(err, archive.ErrInvalidArchive) {
		t.Error("a missing file is not a malformed archive")
	}
}

func TestOpenDirectory(t *testing.T) {
	if _, err := archive.Open(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory")
	}
}

func TestOpenSetsPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(p, build(t, spec{"a.txt", []byte("x"), zip.Store}), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := archive.Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if info.Path != p {
		t.Errorf("Path = %q, want %q", info.Path, p)
	}
}

func TestFixtureSimple(t *testing.T) {
	info, err := archive.Open(filepath.Join("testdata", "simple.zip"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if info.FileCount != 3 {
		t.Errorf("FileCount = %d, want 3", info.FileCount)
	}
	if info.DirCount != 1 {
		t.Errorf("DirCount = %d, want 1", info.DirCount)
	}
	if info.MaxDepth != 1 {
		t.Errorf("MaxDepth = %d, want 1", info.MaxDepth)
	}
	if len(info.Duplicates) != 0 || len(info.NestedArchives) != 0 {
		t.Errorf("simple fixture should be unremarkable: %+v", info)
	}
	if info.Encrypted {
		t.Error("fixture must not be encrypted")
	}
}

func TestFixtureNested(t *testing.T) {
	info, err := archive.Open(filepath.Join("testdata", "nested.zip"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if info.MaxDepth != 5 {
		t.Errorf("MaxDepth = %d, want 5", info.MaxDepth)
	}
	if len(info.NestedArchives) != 1 || info.NestedArchives[0] != "bundle/inner.zip" {
		t.Errorf("NestedArchives = %v", info.NestedArchives)
	}
	if len(info.Duplicates) != 1 || info.Duplicates[0].Name != "dup.txt" {
		t.Errorf("Duplicates = %+v", info.Duplicates)
	}
	if info.Comment != "zipthorn fixture" {
		t.Errorf("Comment = %q", info.Comment)
	}
}
