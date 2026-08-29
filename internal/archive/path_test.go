package archive_test

import (
	"slices"
	"testing"

	"github.com/PeacexF/zipthorn/internal/archive"
)

func TestPathIssuesCleanNames(t *testing.T) {
	clean := []string{
		"a.txt",
		"docs/readme.txt",
		"a/b/c/d.txt",
		"dir/",
		"spaced name.txt",
		"unicode-ü.txt",
		"..leading-dots.txt",
		"CONSOLE.txt", // only the exact reserved stem is reserved
		"a.CON",       // reserved names are matched on the stem, not the extension
	}
	for _, name := range clean {
		if got := archive.PathIssues(name); got != nil {
			t.Errorf("PathIssues(%q) = %v, want none", name, got)
		}
	}
}

func TestPathIssuesClassifies(t *testing.T) {
	tests := []struct {
		name string
		want []archive.PathIssue
	}{
		{"", []archive.PathIssue{archive.PathEmpty}},
		{"../etc/passwd", []archive.PathIssue{archive.PathTraversal}},
		{"a/../../b.txt", []archive.PathIssue{archive.PathTraversal}},
		{"/etc/passwd", []archive.PathIssue{archive.PathAbsolute}},
		{`\windows\system32`, []archive.PathIssue{archive.PathAbsolute, archive.PathBackslash}},
		{`C:/Windows/x.txt`, []archive.PathIssue{archive.PathAbsolute}},
		{`..\..\windows\x`, []archive.PathIssue{archive.PathTraversal, archive.PathBackslash}},
		{"dir\\file.txt", []archive.PathIssue{archive.PathBackslash}},
		{"./x.txt", []archive.PathIssue{archive.PathDotSegment}},
		{"a/./b.txt", []archive.PathIssue{archive.PathDotSegment}},
		{"CON", []archive.PathIssue{archive.PathReserved}},
		{"dir/nul.txt", []archive.PathIssue{archive.PathReserved}},
		{"COM9.log", []archive.PathIssue{archive.PathReserved}},
		{"trailing.", []archive.PathIssue{archive.PathTrailing}},
		{"trailing ", []archive.PathIssue{archive.PathTrailing}},
		{"a\nb.txt", []archive.PathIssue{archive.PathControl}},
		{"a\x00b.txt", []archive.PathIssue{archive.PathControl}},
		{"a\x7fb.txt", []archive.PathIssue{archive.PathControl}},
		{"bad\xffname.txt", []archive.PathIssue{archive.PathNonUTF8}},
	}

	for _, tt := range tests {
		got := archive.PathIssues(tt.name)
		if !slices.Equal(got, tt.want) {
			t.Errorf("PathIssues(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// A single name can be suspicious several ways at once, and the order is fixed
// so callers and tests can compare directly.
func TestPathIssuesAreOrdered(t *testing.T) {
	got := archive.PathIssues("/a/../b/./CON.txt")
	want := []archive.PathIssue{
		archive.PathAbsolute, archive.PathTraversal,
		archive.PathDotSegment, archive.PathReserved,
	}
	if !slices.Equal(got, want) {
		t.Errorf("PathIssues = %v, want %v", got, want)
	}
}

func TestEscapes(t *testing.T) {
	tests := map[string]bool{
		"":                false,
		"a.txt":           false,
		"docs/a.txt":      false,
		"a/../b.txt":      false, // cancels out, stays inside
		"./a.txt":         false,
		"../a.txt":        true,
		"..":              true,
		"a/../../b.txt":   true,
		"/etc/passwd":     true,
		`\etc\passwd`:     true,
		`C:\Windows\x`:    true,
		`..\..\windows\x`: true, // a backslash still separates for the extractors that split on it
		"dir/..":          false,
	}
	for name, want := range tests {
		if got := archive.Escapes(name); got != want {
			t.Errorf("Escapes(%q) = %v, want %v", name, got, want)
		}
	}
}
