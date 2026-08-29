package archive

import (
	"path"
	"strings"
	"unicode/utf8"
)

// PathIssue names one suspicious property of an archive entry name
type PathIssue string

const (
	PathEmpty      PathIssue = "empty"
	PathNonUTF8    PathIssue = "non_utf8"
	PathControl    PathIssue = "control"
	PathAbsolute   PathIssue = "absolute"
	PathTraversal  PathIssue = "traversal"
	PathBackslash  PathIssue = "backslash"
	PathDotSegment PathIssue = "dot_segment"
	PathReserved   PathIssue = "reserved"
	PathTrailing   PathIssue = "trailing"
)

// Windows refuses these as filenames whatever the extension,
// so an archive carrying one is either broken or probing the extractor.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func PathIssues(name string) []PathIssue {
	if name == "" {
		return []PathIssue{PathEmpty}
	}

	var out []PathIssue
	if !utf8.ValidString(name) {
		out = append(out, PathNonUTF8)
	}
	if hasControl(name) {
		out = append(out, PathControl)
	}
	if isAbsolute(name) {
		out = append(out, PathAbsolute)
	}

	var traversal, dot, reserved, trailing bool
	for _, e := range elements(name) {
		switch e {
		case "..":
			traversal = true
			continue
		case ".":
			dot = true
			continue
		}
		if reservedNames[strings.ToUpper(stem(e))] {
			reserved = true
		}
		if strings.HasSuffix(e, ".") || strings.HasSuffix(e, " ") {
			trailing = true
		}
	}

	if traversal {
		out = append(out, PathTraversal)
	}
	if strings.ContainsRune(name, '\\') {
		out = append(out, PathBackslash)
	}
	if dot {
		out = append(out, PathDotSegment)
	}
	if reserved {
		out = append(out, PathReserved)
	}
	if trailing {
		out = append(out, PathTrailing)
	}
	return out
}

func Escapes(name string) bool {
	if name == "" {
		return false
	}
	if isAbsolute(name) {
		return true
	}
	clean := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	return clean == ".." || strings.HasPrefix(clean, "../")
}

// Backslashes count as separators: an extractor that splits on them is exactly
// the one a smuggled `..\` is aimed at.
func elements(name string) []string {
	return strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' })
}

func isAbsolute(name string) bool {
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return true
	}
	// A drive prefix such as "C:" is absolute or drive-relative; both escape.
	return len(name) >= 2 && name[1] == ':' && isLetter(name[0])
}

func isLetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func hasControl(name string) bool {
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func stem(elem string) string {
	base, _, _ := strings.Cut(elem, ".")
	return base
}
