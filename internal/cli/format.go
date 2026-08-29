package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// labelWidth keeps every report's values in one column.
const labelWidth = 18

func section(w io.Writer, name string) { fmt.Fprintf(w, "\n%s\n", name) }

func field(w io.Writer, label, value string) {
	fmt.Fprintf(w, "  %-*s%s\n", labelWidth, label+":", value)
}

// Byte units are binary, matching config's KB/MB/GB constants.
var byteUnits = []struct {
	limit int64
	name  string
}{
	{1 << 50, "PB"},
	{1 << 40, "TB"},
	{1 << 30, "GB"},
	{1 << 20, "MB"},
	{1 << 10, "KB"},
}

func humanBytes(n int64) string {
	if n < 0 {
		return "-"
	}
	for _, u := range byteUnits {
		if n >= u.limit {
			return trimZero(fmt.Sprintf("%.1f", float64(n)/float64(u.limit))) + " " + u.name
		}
	}
	return fmt.Sprintf("%d B", n)
}

func humanRatio(r float64) string {
	if r <= 0 {
		return "n/a"
	}
	if r >= 100 {
		return fmt.Sprintf("%.0fx", r)
	}
	return trimZero(fmt.Sprintf("%.1f", r)) + "x"
}

// humanCount groups digits so six-figure entry counts stay readable.
func humanCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")

	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return humanCount(n) + " " + one
	}
	return humanCount(n) + " " + many
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }
