package cli

import (
	"flag"
	"fmt"
	"io"
	"math"
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
const (
	kb int64 = 1 << 10
	mb int64 = 1 << 20
	gb int64 = 1 << 30
	tb int64 = 1 << 40
	pb int64 = 1 << 50
)

var byteUnits = []struct {
	limit int64
	name  string
}{
	{pb, "PB"},
	{tb, "TB"},
	{gb, "GB"},
	{mb, "MB"},
	{kb, "KB"},
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

// Units are binary regardless of spelling, so "KB" and "KiB" both mean 1024.
var byteMultipliers = map[string]int64{
	"": 1, "B": 1,
	"K": kb, "KB": kb, "KIB": kb,
	"M": mb, "MB": mb, "MIB": mb,
	"G": gb, "GB": gb, "GIB": gb,
	"T": tb, "TB": tb, "TIB": tb,
	"P": pb, "PB": pb, "PIB": pb,
}

// parseBytes reads a byte size such as "512", "8MB", or "1.5 GiB".
func parseBytes(s string) (int64, error) {
	t := strings.TrimSpace(s)
	i := 0
	for i < len(t) && (t[i] >= '0' && t[i] <= '9' || t[i] == '.') {
		i++
	}

	digits, unit := t[:i], strings.ToUpper(strings.TrimSpace(t[i:]))
	mult, ok := byteMultipliers[unit]
	if digits == "" || !ok {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	v, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}

	scaled := v * float64(mult)
	if scaled > math.MaxInt64 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return int64(scaled), nil
}

// byteSizeValue adapts parseBytes to the flag package.
type byteSizeValue struct{ p *int64 }

func (b byteSizeValue) String() string {
	if b.p == nil {
		return "0"
	}
	return humanBytes(*b.p)
}

func (b byteSizeValue) Set(s string) error {
	n, err := parseBytes(s)
	if err != nil {
		return err
	}
	*b.p = n
	return nil
}

func sizeVar(fs *flag.FlagSet, p *int64, name, usage string) {
	fs.Var(byteSizeValue{p}, name, usage)
}
