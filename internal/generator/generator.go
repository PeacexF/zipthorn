// Package generator builds bounded, deterministic pathological ZIP fixtures
//
// Generation is fail-closed: a plan that would exceed the configured limits is rejected
package generator

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

// Profiles, each shaping the archive around one pathological characteristic.
const (
	ProfileRatio     = "ratio"
	ProfileFileCount = "file-count"
	ProfileNested    = "nested"
	ProfileDepth     = "depth"
	ProfileMetadata  = "metadata"
	ProfileMixed     = "mixed"
	ProfileFuzz      = "fuzz"
)

var profileNames = []string{
	ProfileRatio, ProfileFileCount, ProfileNested,
	ProfileDepth, ProfileMetadata, ProfileMixed, ProfileFuzz,
}

func Profiles() []string { return append([]string(nil), profileNames...) }

// LevelDefault selects the standard deflate setting.
const LevelDefault = flate.DefaultCompression

var (
	ErrUnknownProfile = errors.New("unknown profile")
	ErrLimitExceeded  = errors.New("safety limit exceeded")
)

// stamp is fixed so that a seed and a spec fully determine the output bytes.
var stamp = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// Every shape field is optional
type Spec struct {
	Profile      string
	Seed         int64
	DeclaredSize int64   // total uncompressed bytes to generate
	FileCount    int64   // entries to generate
	FileSize     int64   // uncompressed size of one generated entry
	Ratio        float64 // target expansion of generated payloads
	Depth        int     // directory nesting
	Nesting      int     // archive-within-archive levels
	Level        int     // deflate level 1..9, or LevelDefault; 0 also means default
	Limits       config.Limits
}

type Result struct {
	Path           string        `json:"path,omitempty"`
	Profile        string        `json:"profile"`
	Seed           int64         `json:"seed"`
	ArchiveSize    int64         `json:"archive_size"`
	DeclaredSize   int64         `json:"declared_size"`
	ExpansionRatio float64       `json:"expansion_ratio"`
	FileCount      int64         `json:"file_count"`
	DirCount       int64         `json:"dir_count"`
	MaxDepth       int           `json:"max_depth"`
	Nesting        int           `json:"nesting"`
	Limits         config.Limits `json:"limits"`
}

// Generate writes a fixture matching s to w.
func Generate(w io.Writer, s Spec) (*Result, error) {
	s, err := resolve(s)
	if err != nil {
		return nil, err
	}

	p, err := buildPlan(s)
	if err != nil {
		return nil, err
	}
	st := p.stats()
	if err := checkPlan(st, s.Limits); err != nil {
		return nil, err
	}

	cw := &countingWriter{w: w}
	g := &gen{
		rng:   rand.New(rand.NewPCG(uint64(s.Seed), 0x9E3779B97F4A7C15)),
		level: s.Level,
		limit: s.Limits.MaxOutputBytes,
	}
	if err := g.writePlan(cw, p); err != nil {
		return nil, err
	}

	res := &Result{
		Profile:        s.Profile,
		Seed:           s.Seed,
		ArchiveSize:    cw.n,
		DeclaredSize:   g.declared,
		ExpansionRatio: archive.Ratio(g.declared, cw.n),
		FileCount:      st.files,
		DirCount:       st.dirs,
		MaxDepth:       st.depth,
		Nesting:        st.nesting,
		Limits:         s.Limits,
	}
	// Compressibility is only approximated, so the achieved ratio is checked
	// against the limit the same way the requested one was.
	if lim := s.Limits.MaxExpansionRatio; lim > 0 && res.ExpansionRatio > lim {
		return nil, fmt.Errorf("%w: generated archive expands %.1fx, above the %.1fx maximum",
			ErrLimitExceeded, res.ExpansionRatio, lim)
	}
	return res, nil
}

func resolve(s Spec) (Spec, error) {
	if s.Profile == "" {
		s.Profile = ProfileRatio
	}
	if !known(s.Profile) {
		return s, fmt.Errorf("%w %q (want one of: %s)",
			ErrUnknownProfile, s.Profile, strings.Join(profileNames, ", "))
	}
	if s.Level == 0 {
		s.Level = LevelDefault
	}
	if s.Level < flate.HuffmanOnly || s.Level > flate.BestCompression {
		return s, fmt.Errorf("compression level %d out of range (%d..%d)",
			s.Level, flate.HuffmanOnly, flate.BestCompression)
	}
	if s.Limits == (config.Limits{}) {
		s.Limits = config.Default().Limits
	}
	s = withDefaults(s)

	if lim := s.Limits.MaxExpansionRatio; lim > 0 && s.Ratio > lim {
		return s, fmt.Errorf("%w: requested %.1fx expansion, above the %.1fx maximum",
			ErrLimitExceeded, s.Ratio, lim)
	}
	return s, nil
}

func known(profile string) bool {
	for _, p := range profileNames {
		if p == profile {
			return true
		}
	}
	return false
}

// gen carries the generation state shared across nesting levels.
type gen struct {
	rng      *rand.Rand
	level    int
	limit    int64 // declared-byte budget; non-positive disables it
	declared int64
}

func (g *gen) writePlan(w io.Writer, p *plan) error {
	zw := zip.NewWriter(w)
	if p.comment != "" {
		if err := zw.SetComment(p.comment); err != nil {
			return err
		}
	}
	if g.level != LevelDefault {
		zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(w, g.level)
		})
	}
	for _, it := range p.items {
		if err := g.writeItem(zw, it); err != nil {
			return err
		}
	}
	return zw.Close()
}

func (g *gen) writeItem(zw *zip.Writer, it item) error {
	h := &zip.FileHeader{Name: it.name, Method: zip.Deflate, Modified: stamp, Comment: it.comment}
	switch {
	case it.dir:
		h.Method = zip.Store
		h.SetMode(0o755 | fs.ModeDir)
	case it.store:
		h.Method = zip.Store
		h.SetMode(0o644)
	default:
		h.SetMode(0o644)
	}

	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}

	switch {
	case it.dir:
		return nil
	case it.nested != nil:
		// The inner archive's own payload is what a recursive extraction
		// produces, so only that is charged against the budget.
		var buf bytes.Buffer
		if err := g.writePlan(&buf, it.nested); err != nil {
			return err
		}
		_, err = w.Write(buf.Bytes())
		return err
	case it.body != nil:
		if err := g.spend(int64(len(it.body))); err != nil {
			return err
		}
		_, err = w.Write(it.body)
		return err
	default:
		if err := g.spend(it.size); err != nil {
			return err
		}
		return newFiller(g.rng, it.ratio).writeTo(w, it.size)
	}
}

func (g *gen) spend(n int64) error {
	g.declared += n
	if g.limit > 0 && g.declared > g.limit {
		return fmt.Errorf("%w: generation would produce more than %d bytes of output",
			ErrLimitExceeded, g.limit)
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
