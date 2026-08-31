package generator

import (
	"fmt"
	"strings"

	"github.com/PeacexF/zipthorn/internal/archive"
	"github.com/PeacexF/zipthorn/internal/config"
)

// item is one entry to write. Exactly one of nested, body, or a generated
// payload of size bytes supplies its content.
type item struct {
	name    string
	dir     bool
	store   bool
	size    int64
	ratio   float64
	body    []byte
	nested  *plan
	comment string
}

// plan is one archive's worth of entries; nested items carry plans of their own.
type plan struct {
	comment string
	items   []item
}

// stats is what the limits are checked against, summed across nesting levels.
type stats struct {
	files    int64
	dirs     int64
	declared int64
	depth    int
	nesting  int
}

func (p *plan) stats() stats {
	var st stats
	for _, it := range p.items {
		if d := archive.Depth(it.name); d > st.depth {
			st.depth = d
		}
		switch {
		case it.dir:
			st.dirs++
		case it.nested != nil:
			st.files++
			sub := it.nested.stats()
			st.files += sub.files
			st.dirs += sub.dirs
			st.declared += sub.declared
			// Depth restarts inside a nested archive rather than accumulating.
			if sub.depth > st.depth {
				st.depth = sub.depth
			}
			if sub.nesting+1 > st.nesting {
				st.nesting = sub.nesting + 1
			}
		case it.body != nil:
			st.files++
			st.declared += int64(len(it.body))
		default:
			st.files++
			st.declared += it.size
		}
	}
	return st
}

func checkPlan(st stats, l config.Limits) error {
	switch {
	case l.MaxOutputBytes > 0 && st.declared > l.MaxOutputBytes:
		return fmt.Errorf("%w: would produce %d bytes of output, above the %d-byte maximum",
			ErrLimitExceeded, st.declared, l.MaxOutputBytes)
	case l.MaxFiles > 0 && st.files > l.MaxFiles:
		return fmt.Errorf("%w: would generate %d files, above the %d-file maximum",
			ErrLimitExceeded, st.files, l.MaxFiles)
	case l.MaxDepth > 0 && st.depth > l.MaxDepth:
		return fmt.Errorf("%w: would nest directories %d deep, above the maximum of %d",
			ErrLimitExceeded, st.depth, l.MaxDepth)
	case l.MaxNesting > 0 && st.nesting > l.MaxNesting:
		return fmt.Errorf("%w: would nest archives %d deep, above the maximum of %d",
			ErrLimitExceeded, st.nesting, l.MaxNesting)
	}
	return nil
}

type number interface{ ~int | ~int64 | ~float64 }

func orDefault[T number](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

func within[T number](v, limit T) T {
	if limit > 0 && v > limit {
		return limit
	}
	return v
}

// defaultRatio leaves headroom under the expansion limit, since a payload's
// achieved ratio only approximates the one it was built for.
func defaultRatio(l config.Limits) float64 {
	const target = 80
	return within(float64(target), l.MaxExpansionRatio*0.8)
}

func withDefaults(s Spec) Spec {
	l := s.Limits
	switch s.Profile {
	case ProfileRatio:
		s.FileCount = orDefault(s.FileCount, 1)
		s.DeclaredSize = orDefault(s.DeclaredSize, within(32*config.MB, l.MaxOutputBytes))
		s.Ratio = orDefault(s.Ratio, defaultRatio(l))
	case ProfileFileCount:
		s.FileCount = orDefault(s.FileCount, within(int64(10_000), l.MaxFiles))
		s.FileSize = orDefault(s.FileSize, 64)
		s.Ratio = orDefault(s.Ratio, 4)
	case ProfileNested:
		s.Nesting = orDefault(s.Nesting, within(3, l.MaxNesting))
		s.DeclaredSize = orDefault(s.DeclaredSize, within(8*config.MB, l.MaxOutputBytes))
		s.Ratio = orDefault(s.Ratio, defaultRatio(l))
	case ProfileDepth:
		s.Depth = orDefault(s.Depth, within(20, l.MaxDepth))
		s.FileSize = orDefault(s.FileSize, config.KB)
	case ProfileMetadata:
		s.FileSize = orDefault(s.FileSize, 256)
	case ProfileMixed:
		s.DeclaredSize = orDefault(s.DeclaredSize, within(8*config.MB, l.MaxOutputBytes*3/4))
		s.FileCount = orDefault(s.FileCount, within(int64(256), l.MaxFiles-mixedFixedEntries))
		s.FileSize = orDefault(s.FileSize, 512)
		s.Depth = orDefault(s.Depth, within(8, l.MaxDepth))
		s.Nesting = orDefault(s.Nesting, within(2, l.MaxNesting))
		s.Ratio = orDefault(s.Ratio, defaultRatio(l))
	case ProfileFuzz:
		// Fuzz uses seed-driven randomization with safe defaults
		s.DeclaredSize = orDefault(s.DeclaredSize, within(4*config.MB, l.MaxOutputBytes/2))
		s.FileCount = orDefault(s.FileCount, within(int64(100), l.MaxFiles/2))
		s.FileSize = orDefault(s.FileSize, 512)
		s.Depth = orDefault(s.Depth, within(6, l.MaxDepth/2))
		s.Nesting = orDefault(s.Nesting, within(1, l.MaxNesting/2))
		s.Ratio = orDefault(s.Ratio, within(20, l.MaxExpansionRatio/2))
	}
	return s
}

func buildPlan(s Spec) (*plan, error) {
	switch s.Profile {
	case ProfileRatio:
		return ratioPlan(s), nil
	case ProfileFileCount:
		return fileCountPlan(s), nil
	case ProfileNested:
		return nestedPlan(s), nil
	case ProfileDepth:
		return depthPlan(s), nil
	case ProfileMetadata:
		return metadataPlan(s), nil
	case ProfileMixed:
		return mixedPlan(s), nil
	case ProfileFuzz:
		return fuzzPlan(s), nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownProfile, s.Profile)
}

func ratioPlan(s Spec) *plan {
	p := &plan{comment: "zipthorn ratio fixture"}
	p.items = append(p.items, item{name: "payload/", dir: true})
	p.items = append(p.items, blobs(s.DeclaredSize, s.FileCount, s.Ratio)...)
	return p
}

// blobs splits size evenly across n entries, giving the remainder to the first.
func blobs(size, n int64, ratio float64) []item {
	if n < 1 {
		n = 1
	}
	each, rem := size/n, size%n
	out := make([]item, 0, n)
	for i := int64(0); i < n; i++ {
		b := each
		if i < rem {
			b++
		}
		out = append(out, item{
			name:  fmt.Sprintf("payload/blob-%04d.bin", i),
			size:  b,
			ratio: ratio,
		})
	}
	return out
}

// bucket keeps a large flat entry count out of one enormous directory.
const bucket = 100

// mixedFixedEntries is how many files mixedPlan writes besides its small-file
// run: the payload blob, the deep leaf, two duplicates, one escaping name, and
// the nested archive with its own payload.
const mixedFixedEntries = 7

func fileCountPlan(s Spec) *plan {
	p := &plan{comment: "zipthorn file-count fixture"}
	for i := int64(0); i < s.FileCount; i++ {
		if i%bucket == 0 {
			p.items = append(p.items, item{name: fmt.Sprintf("files/%04d/", i/bucket), dir: true})
		}
		p.items = append(p.items, item{
			name:  fmt.Sprintf("files/%04d/f%06d.dat", i/bucket, i),
			size:  s.FileSize,
			ratio: s.Ratio,
		})
	}
	return p
}

func depthPlan(s Spec) *plan {
	p := &plan{comment: "zipthorn depth fixture"}
	p.items = chain("", s.Depth, s.FileSize)
	return p
}

// chain builds a single directory run prefix/d01/d02/... ending in a leaf file.
func chain(prefix string, depth int, size int64) []item {
	out := make([]item, 0, depth+1)
	var b strings.Builder
	b.WriteString(prefix)
	for i := 1; i <= depth; i++ {
		fmt.Fprintf(&b, "d%02d/", i)
		out = append(out, item{name: b.String(), dir: true})
	}
	return append(out, item{name: b.String() + "leaf.txt", size: size, ratio: 2})
}

func nestedPlan(s Spec) *plan {
	return wrap(s.Nesting, s.DeclaredSize, s.Ratio)
}

// wrap builds levels archives nested one inside the next, the innermost
// holding a single payload.
func wrap(levels int, size int64, ratio float64) *plan {
	p := &plan{
		comment: "zipthorn nested payload",
		items:   []item{{name: "payload.bin", size: size, ratio: ratio}},
	}
	for i := levels; i >= 1; i-- {
		p = &plan{
			comment: fmt.Sprintf("zipthorn nested fixture (level %d)", i),
			items: []item{
				{name: fmt.Sprintf("level-%02d/", i), dir: true},
				{name: fmt.Sprintf("level-%02d/inner.zip", i), store: true, nested: p},
			},
		}
	}
	return p
}

// The metadata profile exercises an extractor's name handling: every entry
// below is legal ZIP that a careless extractor mishandles.
func metadataPlan(s Spec) *plan {
	names := []string{
		"normal.txt",
		"../escape.txt",
		"/absolute.txt",
		`..\windows.txt`,
		"./dot-segment.txt",
		"CON.txt",
		"trailing./leaf.txt",
		"control\x01name.txt",
	}
	p := &plan{comment: "zipthorn metadata fixture"}
	for _, n := range names {
		p.items = append(p.items, item{name: n, size: s.FileSize, ratio: 2})
	}
	p.items = append(p.items,
		item{name: "dup.txt", size: s.FileSize, ratio: 2, comment: "first"},
		item{name: "dup.txt", size: s.FileSize, ratio: 2, comment: "second"},
	)
	return p
}

func mixedPlan(s Spec) *plan {
	p := &plan{comment: "zipthorn mixed fixture"}
	p.items = append(p.items, item{name: "payload/", dir: true})
	p.items = append(p.items, blobs(s.DeclaredSize, 1, s.Ratio)...)

	p.items = append(p.items, item{name: "files/", dir: true})
	for i := int64(0); i < s.FileCount; i++ {
		p.items = append(p.items, item{
			name:  fmt.Sprintf("files/f%05d.dat", i),
			size:  s.FileSize,
			ratio: 4,
		})
	}

	p.items = append(p.items, item{name: "deep/", dir: true})
	p.items = append(p.items, chain("deep/", s.Depth-1, s.FileSize)...)

	p.items = append(p.items,
		item{name: "dup.txt", size: s.FileSize, ratio: 2},
		item{name: "dup.txt", size: s.FileSize, ratio: 2},
		item{name: "../escape.txt", size: s.FileSize, ratio: 2},
	)

	if s.Nesting > 0 {
		p.items = append(p.items, item{
			name:   "bundle/inner.zip",
			store:  true,
			nested: wrap(s.Nesting-1, s.FileSize*8, s.Ratio),
		})
	}
	return p
}

// fuzzPlan produces randomized combinations for robustness testing.
// Uses the seed to generate varied but deterministic fixtures.
func fuzzPlan(s Spec) *plan {
	p := &plan{comment: "zipthorn fuzz fixture"}

	// Use a local RNG seeded from the spec to make mutations deterministic
	rng := newFuzzRNG(s.Seed)

	// Randomize declared size within limits (50-100% of requested)
	declaredSize := s.DeclaredSize/2 + rng.int64n(s.DeclaredSize/2)

	// Randomize file count (50-100% of requested)
	fileCount := s.FileCount/2 + rng.int64n(s.FileCount/2+1)
	if fileCount < 1 {
		fileCount = 1
	}

	// Randomize ratio (50-100% of requested)
	ratio := s.Ratio/2 + rng.float64()*s.Ratio/2
	if ratio < 1 {
		ratio = 1
	}

	// Add payload blobs with randomized characteristics
	if declaredSize > 0 {
		p.items = append(p.items, item{name: "payload/", dir: true})
		blobCount := int64(1) + rng.int64n(fileCount/4+1)
		if blobCount > fileCount {
			blobCount = fileCount
		}
		p.items = append(p.items, blobs(declaredSize/2, blobCount, ratio)...)
	}

	// Add small files with varied sizes
	if fileCount > 0 {
		p.items = append(p.items, item{name: "files/", dir: true})
		smallCount := fileCount / 4
		if smallCount < 1 {
			smallCount = 1
		}
		for i := int64(0); i < smallCount; i++ {
			// Randomize file sizes
			size := s.FileSize/2 + rng.int64n(s.FileSize)
			if size < 1 {
				size = 1
			}
			p.items = append(p.items, item{
				name:  fmt.Sprintf("files/f%05d.dat", i),
				size:  size,
				ratio: 2 + rng.float64()*4,
			})
		}
	}

	// Add depth with randomization
	if s.Depth > 0 {
		p.items = append(p.items, item{name: "deep/", dir: true})
		depth := 1 + rng.intn(s.Depth)
		if depth > s.Depth {
			depth = s.Depth
		}
		p.items = append(p.items, chain("deep/", depth, s.FileSize)...)
	}

	// Sometimes add problematic filenames
	if rng.intn(2) == 0 {
		names := []string{"../escape.txt", "./dot.txt", "dup.txt"}
		idx := rng.intn(len(names))
		p.items = append(p.items, item{
			name:  names[idx],
			size:  s.FileSize,
			ratio: 2,
		})
	}

	// Sometimes add duplicates
	if rng.intn(3) == 0 {
		p.items = append(p.items,
			item{name: "dup.txt", size: s.FileSize, ratio: 2},
			item{name: "dup.txt", size: s.FileSize, ratio: 2},
		)
	}

	// Sometimes add nesting
	if s.Nesting > 0 && rng.intn(2) == 0 {
		nestLevel := 1 + rng.intn(s.Nesting)
		if nestLevel > s.Nesting {
			nestLevel = s.Nesting
		}
		p.items = append(p.items, item{
			name:   "nested/inner.zip",
			store:  true,
			nested: wrap(nestLevel-1, s.FileSize*4, ratio),
		})
	}

	return p
}

// fuzzRNG wraps deterministic random generation for fuzz plans
type fuzzRNG struct {
	state uint64
}

func newFuzzRNG(seed int64) *fuzzRNG {
	return &fuzzRNG{state: uint64(seed) ^ 0x123456789ABCDEF0}
}

func (r *fuzzRNG) next() uint64 {
	// Simple LCG for deterministic randomization
	r.state = r.state*6364136223846793005 + 1442695040888963407
	return r.state
}

func (r *fuzzRNG) int64n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return int64(r.next() % uint64(n))
}

func (r *fuzzRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

func (r *fuzzRNG) float64() float64 {
	return float64(r.next()&0x1FFFFFFFFFFFFF) / float64(0x1FFFFFFFFFFFFF)
}
