// Package config defines zipthorn's resource limits and detection thresholds.
package config

// Limits bounds any operation that generates or extracts archive data.
type Limits struct {
	MaxOutputBytes    int64   `json:"max_output_bytes"`
	MaxExpansionRatio float64 `json:"max_expansion_ratio"` // declared / compressed
	MaxFiles          int64   `json:"max_files"`
	MaxDepth          int     `json:"max_depth"`   // directory nesting
	MaxNesting        int     `json:"max_nesting"` // archive-within-archive
}

// Thresholds are the detection engine's decision boundaries. Each value is the
// point at or above which a characteristic is treated as HIGH risk.
type Thresholds struct {
	ExpansionRatio float64 `json:"expansion_ratio"`
	DeclaredSize   int64   `json:"declared_size"`
	FileCount      int64   `json:"file_count"`
	Depth          int     `json:"depth"`
	Nesting        int     `json:"nesting"`
}

type Config struct {
	Limits     Limits     `json:"limits"`
	Thresholds Thresholds `json:"thresholds"`
}

const (
	KB int64 = 1 << 10
	MB int64 = 1 << 20
	GB int64 = 1 << 30
)

func Default() Config {
	return Config{
		Limits: Limits{
			MaxOutputBytes:    256 * MB,
			MaxExpansionRatio: 100,
			MaxFiles:          10_000,
			MaxDepth:          32,
			MaxNesting:        4,
		},
		Thresholds: Thresholds{
			ExpansionRatio: 50,
			DeclaredSize:   1 * GB,
			FileCount:      10_000,
			Depth:          16,
			Nesting:        2,
		},
	}
}
