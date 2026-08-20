package config_test

import (
	"testing"

	"github.com/PeacexF/zipthorn/internal/config"
)

func TestDefaultIsSane(t *testing.T) {
	c := config.Default()

	if c.Limits.MaxOutputBytes <= 0 {
		t.Errorf("MaxOutputBytes = %d, want > 0", c.Limits.MaxOutputBytes)
	}
	if c.Limits.MaxExpansionRatio <= 1 {
		t.Errorf("MaxExpansionRatio = %v, want > 1", c.Limits.MaxExpansionRatio)
	}
	if c.Limits.MaxFiles <= 0 {
		t.Errorf("MaxFiles = %d, want > 0", c.Limits.MaxFiles)
	}
	if c.Limits.MaxDepth <= 0 || c.Limits.MaxNesting <= 0 {
		t.Errorf("depth/nesting limits must be positive: %+v", c.Limits)
	}

	// Thresholds should sit at or below the hard limits so an archive is
	// flagged before it hits an operational ceiling.
	if c.Thresholds.FileCount > c.Limits.MaxFiles {
		t.Errorf("FileCount threshold %d exceeds MaxFiles limit %d",
			c.Thresholds.FileCount, c.Limits.MaxFiles)
	}
	if c.Thresholds.Depth > c.Limits.MaxDepth {
		t.Errorf("Depth threshold %d exceeds MaxDepth limit %d",
			c.Thresholds.Depth, c.Limits.MaxDepth)
	}
	if c.Thresholds.Nesting > c.Limits.MaxNesting {
		t.Errorf("Nesting threshold %d exceeds MaxNesting limit %d",
			c.Thresholds.Nesting, c.Limits.MaxNesting)
	}
}
