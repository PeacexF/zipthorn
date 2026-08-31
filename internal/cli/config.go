package cli

import (
	"fmt"

	"github.com/PeacexF/zipthorn/internal/config"
)

// loadConfig loads configuration respecting the global --config flag
func loadConfig() (config.Config, error) {
	if globalConfigPath != "" {
		cfg, err := config.LoadFrom(globalConfigPath)
		if err != nil {
			return config.Config{}, fmt.Errorf("loading config from %s: %w", globalConfigPath, err)
		}
		return cfg, nil
	}
	
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, fmt.Errorf("loading config: %w", err)
	}
	return cfg, nil
}
