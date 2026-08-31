// Command zipthorn is a defensive ZIP-archive security-testing toolkit for
// generating, analyzing, detecting, and safely testing pathological archives.
package main

import (
	"os"

	"github.com/PeacexF/zipthorn/internal/cli"
)

// Version information set by GoReleaser via ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version, commit, date)
	os.Exit(cli.Run())
}
