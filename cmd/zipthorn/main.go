// Command zipthorn is a defensive ZIP-archive security-testing toolkit for
// generating, analyzing, detecting, and safely testing pathological archives.
package main

import (
	"os"

	"github.com/PeacexF/zipthorn/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
