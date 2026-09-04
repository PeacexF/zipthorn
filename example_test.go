package zipthorn_test

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/PeacexF/zipthorn"
)

// Example_uploadGate is the package doc's headline flow, made runnable:
// gate an upload by inspecting, assessing, and — if it passes — extracting
// it, all in one call and one pass over the archive.
func Example_uploadGate() {
	// Stand in for an upload with a small, well-formed archive. A real
	// caller already has bytes from disk, memory, or a multipart.File.
	var archive bytes.Buffer
	if _, err := zipthorn.Generate(&archive, zipthorn.Spec{
		Profile: zipthorn.ProfileFileCount, Seed: 1, FileCount: 2, FileSize: 16,
		Limits: zipthorn.DefaultConfig().Limits,
	}); err != nil {
		fmt.Println(err)
		return
	}
	data := archive.Bytes()

	dest, err := os.MkdirTemp("", "zipthorn-example")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.RemoveAll(dest)

	opts := zipthorn.DefaultGuardOptions()
	opts.Sink = zipthorn.DirSink(dest)

	res, err := zipthorn.Guard(context.Background(), bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		fmt.Println(err) // unparseable is a rejection, not a retry
		return
	}
	if !res.OK() {
		fmt.Println("rejected:", res.Reason())
		return
	}
	fmt.Println(res.Extract.Status, res.Extract.FilesProcessed)
	// Output:
	// PASS 2
}
