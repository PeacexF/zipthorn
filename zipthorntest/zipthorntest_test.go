package zipthorntest_test

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PeacexF/zipthorn"
	"github.com/PeacexF/zipthorn/zipthorntest"
)

func TestBomb_ProducesAValidArchive(t *testing.T) {
	data := zipthorntest.Bomb(t, zipthorn.ProfileFileCount, zipthorntest.FileCount(7), zipthorntest.FileSize(32))

	info, err := zipthorn.Inspect(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.FileCount != 7 {
		t.Errorf("FileCount = %d, want 7 (the FileCount option should have applied)", info.FileCount)
	}
}

func TestBomb_IsDeterministic(t *testing.T) {
	a := zipthorntest.Bomb(t, zipthorn.ProfileRatio, zipthorntest.Seed(9))
	b := zipthorntest.Bomb(t, zipthorn.ProfileRatio, zipthorntest.Seed(9))
	if !bytes.Equal(a, b) {
		t.Error("same profile and Seed should produce byte-identical archives")
	}

	c := zipthorntest.Bomb(t, zipthorn.ProfileRatio, zipthorntest.Seed(10))
	if bytes.Equal(a, c) {
		t.Error("a different Seed should produce a different archive")
	}
}

func TestBombFile_WritesToDisk(t *testing.T) {
	dir := t.TempDir()
	path := zipthorntest.BombFile(t, dir, zipthorn.ProfileNested, zipthorntest.Seed(3))

	if filepath.Dir(path) != dir {
		t.Errorf("path = %q, want it under %q", path, dir)
	}

	info, err := zipthorn.InspectFile(path)
	if err != nil {
		t.Fatalf("InspectFile(%q): %v", path, err)
	}
	if info.ArchiveSize == 0 {
		t.Error("BombFile should have written a non-empty archive")
	}
}

// fakeTB is a minimal testing.TB that records Fatalf instead of failing the
// real test, so TestBomb_FailsTestOnUnknownProfile can observe Bomb's
// fail-the-test contract without actually failing itself. A real
// testing.T.Fatalf never returns (it calls runtime.Goexit internally), so
// this one must too — matched here by running Bomb in its own goroutine, the
// same isolation the real testing package gives each test.
type fakeTB struct {
	testing.TB
	failed bool
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	runtime.Goexit()
}

func TestBomb_FailsTestOnUnknownProfile(t *testing.T) {
	tb := &fakeTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		zipthorntest.Bomb(tb, "no-such-profile")
	}()
	<-done

	if !tb.failed {
		t.Error("Bomb should have called Fatalf for an unknown profile")
	}
}
