package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PeacexF/zipthorn/internal/cli"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cli.Main(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestNoArgsShowsUsage(t *testing.T) {
	code, _, stderr := run(t)
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr missing usage, got:\n%s", stderr)
	}
}

func TestHelp(t *testing.T) {
	code, stdout, _ := run(t, "--help")
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}
	for _, cmd := range []string{"create", "inspect", "detect", "test"} {
		if !strings.Contains(stdout, cmd) {
			t.Errorf("help missing command %q", cmd)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := run(t, "--version")
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}
	if !strings.Contains(stdout, "zipthorn") {
		t.Errorf("version output = %q", stdout)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := run(t, "bogus")
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestStubsReportUnimplemented(t *testing.T) {
	// All MVP commands are now implemented
	// This test remains as a placeholder for future unimplemented commands
	t.Skip("No unimplemented commands in current milestone")
}

func TestBadFlagIsUsageError(t *testing.T) {
	code, _, _ := run(t, "create", "--nope")
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
}

func TestJSONStubOutput(t *testing.T) {
	// The test command is now implemented, so this test is no longer valid
	t.Skip("test command is now implemented")
}

func TestCommandHelpExitsCleanly(t *testing.T) {
	code, _, stderr := run(t, "inspect", "--help")
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want %d", code, cli.ExitOK)
	}
	if !strings.Contains(stderr, "zipthorn inspect <archive>") {
		t.Errorf("stderr missing command usage:\n%s", stderr)
	}
	if strings.Contains(stderr, "help requested") {
		t.Errorf("help must not surface as an error:\n%s", stderr)
	}
}

// Options must work on either side of the archive path: Go's flag package stops
// at the first operand, so the CLI permutes arguments before parsing.
func TestFlagsMayFollowTheArchivePath(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")

	forms := [][]string{
		{"test", "--max-bytes", "64MB", "--timeout", "5", p},
		{"test", p, "--max-bytes", "64MB", "--timeout", "5"},
		{"test", "--max-bytes", "64MB", p, "--timeout", "5"},
		{"test", p, "--max-bytes=64MB", "--quiet"},
	}

	for _, args := range forms {
		code, stdout, stderr := run(t, args...)
		if code != cli.ExitOK {
			t.Errorf("%v: code = %d, want %d (stdout: %s stderr: %s)",
				args, code, cli.ExitOK, stdout, stderr)
		}
	}
}

// A trailing option must actually take effect, not merely be tolerated.
func TestTrailingFlagIsApplied(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")

	code, stdout, _ := run(t, "test", p, "--max-bytes", "1")
	if code != cli.ExitRisk {
		t.Fatalf("code = %d, want %d (a 1-byte limit must trip)\n%s", code, cli.ExitRisk, stdout)
	}
	if !strings.Contains(stdout, "LIMIT_REACHED") {
		t.Errorf("output should report the limit:\n%s", stdout)
	}
}

// Everything after -- is an operand, even if it looks like a flag.
func TestDoubleDashEndsFlagParsing(t *testing.T) {
	p := writeZip(t, "docs/notes.txt")

	code, _, stderr := run(t, "inspect", "--", p)
	if code != cli.ExitOK {
		t.Errorf("code = %d, want %d (stderr: %s)", code, cli.ExitOK, stderr)
	}
}
