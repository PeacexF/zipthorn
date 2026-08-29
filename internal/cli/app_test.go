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
	for _, cmd := range []string{"create", "detect", "test"} {
		code, _, _ := run(t, cmd)
		if code != cli.ExitUnsupported {
			t.Errorf("%s: code = %d, want %d", cmd, code, cli.ExitUnsupported)
		}
	}
}

func TestBadFlagIsUsageError(t *testing.T) {
	code, _, _ := run(t, "detect", "--nope")
	if code != cli.ExitUsage {
		t.Fatalf("code = %d, want %d", code, cli.ExitUsage)
	}
}

func TestJSONStubOutput(t *testing.T) {
	code, stdout, _ := run(t, "detect", "--json")
	if code != cli.ExitUnsupported {
		t.Fatalf("code = %d, want %d", code, cli.ExitUnsupported)
	}
	if !strings.Contains(stdout, `"status": "not_implemented"`) {
		t.Errorf("stdout = %q", stdout)
	}
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
