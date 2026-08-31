package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/PeacexF/zipthorn/internal/detector"
)

func runPolicyCmd(args []string, stdout, stderr io.Writer) error {
	code := runPolicy(stdout, stderr, args)
	if code != ExitOK {
		return &CodedError{Code: code}
	}
	return nil
}

func runPolicy(stdout, stderr io.Writer, args []string) int {
	var (
		cf      commonFlags
		listAll bool
	)

	fs := newFlagSet("policy", stderr, &cf)
	fs.BoolVar(&listAll, "list", false, "List all available policies")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}

	if listAll {
		names := detector.ListPolicies()
		if cf.json {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(names); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
				return ExitError
			}
			return ExitOK
		}
		for _, name := range names {
			p, _ := detector.GetPolicy(name)
			fmt.Fprintf(stdout, "%s - %s\n", name, p.Description)
		}
		return ExitOK
	}

	args = fs.Args()
	if len(args) == 0 {
		fmt.Fprintf(stderr, "usage: zipthorn policy [--list] [--json] <policy-name>\n")
		return ExitError
	}

	policyName := args[0]
	p, err := detector.GetPolicy(policyName)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitError
	}

	if cf.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(p); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	fmt.Fprintf(stdout, "Policy: %s\n", p.Name)
	fmt.Fprintf(stdout, "Description: %s\n\n", p.Description)
	fmt.Fprintf(stdout, "Thresholds:\n")
	fmt.Fprintf(stdout, "  Expansion Ratio: %.0fx\n", p.Thresholds.ExpansionRatio)
	fmt.Fprintf(stdout, "  Declared Size:   %s\n", bytesText(p.Thresholds.DeclaredSize))
	fmt.Fprintf(stdout, "  File Count:      %d\n", p.Thresholds.FileCount)
	fmt.Fprintf(stdout, "  Depth:           %d\n", p.Thresholds.Depth)
	fmt.Fprintf(stdout, "  Nesting:         %d\n", p.Thresholds.Nesting)

	if len(p.Disabled) > 0 {
		fmt.Fprintf(stdout, "\nDisabled Rules:\n")
		for rule := range p.Disabled {
			fmt.Fprintf(stdout, "  - %s\n", rule)
		}
	}

	return ExitOK
}

func bytesText(n int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
		TB = 1 << 40
		PB = 1 << 50
	)
	units := []struct {
		limit int64
		name  string
	}{
		{PB, "PB"}, {TB, "TB"}, {GB, "GB"}, {MB, "MB"}, {KB, "KB"},
	}
	for _, u := range units {
		if n >= u.limit {
			v := float64(n) / float64(u.limit)
			if v == float64(int64(v)) {
				return fmt.Sprintf("%d %s", int64(v), u.name)
			}
			return fmt.Sprintf("%.1f %s", v, u.name)
		}
	}
	return fmt.Sprintf("%d B", n)
}
