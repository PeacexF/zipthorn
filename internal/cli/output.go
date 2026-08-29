package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitRisk        = 3 // unsafe archive / limit reached — a policy signal, not a crash
	ExitUnsupported = 4
)

// CodedError pairs an error with the process exit code it should produce.
type CodedError struct {
	Code int
	Err  error
}

func (e *CodedError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}
func (e *CodedError) Unwrap() error { return e.Err }

func coded(code int, err error) *CodedError { return &CodedError{Code: code, Err: err} }

func codef(code int, format string, a ...any) *CodedError {
	return &CodedError{Code: code, Err: fmt.Errorf(format, a...)}
}

// output renders command results as either JSON or human-readable text.
type output struct {
	w    io.Writer
	err  io.Writer
	json bool
}

func newOutput(stdout, stderr io.Writer, jsonMode bool) *output {
	return &output{w: stdout, err: stderr, json: jsonMode}
}

func (o *output) JSON() bool { return o.json }

// Emit writes v as JSON in JSON mode, otherwise calls human. human may be nil.
func (o *output) Emit(v any, human func(io.Writer)) error {
	if o.json {
		enc := json.NewEncoder(o.w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	if human != nil {
		human(o.w)
	}
	return nil
}

func (o *output) Line(format string, a ...any) {
	if o.json {
		return
	}
	fmt.Fprintf(o.w, format+"\n", a...)
}
