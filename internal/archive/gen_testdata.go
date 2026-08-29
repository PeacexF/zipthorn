//go:build ignore

// Regenerates the committed fixtures in testdata:
//
//	go run internal/archive/gen_testdata.go internal/archive/testdata
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var stamp = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

type spec struct {
	name   string
	body   []byte
	method uint16
}

func build(specs []spec, comment string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if comment != "" {
		if err := zw.SetComment(comment); err != nil {
			return nil, err
		}
	}
	for _, s := range specs {
		h := &zip.FileHeader{Name: s.name, Method: s.method, Modified: stamp}
		if strings.HasSuffix(s.name, "/") {
			h.SetMode(0o755 | os.ModeDir)
		} else {
			h.SetMode(0o644)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(s.body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	dir := "testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}

	simple, err := build([]spec{
		{"docs/", nil, zip.Store},
		{"docs/readme.txt", bytes.Repeat([]byte("zipthorn "), 64), zip.Deflate},
		{"docs/notes.txt", []byte("plain"), zip.Store},
		{"top.bin", bytes.Repeat([]byte{0xAB}, 512), zip.Deflate},
	}, "")
	if err != nil {
		panic(err)
	}

	inner, err := build([]spec{
		{"payload.txt", bytes.Repeat([]byte("A"), 4096), zip.Deflate},
	}, "")
	if err != nil {
		panic(err)
	}

	nested, err := build([]spec{
		{"bundle/inner.zip", inner, zip.Store},
		{"a/b/c/d/e/deep.txt", []byte("deep"), zip.Deflate},
		{"dup.txt", []byte("first"), zip.Store},
		{"dup.txt", []byte("second"), zip.Store},
	}, "zipthorn fixture")
	if err != nil {
		panic(err)
	}

	for name, data := range map[string][]byte{"simple.zip": simple, "nested.zip": nested} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("%s: %d bytes\n", p, len(data))
	}
}
