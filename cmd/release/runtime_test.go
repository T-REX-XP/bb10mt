package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalProjectText(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.ini")
	for _, input := range []string{"line one\r\nline two\r\n", "line one\nline two\n"} {
		if err := os.WriteFile(p, []byte(input), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := canonicalText(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte("line one\nline two\n")) {
			t.Fatal("noncanonical project text")
		}
	}
}
