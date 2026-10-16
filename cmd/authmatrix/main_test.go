package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIVersion(t *testing.T) {
	if got := run([]string{"version"}); got != 0 {
		t.Fatalf("version rc=%d", got)
	}
}
func TestCLIExitCodesAndFileSafety(t *testing.T) {
	d := t.TempDir()
	in := filepath.Join(d, "in.json")
	b, err := os.ReadFile("../../testdata/matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, b, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(d, "out.json")
	if got := run([]string{"evaluate", "-in", in, "-out", out}); got != 1 {
		t.Fatalf("expected potential-bypass rc 1 got %d", got)
	}
	if b, err := os.ReadFile(out); err != nil || !bytes.Contains(b, []byte(`"schema": "authmatrix.result/v1"`)) {
		t.Fatalf("output broken %v", err)
	}
	if got := run([]string{"evaluate", "-in", in, "-out", out}); got != 2 {
		t.Fatalf("overwritten existing evidence rc=%d", got)
	}
	if got := run([]string{"evaluate", "-in", in, "-out", filepath.Join(d, "missing", "o.json")}); got != 2 {
		t.Fatalf("wrong parent rc=%d", got)
	}
	if got := run([]string{"evaluate", "-in", in, "-out", in}); got != 2 {
		t.Fatalf("overwrote input rc=%d", got)
	}
	if got := run([]string{"evaluate", "-in", strings.Repeat("\x1b[0mLOG-FORGE", 2)}); got != 2 {
		t.Fatalf("invalid path rc=%d", got)
	}
	if got := run([]string{"evaluate", "-in", in, "-bad=\n\x1b[0mFAKE-PASS"}); got != 2 {
		t.Fatalf("unsafe flag accepted rc=%d", got)
	}
}
func TestRefuseSymlinkInput(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "file.json")
	if err := os.WriteFile(p, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(d, "link")
	if err := os.Symlink(p, q); err != nil {
		t.Skip(err)
	}
	if _, err := load(q); err == nil {
		t.Fatal("followed symlink")
	}
}

func TestNormalHelpAndInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--help"}, {"evaluate", "-h"}, {"evaluate", "-help"}, {"evaluate", "--help"}} {
		if rc := run(args); rc != 0 {
			t.Errorf("help %v returned %d", args, rc)
		}
	}
	if rc := run([]string{"evaluate", "--not-a-real-flag"}); rc != 2 {
		t.Fatalf("invalid option exit code %d", rc)
	}
}
