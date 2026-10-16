//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeOutputParentAndNoOverwrite(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "out")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "result.json")
	if err := save(target, []byte("{\"ok\":true}\n")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(target)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("wrong output mode: %v, %v", st, err)
	}
	if err := save(target, []byte("overwrite")); err == nil {
		t.Fatal("existing evidence overwritten")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "{\"ok\":true}\n" {
		t.Fatalf("original changed: %q %v", data, err)
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := save(filepath.Join(link, "linked.json"), []byte("test")); err == nil {
		t.Fatal("symlink output parent accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "linked.json")); !os.IsNotExist(err) {
		t.Fatalf("symlink leaked write: %v", err)
	}
}

// BUG-AM-167-001: RC8 pinned only the final output-parent component, so a
// symlink in an earlier path component could still redirect an evidence write.
func TestRejectSymlinkAncestorAndAllowNestedNormalPath(t *testing.T) {
	tmp := t.TempDir()
	anchor := filepath.Join(tmp, "anchor")
	outside := filepath.Join(tmp, "outside")
	for _, dir := range []string{filepath.Join(anchor, "nested", "reports"), filepath.Join(outside, "nested", "reports")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(anchor, "nested", "reports", "normal.json")
	if err := save(file, []byte("ok")); err != nil {
		t.Fatalf("valid nested parent rejected: %v", err)
	}
	if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("bad normal output: %v, %v", st, err)
	}
	link := filepath.Join(tmp, "ancestor-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(link, "nested", "reports", "escape.json")
	if err := save(bad, []byte("outside")); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
	if _, err := os.Lstat(filepath.Join(outside, "nested", "reports", "escape.json")); !os.IsNotExist(err) {
		t.Fatalf("wrote outside: %v", err)
	}
}
