//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinAncestorConfinement(t *testing.T) {
	d := t.TempDir()
	real := filepath.Join(d, "real")
	if err := os.MkdirAll(filepath.Join(real, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(d, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if err := save(filepath.Join(alias, "nested", "escaped.json"), []byte("synthetic")); err == nil {
		t.Fatal("accepted symlink ancestor")
	}
	if _, err := os.Lstat(filepath.Join(real, "nested", "escaped.json")); !os.IsNotExist(err) {
		t.Fatalf("output escaped: %v", err)
	}
	if err := save(filepath.Join(real, "nested", "valid-ë.json"), []byte("valid")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(real, "nested", "valid-ë.json"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", st, err)
	}
}
