//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The fallback retains the existing checks but does not guarantee protection
// against an adversary that renames ancestor directories during a write.
func save(path string, b []byte) error {
	// Refuse existing files (including links). Caller never overwrites evidence.
	if strings.TrimSpace(path) == "" {
		return errors.New("empty output path")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return errors.New("output parent is not a directory")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil || n != len(b) {
		os.Remove(path)
		return errors.New("write failed")
	}
	return nil
}
