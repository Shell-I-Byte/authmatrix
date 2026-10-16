//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// save traverses each output-directory component relative to an already-open
// directory descriptor with O_NOFOLLOW. This prevents an attacker from
// introducing a symlink at an ancestor during path resolution. The final
// directory descriptor remains pinned for openat/unlinkat. It does not
// prevent privileged bind-mount changes, or renaming the pinned directory itself.
func save(path string, b []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty output path")
	}
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return errors.New("output parent is not a directory")
	}
	parent, err := openPinnedOutputParent(dir)
	if err != nil {
		return errors.New("cannot safely open output parent")
	}
	defer parent.Close()
	dfd := int(parent.Fd())
	opened, err := parent.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(st, opened) {
		return errors.New("output parent changed during open")
	}
	base := filepath.Base(path)
	if base == "." || base == ".." || base == "" {
		return errors.New("invalid output filename")
	}
	fd, err := syscall.Openat(dfd, base, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	out := os.NewFile(uintptr(fd), base)
	n, werr := out.Write(b)
	cerr := out.Close()
	if werr != nil || cerr != nil || n != len(b) {
		// Never delete by the mutable pathname. Use the same pinned parent.
		_ = syscall.Unlinkat(dfd, base)
		return errors.New("write failed")
	}
	return nil
}

// openPinnedOutputParent walks from the filesystem root using directory
// descriptors. O_PATH allows traversing searchable but unreadable directories
// without granting read access; O_NOFOLLOW rejects symlinks at *every* level.
// The returned fd is used for every subsequent write/cleanup operation.
func openPinnedOutputParent(dir string) (*os.File, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// Linux O_PATH (010000000 octal) is intentionally defined locally: the
	// frozen Go 1.23 syscall API does not expose syscall.O_PATH.
	const linuxOPath = 0x200000
	const flags = linuxOPath | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.TrimPrefix(filepath.Clean(abs), "/")
	if parts != "" {
		for _, part := range strings.Split(parts, "/") {
			next, e := syscall.Openat(fd, part, flags, 0)
			_ = syscall.Close(fd)
			if e != nil {
				return nil, e
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), abs), nil
}
