//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
	fd, err := unix.Openat(dfd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	out := os.NewFile(uintptr(fd), base)
	n, werr := out.Write(b)
	cerr := out.Close()
	if werr != nil || cerr != nil || n != len(b) {
		// Never delete by the mutable pathname. Use the same pinned parent.
		_ = unix.Unlinkat(dfd, base, 0)
		return errors.New("write failed")
	}
	return nil
}

// openPinnedOutputParent walks from the filesystem root using directory
// descriptors. O_NOFOLLOW rejects symlinks at every level.
// The returned fd is used for every subsequent write/cleanup operation.
func openPinnedOutputParent(dir string) (*os.File, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.TrimPrefix(filepath.Clean(abs), "/")
	if parts != "" {
		for _, part := range strings.Split(parts, "/") {
			next, e := unix.Openat(fd, part, flags, 0)
			_ = unix.Close(fd)
			if e != nil {
				return nil, e
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), abs), nil
}
