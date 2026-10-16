//go:build linux || darwin

package main

import (
	"os"
	"syscall"
)

// openInputFile prevents FIFO swap hangs between the initial Lstat and open.
// O_NOFOLLOW additionally rejects a symlink installed in that window.
// The caller revalidates type and identity using the opened descriptor.
func openInputFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
