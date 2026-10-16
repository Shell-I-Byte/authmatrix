//go:build !linux && !darwin

package main

import "os"

// The nonblocking Unix FIFO mitigation is platform-specific. On other
// platforms the caller still checks descriptor type/identity after opening.
// A hostile-filesystem Lstat/Open race is not claimed to be resolved here.
func openInputFile(path string) (*os.File, error) { return os.Open(path) }
