//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenInputFileNonblockingAndTypeSafe(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.json")
	fifo := filepath.Join(dir, "fifo")
	link := filepath.Join(dir, "fifo-link")
	if err := os.WriteFile(regular, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, link} {
		done := make(chan error, 1)
		go func() {
			f, err := openInputFile(p)
			if err == nil {
				defer f.Close()
				_, err = f.Stat()
			}
			done <- err
		}()
		select {
		case err := <-done:
			// Direct FIFO may be opened O_NONBLOCK but must be rejected by load.
			if p == link && err == nil {
				t.Fatal("followed symlink")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("nonblocking open hung on %q", p)
		}
		if _, err := load(p); err == nil {
			t.Fatalf("accepted nonregular input %q", p)
		}
	}
	if _, err := load(regular); err != nil {
		t.Fatalf("rejected regular: %v", err)
	}
}
