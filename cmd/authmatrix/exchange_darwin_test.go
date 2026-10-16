//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// A native Darwin atomic exchange, confined to two synthetic test directories.
func TestDarwinConcurrentAncestorExchange(t *testing.T) {
	d := t.TempDir()
	parent := filepath.Join(d, "parent")
	other := filepath.Join(d, "other")
	link := filepath.Join(d, "exchange")
	for _, p := range []string{parent, other} {
		if e := os.MkdirAll(filepath.Join(p, "nested"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink(other, link); e != nil {
		t.Fatal(e)
	}
	var stop atomic.Bool
	var swaps atomic.Int64
	done := make(chan error, 1)
	go func() {
		for !stop.Load() {
			if e := unix.RenamexNp(parent, link, unix.RENAME_SWAP); e != nil {
				done <- e
				return
			}
			swaps.Add(1)
		}
		done <- nil
	}()
	successes := 0
	for i := 0; i < 200; i++ {
		if e := save(filepath.Join(parent, "nested", fmt.Sprintf("out-%d", i)), []byte("synthetic")); e == nil {
			successes++
		}
	}
	stop.Store(true)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(filepath.Join(other, "nested"))
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 0 {
		t.Fatalf("%d files escaped via symlink ancestor", len(entries))
	}
	if swaps.Load() == 0 {
		t.Fatal("exchange worker never ran")
	}
	t.Logf("attempts=200 exchanges=%d successful writes=%d foreign writes=%d", swaps.Load(), successes, len(entries))
}
