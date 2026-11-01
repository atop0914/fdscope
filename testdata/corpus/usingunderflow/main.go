// Command usingunderflow is a stand-in for a descriptor cache whose reference
// count wraps around.
//
// It reproduces the PATTERN of a defect found in nutsdb's
// internal/fileio/fd_manager.go; nothing here is copied from that repository,
// which is not imported (fdscope has no dependencies). The defect is
// FdManager.ReduceUsing: "using" is a uint field on the cache entry and the
// decrement is unguarded, so a second release of the same path takes it from 0 to
// 18446744073709551615 instead of failing. The entry is then permanently "in use",
// cleanUselessFd skips it forever, and its descriptor is never reclaimed - the leak
// is not one big open, it is a close that can no longer happen.
//
// Run with -fixed for the version that refuses to release what nobody holds.
// One guard, one field: the pair isolates the counter from everything else.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type cache struct {
	files map[string]*os.File
	using map[string]uint
	fixed bool
}

func newCache(fixed bool) *cache {
	return &cache{files: map[string]*os.File{}, using: map[string]uint{}, fixed: fixed}
}

// get opens a segment and records that one caller is using it.
func (c *cache) get(path string) error {
	if f, ok := c.files[path]; ok {
		c.using[path]++
		_ = f
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	c.files[path] = f
	c.using[path] = 1
	return nil
}

// reduceUsing says one caller is done with path.
//
// The double release below is not contrived: the same call site runs on the read
// path and again when the segment is rotated out, and the guard is what the
// upstream code was missing.
func (c *cache) reduceUsing(path string) {
	if c.fixed {
		if c.using[path] > 0 {
			c.using[path]--
		}
		return
	}
	c.using[path]-- // unguarded: on uint this wraps to 18446744073709551615
}

// reclaim closes every descriptor nobody is using any more.
func (c *cache) reclaim() int {
	closed := 0
	for path, f := range c.files {
		if c.using[path] != 0 {
			continue
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close %s: %v\n", path, err)
			continue
		}
		delete(c.files, path)
		delete(c.using, path)
		closed++
	}
	return closed
}

func main() {
	fixed := flag.Bool("fixed", false, "guard the decrement so a double release cannot wrap (the corrected cache)")
	flag.Parse()

	dir, err := os.MkdirTemp("", "fdscope-corpus-usingunderflow-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "work dir: %v\n", err)
		os.Exit(1)
	}
	c := newCache(*fixed)
	fmt.Printf("ready %s\n", dir)

	for i := 0; ; i++ {
		// A fresh segment each round, as a write-ahead log does. The entry is
		// opened, used, released twice - and then nobody can ever reclaim it.
		path := filepath.Join(dir, fmt.Sprintf("segment-%06d.wal", i))
		if err := c.get(path); err != nil {
			fmt.Fprintf(os.Stderr, "open segment: %v\n", err)
			os.Exit(1)
		}
		c.reduceUsing(path)
		c.reduceUsing(path)
		c.reclaim()
		time.Sleep(20 * time.Millisecond)
	}
}
