// Command panicunknown is a stand-in for a descriptor cache that panics instead
// of reporting a bad release.
//
// It reproduces the PATTERN of a defect found in nutsdb's
// internal/fileio/fd_manager.go; nothing here is copied from that repository,
// which is not imported (fdscope has no dependencies). The defect is
// FdManager.ReduceUsing: the release path looks the path up in the cache and, when
// it is absent, panics with "unexpected the node is not in cache" instead of
// reporting it. Every release after a rotation that dropped the entry, or a second
// release of the same path, takes the whole process down.
//
// This fixture exists for one assertion, and it is the most important one in the
// corpus: a process that disappears mid-window must make a check FAIL, never
// pass. The descriptors held before the panic are released by the kernel, so a
// sampler that accepted "the fd set is now empty" as a measurement would report
// the leak as fixed - the tool's conclusion inverted at the exact moment it
// matters most.
//
// Run with -fixed for the version that reports the bad release and stays alive.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrNotCached reports a release of a path the cache does not hold.
var ErrNotCached = errors.New("path is not in the descriptor cache")

// held is how many descriptors the fixture opens before hitting the bad release.
const held = 40

type fdEntry struct {
	file  *os.File
	using uint
}

type cache struct {
	entries map[string]*fdEntry
	fixed   bool
}

func newCache(fixed bool) *cache {
	return &cache{entries: map[string]*fdEntry{}, fixed: fixed}
}

func (c *cache) get(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	c.entries[path] = &fdEntry{file: f, using: 1}
	return nil
}

// reduceUsing releases one holder of path.
func (c *cache) reduceUsing(path string) error {
	e := c.entries[path]
	if c.fixed {
		if e == nil {
			return fmt.Errorf("release %s: %w", path, ErrNotCached)
		}
		if e.using == 0 {
			return fmt.Errorf("release %s: %w", path, ErrNotCached)
		}
		e.using--
		return nil
	}
	if e == nil {
		// Upstream panics here on purpose, with this wording:
		//   panic(fmt.Errorf("unexpected the node is not in cache %s", cleanPath))
		// The pattern being reproduced is the decision to panic, not the sentence:
		// a release of something nobody holds kills the process instead of being
		// reported.
		panic(fmt.Errorf("unexpected the node is not in cache %s", path))
	}
	e.using--
	return nil
}

// closeAll releases what the cache still holds.
func (c *cache) closeAll() {
	for path, e := range c.entries {
		if err := e.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close %s: %v\n", path, err)
		}
		delete(c.entries, path)
	}
}

func main() {
	fixed := flag.Bool("fixed", false, "report an unknown release instead of dereferencing it (the corrected cache)")
	flag.Parse()

	dir, err := os.MkdirTemp("", "fdscope-corpus-panicunknown-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "work dir: %v\n", err)
		os.Exit(1)
	}
	c := newCache(*fixed)
	fmt.Printf("ready %s\n", dir)

	// Hold a set of descriptors first, so the process really is growing before it
	// dies. Without this the case would only prove that a check notices a dead
	// process, not that it refuses to explain one.
	for i := 0; i < held; i++ {
		if err := c.get(filepath.Join(dir, fmt.Sprintf("page-%03d.idx", i))); err != nil {
			fmt.Fprintf(os.Stderr, "open page: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A release for a path that was never cached - the shape of a caller that
	// releases twice, or releases after a rotation dropped the entry.
	if err := c.reduceUsing(filepath.Join(dir, "never-cached.page")); err != nil {
		fmt.Fprintf(os.Stderr, "release: %v\n", err)
		c.closeAll()
		fmt.Println("recovered")
		for {
			time.Sleep(time.Second)
		}
	}
}
