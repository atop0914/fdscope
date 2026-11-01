// Command fdlistdrift is a stand-in for a descriptor cache whose accounting
// drifted away from its contents.
//
// It reproduces the PATTERN, not the upstream code: no line here is copied from
// that repository, which is neither imported nor importable (fdscope has no
// dependencies, and a fixture that pulled one in would break that promise). The
// defect being reproduced is the one in nutsdb's FdManager.cleanUselessFd
// (fd_manager.go): the descriptor list is trimmed but the list's own size
// counter is never decremented, so the manager's belief about what it holds
// drifts above the truth - observed as "the cache holds 2, list.size still says
// 10" - and every later eviction frees a slot that was already free while the
// descriptor it was supposed to close stays open.
//
// The consequence, which is the only part fdscope is asked about, is a real
// leak: the process keeps holding descriptors it believes it has released.
//
// Run with -fixed for the corrected version, where the counter is decremented
// and the descriptor is closed. The two differ by one statement, which is what
// makes the pair evidence rather than anecdote: same rate, same resource, same
// shape of code.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// capacity is how many descriptors the cache is allowed to hold. Small on
// purpose: the drift has to become visible inside a five second window.
const capacity = 8

type entry struct {
	path string
	file *os.File
}

type cache struct {
	entries []*entry
	// size is the cache's belief about len(entries). Keeping a second copy of a
	// fact the slice already carries is what makes the drift possible at all.
	size  int
	fixed bool
	// parked keeps the descriptors the buggy path abandons reachable. Without a
	// reference the runtime's finalizer on os.File would close them at some
	// unpredictable moment, and the leak would appear and then vanish by itself.
	parked []*os.File
}

func (c *cache) get(path string, n int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%d\n", n); err != nil {
		return err
	}
	c.entries = append(c.entries, &entry{path: path, file: f})
	c.size++
	if c.size > capacity {
		c.evict()
	}
	return nil
}

// evict reclaims the oldest slot.
func (c *cache) evict() {
	old := c.entries[0]
	c.entries = c.entries[1:]
	if c.fixed {
		c.size--
		if err := old.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close %s: %v\n", old.path, err)
		}
		return
	}
	// The defect: the slot is treated as recycled, so size is left alone, and the
	// descriptor is dropped from the list without being closed.
	c.parked = append(c.parked, old.file)
}

func main() {
	fixed := flag.Bool("fixed", false, "decrement the counter and close the descriptor (the corrected cache)")
	flag.Parse()

	dir, err := os.MkdirTemp("", "fdscope-corpus-fdlistdrift-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "work dir: %v\n", err)
		os.Exit(1)
	}
	c := &cache{fixed: *fixed}
	// The parent reads this line to know the leak has started, and takes the
	// directory from it so it can clean up after killing this process.
	fmt.Printf("ready %s\n", dir)

	for i := 0; ; i++ {
		// Four shard files in rotation: the same working set a database keeps
		// open, and the reason the report can attribute the growth to a category
		// instead of only to the process total.
		if err := c.get(filepath.Join(dir, fmt.Sprintf("shard-%d.db", i%4)), i); err != nil {
			fmt.Fprintf(os.Stderr, "open shard: %v\n", err)
			os.Exit(1)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
