// Command fdlistdrift is a stand-in for a descriptor cache whose bookkeeping
// drifted away from its contents.
//
// It reproduces the PATTERN of a defect found in nutsdb's
// internal/fileio/fd_manager.go; no line here is copied from that repository,
// which is neither imported nor importable (fdscope has no dependencies). The
// defect spans three statements of the original:
//
//	doubleLinkedList.addNode      increments the list's own size
//	doubleLinkedList.removeNode   splices a node out and does NOT decrement it
//	FdManager.GetFd               treats "size >= maxFdNums" as "the cache is
//	                              full" and returns the freshly opened
//	                              descriptor *without* caching it
//
// So once the list has held maxFdNums nodes, its size never falls back below that
// number again: the cache permanently believes it is full, and every later open
// hands out a descriptor that nothing owns and nothing ever closes. Measured
// against the original, the cache held 2 entries while its list still counted 10.
//
// The leak is therefore not one big open - it is a bookkeeping number that stopped
// going down, and a guard that trusted it.
//
// Run with -fixed for the version where the count is decremented on removal. The
// two differ by one statement, which is what makes the pair evidence rather than
// anecdote: same rate, same resource, same code shape.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// maxFds is the cache capacity, cleanThreshold the level at which idle
	// descriptors are reclaimed. Small on purpose: the drift has to become
	// visible inside a two second window.
	maxFds         = 8
	cleanThreshold = 6
)

type node struct {
	path  string
	file  *os.File
	using uint
}

type list struct {
	nodes []*node
	// size is the list's own count of nodes, kept separately from len(nodes).
	// Keeping a second copy of a fact the slice already carries is what makes the
	// drift possible at all.
	size  int
	fixed bool
}

func (l *list) add(n *node) {
	l.nodes = append(l.nodes, n)
	l.size++
}

// remove splices n out of the list.
func (l *list) remove(n *node) {
	for i, x := range l.nodes {
		if x != n {
			continue
		}
		l.nodes = append(l.nodes[:i], l.nodes[i+1:]...)
		// The defect: the count is not decremented here. Under -fixed it is, and
		// that single line is the whole difference between the two programs.
		if l.fixed {
			l.size--
		}
		return
	}
}

type cache struct {
	list  list
	entry map[string]*node
	// orphaned keeps the descriptors handed out without being cached reachable.
	// Without a reference the runtime's finalizer would close them at some
	// unpredictable moment, and the leak would heal itself between two samples.
	orphaned []*os.File
}

// get is GetFd: reuse on a hit, otherwise open, reclaim, and maybe refuse to cache.
func (c *cache) get(path string) error {
	if n, ok := c.entry[path]; ok {
		n.using++
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s\n", path); err != nil {
		return err
	}
	if c.list.size >= cleanThreshold {
		c.cleanUselessFd()
	}
	if c.list.size >= maxFds {
		// "The cache is full", so this descriptor is returned uncached. Upstream
		// returns it to a caller that has no idea it now owns a file it will never
		// close; here it goes to a slice that outlives the process.
		c.orphaned = append(c.orphaned, f)
		return nil
	}
	n := &node{path: path, file: f, using: 1}
	c.list.add(n)
	c.entry[path] = n
	return nil
}

// reduceUsing says the caller is done with path.
func (c *cache) reduceUsing(path string) {
	if n, ok := c.entry[path]; ok {
		n.using--
	}
}

// cleanUselessFd closes descriptors nobody is using.
func (c *cache) cleanUselessFd() {
	cleanNums := cleanThreshold
	snapshot := append([]*node(nil), c.list.nodes...)
	for _, n := range snapshot {
		if cleanNums == 0 {
			break
		}
		if n.using != 0 {
			continue
		}
		c.list.remove(n)
		delete(c.entry, n.path)
		if err := n.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close %s: %v\n", n.path, err)
		}
		cleanNums--
	}
}

func main() {
	fixed := flag.Bool("fixed", false, "decrement the list count on removal (the corrected cache)")
	flag.Parse()

	dir, err := os.MkdirTemp("", "fdscope-corpus-fdlistdrift-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "work dir: %v\n", err)
		os.Exit(1)
	}
	c := &cache{list: list{fixed: *fixed}, entry: map[string]*node{}}
	// The parent reads this line to know the leak has started, and takes the
	// directory from it so it can clean up after killing this process.
	fmt.Printf("ready %s\n", dir)

	for i := 0; ; i++ {
		// A data file nobody has opened before, as a write-ahead log produces.
		// Unique paths are not a convenience here: they are the shape in which
		// this defect leaks at all, because a cache hit never opens a descriptor.
		path := filepath.Join(dir, fmt.Sprintf("data-%06d.db", i))
		if err := c.get(path); err != nil {
			fmt.Fprintf(os.Stderr, "get %s: %v\n", path, err)
			os.Exit(1)
		}
		c.reduceUsing(path)
		time.Sleep(20 * time.Millisecond)
	}
}
