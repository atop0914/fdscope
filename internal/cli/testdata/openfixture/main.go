// Command openfixture opens descriptors and does nothing else.
//
// It exists for the reverse assertion of the correlation layer: a process whose
// descriptor table grows while every other counter stays where it was must
// produce no correlation at all. That is the case that decides whether L2 is
// worth reading, so the fixture has to be honest about "nothing else".
//
// It is a Go program rather than the shell loop the plan first named, because the
// shell was not honest about it. Measured on the CI runner, the bash version of
// this loop - `exec {fd}>/dev/null` in a paced loop - reported syscr rising by
// +300 (+88%) across the window. Opening a descriptor does not read anything, so
// that movement came from bash itself: a shell cannot pace a loop without
// syscalls of its own (an external `sleep` per iteration, a `read` builtin, its
// own startup files), and those made a process that only opened files look like
// one that had also started reading. A Go program paces itself with
// time.Sleep and touches nothing else.
//
// Nothing below allocates beyond a fixed ring or spawns a goroutine: a growing
// heap or a new thread would be the process touching something else, and a
// fixture that does that cannot prove the negative it is here to prove.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ring is how many descriptors the fixture keeps referenced. It is allocated up
// front so that holding them cannot grow the heap: an unreferenced *os.File is
// closed by its finalizer, and growing a slice on every iteration would put a
// rising resident set in the window this test asserts is empty.
const ring = 4096

func main() {
	dir := os.Getenv("FIXTURE_DIR")
	gate := os.Getenv("FIXTURE_GATE")
	if dir == "" || gate == "" {
		fmt.Fprintln(os.Stderr, "openfixture: FIXTURE_DIR and FIXTURE_GATE are required")
		os.Exit(2)
	}

	// Wait for the gate so the growth begins inside the sampled window. Stat and
	// sleep only: the wait must not add activity of its own to the window.
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	held := make([]*os.File, ring)
	for i := 0; ; i++ {
		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("open-%d.log", i)),
			os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			held[i%ring] = f
		}
		time.Sleep(80 * time.Millisecond)
	}
}
