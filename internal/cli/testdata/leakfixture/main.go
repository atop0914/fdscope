// Command leakfixture is the child process the correlation tests drive.
//
// It is a Go program rather than a shell script because of what the test asserts:
// that the resident set and the descriptor table start moving at the same moment.
// A shell cannot support that assertion - its memory is dominated by transient
// buffers - measured one run at 71MiB when the window opened and 59MiB during it,
// which is a *fall*, and a fall is not the activity the fixture is supposed to
// exhibit. A Go program holding its allocations in a slice grows monotonically, so
// the signal the test asserts on means what it says.
//
// It leaks on purpose: every iteration opens a file it never closes and keeps a
// buffer it never releases. Nothing here is a bug to fix; it is the shape the tool
// exists to find.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := os.Getenv("FIXTURE_DIR")
	gate := os.Getenv("FIXTURE_GATE")
	if dir == "" || gate == "" {
		fmt.Fprintln(os.Stderr, "leakfixture: FIXTURE_DIR and FIXTURE_GATE are required")
		os.Exit(2)
	}

	// Wait for the gate so that the growth begins *inside* the sampled window.
	// Opening descriptors before sampling starts produces the other interesting
	// case - a rise that predates the observation - and the correlation layer
	// deliberately reports nothing for it.
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	const chunk = 2 << 20 // 2MiB per iteration
	var held [][]byte
	files := make([]*os.File, 0, 1024)
	for i := 0; ; i++ {
		buf := make([]byte, chunk)
		// Touch every page: make() reserves address space, and an untouched slice
		// is not resident, so VmRSS would stay flat and the fixture would prove
		// nothing about memory activity.
		for j := 0; j < len(buf); j += 4096 {
			buf[j] = 1
		}
		held = append(held, buf)

		f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("leak-%d.log", i)), os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			files = append(files, f)
		}
		time.Sleep(80 * time.Millisecond)
	}
}
