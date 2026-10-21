// Command example prints the largest descriptor groups held by a process.
//
// Usage: go run ./examples/snapshot <pid>
//
// It exercises the public package exactly as a library consumer would, so it
// doubles as a compile-time check that the exported surface stays usable.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/atop0914/fdscope/pkg/fdscope"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: snapshot <pid>")
		os.Exit(1)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pid: %v\n", err)
		os.Exit(1)
	}

	if !fdscope.IsSupported() {
		fmt.Fprintln(os.Stderr, "fdscope requires Linux")
		os.Exit(1)
	}

	snap, err := fdscope.NewProbe().Snapshot(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snapshot: %v\n", err)
		os.Exit(1)
	}

	h := fdscope.Headroom{PID: pid, Used: snap.Len(), Limit: snap.OpenLimit}
	fmt.Printf("pid %d: %s\n", pid, h)

	for _, row := range snap.SortedFingerprints() {
		// Print at most ten groups; the tail is almost always noise.
		if row.Count < 2 {
			break
		}
		fmt.Printf("  %4d  %-12s %s\n", row.Count, row.Kind, row.Fingerprint)
	}
}
