//go:build linux

package leakgen

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/probe"
)

// The assertions below read /proc, never the generator's own counters. That is
// not ceremony: the corpus in testdata/corpus reproduces three real descriptor
// bugs, and every one of them is a bug in a counter that disagreed with /proc.
// A fixture whose evidence came from its own bookkeeping could reproduce the bug
// and still pass.

// heldUnder counts this process's descriptors whose raw target mentions dir.
// Counting by target rather than by total keeps the assertion immune to whatever
// else the test binary has open.
func heldUnder(t *testing.T, dir string) map[string]int {
	t.Helper()
	snap, err := probe.NewProbe().Snapshot(os.Getpid())
	if err != nil {
		t.Fatalf("snapshot own process: %v", err)
	}
	if !snap.Complete() {
		t.Fatalf("snapshot is incomplete (%d unreadable): the count below would be a guess", snap.Unreadable)
	}
	counts := map[string]int{}
	for _, d := range snap.Descriptors {
		if strings.Contains(d.Target, dir) {
			counts[d.Target]++
		}
	}
	return counts
}

// totalUnder sums the per-target counts.
func totalUnder(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	for _, c := range heldUnder(t, dir) {
		n += c
	}
	return n
}

// runFor starts the generator and stops it after d, leaving what it opened open.
func runFor(t *testing.T, g *Generator, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	g.Run(ctx)
	if err := g.Err(); err != nil {
		t.Fatalf("generator failed: %v", err)
	}
}

func TestGeneratorHoldsRealDescriptors(t *testing.T) {
	g, err := New(Config{Rate: 100, Paths: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := g.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	runFor(t, g, 400*time.Millisecond)

	held := heldUnder(t, g.Dir())
	total := 0
	for _, c := range held {
		total += c
	}
	// 100/s over 0.4s is 40 opens; the floor leaves room for a slow first tick
	// without leaving room for the generator to have done nothing.
	if total < 20 {
		t.Fatalf("held %d descriptors under %s, want at least 20: the generator did not create the leak it exists for",
			total, g.Dir())
	}
	// Three paths, and every one of them held more than once: this is the shape
	// a cache produces, and the shape fingerprints must grow on.
	if len(held) != 3 {
		t.Fatalf("descriptors spread over %d targets, want 3: %v", len(held), held)
	}
	for target, c := range held {
		if c < 2 {
			t.Errorf("%s held %d time(s), want the round-robin to reuse every path", target, c)
		}
	}
}

func TestGeneratorCloseReleasesEverything(t *testing.T) {
	g, err := New(Config{Rate: 200, Kind: KindDeleted})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dir := g.Dir()
	runFor(t, g, 200*time.Millisecond)
	if n := totalUnder(t, dir); n == 0 {
		t.Fatal("nothing was opened, so this test would prove nothing about Close")
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := totalUnder(t, dir); n != 0 {
		t.Errorf("%d descriptors still open after Close", n)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the generator created %s and did not remove it on Close: %v", dir, err)
	}
}

// TestFiniteLifetimeIsNotALeak is the reversal the verdict's false-alarm
// criterion needs: the same rate, the same resource, one field different.
func TestFiniteLifetimeIsNotALeak(t *testing.T) {
	g, err := New(Config{Rate: 100, Lifetime: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })

	runFor(t, g, 500*time.Millisecond)

	// 100/s with a 20ms lifetime settles at about two descriptors. A generator
	// that leaked would be holding fifty. The bound is loose on purpose: the
	// claim is "bounded", not "exactly two".
	if n := totalUnder(t, g.Dir()); n > 15 {
		t.Fatalf("held %d descriptors with a finite lifetime: %d would mean the descriptors outlive it", n, n)
	}
}

// targetsByFD reads this process's descriptor table as a map from descriptor
// number to raw link target.
//
// A socket's target is "socket:[inode]" and carries no path, so "did this
// generator open it" cannot be answered by looking for the working directory in
// the target. Comparing two snapshots can: only what appeared between them is
// the generator's.
func targetsByFD(t *testing.T) map[int]string {
	t.Helper()
	snap, err := probe.NewProbe().Snapshot(os.Getpid())
	if err != nil {
		t.Fatalf("snapshot own process: %v", err)
	}
	if !snap.Complete() {
		t.Fatalf("snapshot is incomplete (%d unreadable): the comparison below would be a guess", snap.Unreadable)
	}
	byFD := make(map[int]string, len(snap.Descriptors))
	for _, d := range snap.Descriptors {
		byFD[d.FD] = d.Target
	}
	return byFD
}

func TestKindsProduceTheirOwnShape(t *testing.T) {
	cases := []struct {
		name       string
		kind       Kind
		wantKind   model.FDKind
		wantPrefix string
		wantDelete bool
		// named says whether the descriptor's target carries the path it was
		// created at. Sockets do not: /proc reports the inode and nothing else.
		named bool
	}{
		{name: "file", kind: KindFile, wantKind: model.KindFile, wantPrefix: "file:", named: true},
		{name: "socket", kind: KindSocket, wantKind: model.KindSocket, wantPrefix: "socket"},
		{name: "deleted", kind: KindDeleted, wantKind: model.KindDeleted, wantPrefix: "deleted:", wantDelete: true, named: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := targetsByFD(t)

			g, err := New(Config{Rate: 200, Kind: tc.kind})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = g.Close() })
			runFor(t, g, 100*time.Millisecond)

			snap, err := probe.NewProbe().Snapshot(os.Getpid())
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			found := 0
			for _, d := range snap.Descriptors {
				if old, existed := before[d.FD]; existed && old == d.Target {
					continue
				}
				if tc.named && !strings.Contains(d.Target, g.Dir()) {
					continue
				}
				if !tc.named && d.Kind != tc.wantKind {
					continue
				}
				found++
				if d.Kind != tc.wantKind {
					t.Errorf("%s: kind = %q, want %q", d.Target, d.Kind, tc.wantKind)
				}
				if !strings.HasPrefix(d.Fingerprint, tc.wantPrefix) {
					t.Errorf("%s: fingerprint = %q, want prefix %q", d.Target, d.Fingerprint, tc.wantPrefix)
				}
				if d.Deleted != tc.wantDelete {
					t.Errorf("%s: deleted = %v, want %v", d.Target, d.Deleted, tc.wantDelete)
				}
			}
			if found == 0 {
				t.Fatalf("no %s descriptor appeared under %s", tc.kind, g.Dir())
			}
		})
	}
}

func TestConfigRejectsValuesThatCannotMeanWhatWasAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "negative rate", cfg: Config{Rate: -1}},
		{name: "negative lifetime", cfg: Config{Lifetime: -time.Second}},
		{name: "negative path count", cfg: Config{Paths: -2}},
		// A trailing space is the kind of typo a caller makes; treating it as
		// "file" would make the test that asked for a socket pass while opening
		// files.
		{name: "unknown kind", cfg: Config{Kind: Kind("file ")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New(%+v) accepted a configuration it cannot honour", tc.cfg)
			}
		})
	}
}

// TestNothingOutsideFixturesImportsTheGenerator keeps "test-only" a fact rather
// than a comment. A leak injector reachable from pkg/ or cmd/ would be a way to
// make fdscope's own binary open descriptors it never closes, which is the one
// failure mode this project must not be able to ship.
func TestNothingOutsideFixturesImportsTheGenerator(t *testing.T) {
	root := filepath.Join("..", "..")
	const banned = "internal/leakgen"
	offenders := make([]string, 0)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// testdata holds the corpus programs, which are allowed to use the
			// generator; this package obviously is too. Everything else is
			// production or test code and may not import it.
			switch d.Name() {
			case ".git", ".cache", "testdata", "leakgen":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(src), banned) {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("the leak injector is imported by production code: %v", offenders)
	}
}
