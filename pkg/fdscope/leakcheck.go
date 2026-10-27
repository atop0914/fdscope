package fdscope

// This file is the goleak-shaped half of the library: an assertion you put
// around a piece of code in a test.
//
// It answers a different question from CheckPID, and the difference is worth
// being precise about, because conflating them would be exactly the kind of
// over-claim this project exists to avoid:
//
//	CheckPID     "is this process leaking?", answered by watching growth over a
//	             window. The claim is about time, so it needs a window, and its
//	             evidence is the shape of a series.
//	LeakCheck    "did this code leave descriptors behind?", answered by comparing
//	             the descriptor table before and after. The claim is about a
//	             finished operation, so it needs no window: when fn returns, the
//	             resources it opened must be gone. This is goleak's model.
//
// A two-point comparison cannot tell a leak from a batch job in flight, which is
// why fdscope's verdict needs a series - but that objection does not apply here.
// The operation has finished; there is nothing in flight. A descriptor still open
// after fn returned was not released, and saying so is a fact, not an inference
// about cause.
//
// It is also the only form of this check that is usable inside a unit test: a
// window-based verdict would need five seconds per call, and a leak that completes
// in the first millisecond of the window would be invisible in the series anyway.

import (
	"os"
	"sort"
	"strings"
	"time"

	"github.com/atop0914/fdscope/internal/probe"
)

// DefaultSettle is how long LeakCheck waits, sampling, for asynchronously
// released descriptors before comparing.
const DefaultSettle = 50 * time.Millisecond

// TestingT is the smallest slice of *testing.T that LeakCheck needs.
//
// It is an interface rather than *testing.T so that the package does not import
// testing, and so the assertion can be driven from any test framework - or from
// a fake, which is how these tests themselves assert that the assertion fires.
type TestingT interface {
	Errorf(format string, args ...any)
}

// GrowthRow is one resource that was still open after the checked code returned.
type GrowthRow struct {
	// Fingerprint is the resource, normalised as everywhere else.
	Fingerprint string
	// Before and After are how many descriptors of it were open either side of
	// the call, and Delta the difference.
	Before int
	After  int
	Delta  int
}

// leakCheckConfig is the resolved option set.
type leakCheckConfig struct {
	settle    time.Duration
	tolerance int
	ignore    []string
}

// LeakCheckOption configures LeakCheck.
type LeakCheckOption func(*leakCheckConfig)

// WithSettle sets how long the check keeps sampling after fn returns before
// comparing.
//
// The wait exists because "closed" is not always synchronous: a goroutine that
// closes on its way out, a connection returned to a pool and reaped a moment
// later. Convicting on the first look would flag those, and a false alarm is what
// gets a leak checker switched off.
func WithSettle(d time.Duration) LeakCheckOption {
	return func(c *leakCheckConfig) { c.settle = d }
}

// WithTolerance sets how many extra descriptors of a single resource are
// tolerated before they are reported.
//
// Zero is the default, because a test that opened a file and did not close it
// usually leaked exactly one. Raise it for code that legitimately grows a
// process-wide resource (a log file per shard) where the count is not the point.
func WithTolerance(n int) LeakCheckOption {
	return func(c *leakCheckConfig) { c.tolerance = n }
}

// WithIgnoredFingerprints excludes resources whose fingerprint starts with any of
// the given prefixes.
//
// This is goleak's IgnoreTopFunction: the test harness itself opens descriptors
// the code under test is not responsible for, and the honest way to handle that
// is to name them, not to loosen the check for everything.
func WithIgnoredFingerprints(prefixes ...string) LeakCheckOption {
	return func(c *leakCheckConfig) { c.ignore = append(c.ignore, prefixes...) }
}

// LeakCheck runs fn and reports through t every resource whose descriptor count
// did not return to where it was before fn ran.
//
//	fdscope.LeakCheck(t, func() {
//		conn, _ := net.Dial("tcp", addr)
//		_ = conn.Close()
//	})
//
// The comparison is per fingerprint, not on the process total: a descriptor that
// moved from one resource to another is a change in what the process holds, and a
// total that stayed level would hide it.
//
// Every failure to measure is a failure, not a pass. On a platform without
// /proc, or when its own descriptor table could not be read completely, LeakCheck
// calls t.Errorf: a green test would otherwise claim that nothing leaked when in
// fact nothing was looked at.
func LeakCheck(t TestingT, fn func(), opts ...LeakCheckOption) {
	if t == nil {
		// Not a silent return: a check with nowhere to report is a bug in the
		// caller, and quietly doing nothing would look exactly like a pass.
		panic("fdscope: LeakCheck called with a nil TestingT")
	}
	if fn == nil {
		panic("fdscope: LeakCheck called without a function to run")
	}

	cfg := leakCheckConfig{settle: DefaultSettle}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.settle < 0 {
		cfg.settle = 0
	}

	// fn runs on every path, including the failure paths below. Skipping the code
	// under test because the checker could not measure it would be the worst of
	// both worlds: the test would not exercise anything, and it would report a
	// failure that says nothing about the code. It also has to run before any
	// reporting, so that a panic inside it propagates instead of being masked by
	// an earlier assertion.
	if !supported() {
		fn()
		t.Errorf("fdscope: cannot verify descriptors on this platform: %v; failing rather than passing, "+
			"because a pass would claim a measurement that never happened", ErrNotLinux)
		return
	}

	before, beforeErr := snapshotSelf()
	fn()
	if beforeErr != nil {
		t.Errorf("fdscope: could not read this process's descriptors before the check: %v", beforeErr)
		return
	}
	if !before.Complete() {
		// An incomplete baseline could be missing the very descriptor the code
		// under test leaks, and a missing entry in the baseline reads as growth.
		t.Errorf("fdscope: %d descriptor entries were unreadable before the check; refusing to compare "+
			"against a baseline that is only a lower bound", before.Unreadable)
		return
	}

	after, err := snapshotWithSettle(cfg.settle)
	if err != nil {
		t.Errorf("fdscope: could not read this process's descriptors after the check: %v", err)
		return
	}
	if !after.Complete() {
		t.Errorf("fdscope: %d descriptor entries were unreadable after the check; refusing to conclude "+
			"from a partial read, which looks exactly like a release", after.Unreadable)
		return
	}

	for _, row := range grownFingerprints(before, after, cfg) {
		t.Errorf("fdscope: %d descriptor(s) for %s stayed open (%d before, %d after; %+d): "+
			"the checked code returned without releasing them",
			row.Delta, row.Fingerprint, row.Before, row.After, row.Delta)
	}
}

// snapshotSelf reads the calling process's descriptor table.
func snapshotSelf() (Snapshot, error) {
	p := probe.NewProbe()
	if home, err := os.UserHomeDir(); err == nil {
		p.Normalizer.HomeDir = home
	}
	return p.Snapshot(os.Getpid())
}

// snapshotWithSettle samples for the settle period and returns the last snapshot.
//
// Sampling rather than sleeping once: a single sleep-then-look convicts anything
// that takes longer than the sleep and clears anything that happened to be
// mid-release at the instant it looked. Repeated sampling keeps the observation
// honest to the end of the grace period.
func snapshotWithSettle(settle time.Duration) (Snapshot, error) {
	if settle <= 0 {
		return snapshotSelf()
	}
	step := settle / 4
	if step <= 0 {
		step = settle
	}
	deadline := time.Now().Add(settle)
	snap, err := snapshotSelf()
	if err != nil {
		return Snapshot{}, err
	}
	for time.Now().Before(deadline) {
		time.Sleep(step)
		snap, err = snapshotSelf()
		if err != nil {
			return Snapshot{}, err
		}
	}
	return snap, nil
}

// grownFingerprints lists the resources that hold more descriptors after than
// before, largest first.
func grownFingerprints(before, after Snapshot, cfg leakCheckConfig) []GrowthRow {
	b := countByFingerprint(before)
	a := countByFingerprint(after)

	rows := make([]GrowthRow, 0, len(a))
	for fp, n := range a {
		if isIgnored(fp, cfg.ignore) {
			continue
		}
		delta := n - b[fp]
		if delta > cfg.tolerance {
			rows = append(rows, GrowthRow{Fingerprint: fp, Before: b[fp], After: n, Delta: delta})
		}
	}
	// Deterministic order: a failure report that changes between runs is hard to
	// read in a CI log and impossible to assert on.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Delta != rows[j].Delta {
			return rows[i].Delta > rows[j].Delta
		}
		return rows[i].Fingerprint < rows[j].Fingerprint
	})
	return rows
}

// countByFingerprint counts descriptors per resource.
func countByFingerprint(s Snapshot) map[string]int {
	out := make(map[string]int, len(s.Descriptors))
	for _, d := range s.Descriptors {
		out[d.Fingerprint]++
	}
	return out
}

// isIgnored reports whether a fingerprint matches one of the ignored prefixes.
func isIgnored(fp string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(fp, p) {
			return true
		}
	}
	return false
}
