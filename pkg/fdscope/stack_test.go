package fdscope

import (
	"os"
	"strings"
	"testing"
	"time"
)

// leakAndHold opens a descriptor, keeps it open, and parks. It exists so that
// the L3 tests can assert on a function name that is genuinely on the call
// chain rather than on a string that happens to appear in a report.
//
// noinline because the whole point is that this frame is visible in a stack
// dump: an inlined callee would come and go with the compiler's decisions, and
// the assertion would turn into a test of the optimiser.
//
//go:noinline
func leakAndHold(path string, hold <-chan struct{}, opened chan<- struct{}) *os.File {
	f, err := os.Open(path)
	if err != nil {
		close(opened)
		return nil
	}
	close(opened)
	<-hold
	return f
}

// stackLeak runs one real leak - a descriptor opened and not closed, in a
// goroutine that stays alive - and returns what LeakCheck reported.
func stackLeak(t *testing.T, opts ...LeakCheckOption) string {
	t.Helper()

	hold := make(chan struct{})
	opened := make(chan struct{})
	leaked := make(chan *os.File, 1)

	rec := &recorder{}
	LeakCheck(rec, func() {
		go func() { leaked <- leakAndHold("/dev/null", hold, opened) }()
		// Wait until the descriptor exists. Without this the check could take its
		// closing snapshot before the goroutine was ever scheduled, and the test
		// would be measuring the scheduler rather than the leak.
		<-opened
	}, opts...)

	close(hold)
	if f := <-leaked; f != nil {
		t.Cleanup(func() { _ = f.Close() })
	}
	return rec.report()
}

// TestLeakCheckWithStacksNamesWhereTheGoroutinesSit is the positive case, and it
// asserts three separate things: the descriptor is still reported, the stack
// layer names a function that really is on the chain, and the words say what the
// evidence is worth.
func TestLeakCheckWithStacksNamesWhereTheGoroutinesSit(t *testing.T) {
	report := stackLeak(t, WithStacks(), WithSettle(80*time.Millisecond))

	if !strings.Contains(report, "1 descriptor(s) for /dev/null stayed open") {
		t.Fatalf("the descriptor the goroutine kept open was not reported:\n%s", report)
	}
	if !strings.Contains(report, "L3 sampling") {
		t.Fatalf("no stack layer was printed for a leak that was asked to be paired:\n%s", report)
	}
	// The honesty assertion: the function name in the report must be a function
	// that is actually in the goroutine's call chain.
	if !strings.Contains(report, "leakAndHold") {
		t.Fatalf("the stack layer does not name the function the goroutine sits in:\n%s", report)
	}
	if !strings.Contains(report, "1 goroutine(s) sitting in") {
		t.Fatalf("the stack layer does not say how many goroutines share the stack:\n%s", report)
	}
	if !strings.Contains(report, "not the moment each descriptor was opened") {
		t.Fatalf("the stack layer does not say what a photograph cannot show:\n%s", report)
	}
}

// TestLeakCheckWithStacksDoesNotAccuseTheRestOfTheProcess is the reverse
// assertion for L3. The test's own goroutine existed before the check and must
// not be listed; a comparison that reported every goroutine would answer "the
// whole program" to every question.
func TestLeakCheckWithStacksDoesNotAccuseTheRestOfTheProcess(t *testing.T) {
	report := stackLeak(t, WithStacks(), WithSettle(80*time.Millisecond))

	for _, frame := range []string{"testing.tRunner", "runtime.goexit", "leakcheck."} {
		if strings.Contains(report, frame) {
			t.Errorf("a goroutine that existed before the check was listed through %q:\n%s", frame, report)
		}
	}
	// And it must not list the runtime's own workers either: they start on their
	// own schedule and would be attributed to the code under test.
	if strings.Contains(report, "runtime.bgsweep") || strings.Contains(report, "runtime.gcBgMarkWorker") {
		t.Errorf("a runtime worker was named as a suspect:\n%s", report)
	}
}

// TestLeakCheckWithoutStacksSaysNothingAboutGoroutines covers opt-in: the
// existing call keeps its existing report, byte for byte.
func TestLeakCheckWithoutStacksSaysNothingAboutGoroutines(t *testing.T) {
	report := stackLeak(t, WithSettle(80*time.Millisecond))
	if !strings.Contains(report, "stayed open") {
		t.Fatalf("the leak itself was not reported:\n%s", report)
	}
	if strings.Contains(report, "L3 sampling") || strings.Contains(report, "goroutine") {
		t.Fatalf("a check that did not ask for stacks printed them anyway:\n%s", report)
	}
}

// TestLeakCheckWithStacksIsSilentWhenNothingLeaks is the other reverse
// assertion, and the one adoption depends on: a green test must stay quiet even
// with the most expensive layer switched on.
func TestLeakCheckWithStacksIsSilentWhenNothingLeaks(t *testing.T) {
	rec := &recorder{}
	LeakCheck(rec, func() {
		hold := make(chan struct{})
		opened := make(chan struct{})
		leaked := make(chan *os.File, 1)
		go func() { leaked <- leakAndHold("/dev/null", hold, opened) }()
		<-opened
		close(hold)
		if f := <-leaked; f != nil {
			_ = f.Close()
		}
	}, WithStacks())

	if len(rec.msgs) > 0 {
		t.Fatalf("code that released everything was reported anyway:\n%s", rec.report())
	}
}
