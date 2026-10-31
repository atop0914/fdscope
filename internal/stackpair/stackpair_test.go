package stackpair

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The fixtures below are verbatim shapes of runtime.Stack output. They are
// fixtures rather than live goroutines because the cases that matter most are
// the awkward ones - argument values that differ between two goroutines on the
// same path, a header that does not parse, a worker that exists inside the
// runtime - and those are painful to stage and trivial to write down. The live
// path is exercised end to end from pkg/fdscope.

const dumpBefore = `goroutine 1 [running]:
main.main()
	/tmp/app/main.go:6 +0x25

goroutine 18 [chan receive]:
runtime.gopark(0xc000020000, 0xc00006bd48, 0x14, 0x1, 0x2)
	/usr/local/go/src/runtime/proc.go:424 +0xce
runtime.chanrecv(0xc000028060, 0x0, 0x1)
	/usr/local/go/src/runtime/chan.go:639 +0x41c
runtime.chanrecv1(0xc000028060, 0x0)
	/usr/local/go/src/runtime/chan.go:487 +0x12
example.com/app.(*Loader).refresh(0xc000012345)
	/tmp/app/loader.go:88 +0x3d
created by example.com/app.New in goroutine 1
	/tmp/app/loader.go:41 +0x1a5
`

// dumpAfter holds the same two goroutines plus three that share one stack and
// one that is entirely inside the runtime.
const dumpAfter = dumpBefore + `
goroutine 31 [chan receive]:
runtime.gopark(0xc0000a0000, 0xc0000abd48, 0x14, 0x1, 0x2)
	/usr/local/go/src/runtime/proc.go:424 +0xce
runtime.chanrecv(0xc0000a8060, 0x0, 0x1)
	/usr/local/go/src/runtime/chan.go:639 +0x41c
runtime.chanrecv1(0xc0000a8060, 0x0)
	/usr/local/go/src/runtime/chan.go:487 +0x12
example.com/app.(*Loader).refresh(0xc00004c001)
	/tmp/app/loader.go:88 +0x3d
created by example.com/app.New in goroutine 1
	/tmp/app/loader.go:41 +0x1a5

goroutine 32 [chan receive]:
runtime.gopark(0xc0000a0000, 0xc0000abd48, 0x14, 0x1, 0x2)
	/usr/local/go/src/runtime/proc.go:424 +0xce
runtime.chanrecv(0xc0000a8060, 0x0, 0x1)
	/usr/local/go/src/runtime/chan.go:639 +0x41c
runtime.chanrecv1(0xc0000a8060, 0x0)
	/usr/local/go/src/runtime/chan.go:487 +0x12
example.com/app.(*Loader).refresh(0xc00004c002)
	/tmp/app/loader.go:88 +0x3d
created by example.com/app.New in goroutine 1
	/tmp/app/loader.go:41 +0x1a5

goroutine 33 [chan receive]:
runtime.gopark(0xc0000a0000, 0xc0000abd48, 0x14, 0x1, 0x2)
	/usr/local/go/src/runtime/proc.go:424 +0xce
runtime.chanrecv(0xc0000a8060, 0x0, 0x1)
	/usr/local/go/src/runtime/chan.go:639 +0x41c
runtime.chanrecv1(0xc0000a8060, 0x0)
	/usr/local/go/src/runtime/chan.go:487 +0x12
example.com/app.(*Loader).refresh(0xc00004c003)
	/tmp/app/loader.go:88 +0x3d
created by example.com/app.New in goroutine 1
	/tmp/app/loader.go:41 +0x1a5

goroutine 40 [GC sweep wait]:
runtime.gopark(0x1, 0x0, 0x0, 0x0, 0x0)
	/usr/local/go/src/runtime/proc.go:424 +0xce
runtime.goparkunlock(0x0, 0x0, 0x0, 0x0, 0x0)
	/usr/local/go/src/runtime/proc.go:430 +0x15e
runtime.bgsweep(0x0)
	/usr/local/go/src/runtime/mgcsweep.go:323 +0x9d
runtime.gcenable.func1()
	/usr/local/go/src/runtime/mgc.go:205 +0x25
created by runtime.gcenable in goroutine 1
	/usr/local/go/src/runtime/mgc.go:205 +0x66
`

var at = time.Date(2026, 10, 31, 20, 45, 0, 0, time.UTC)

func captureOf(text string) Capture { return Parse(text, at) }

// TestParseReadsFramesAndCreationSite covers the parser directly: frames carry
// the file:line a reader needs, the creation site is kept but stripped of its
// goroutine number, and the instruction offsets are not part of a frame.
func TestParseReadsFramesAndCreationSite(t *testing.T) {
	c := captureOf(dumpBefore)
	if len(c.Goroutines) != 2 {
		t.Fatalf("parsed %d goroutines, want 2", len(c.Goroutines))
	}
	if c.Unparsed != 0 || c.Malformed != 0 {
		t.Fatalf("a well-formed dump produced %d unparsed and %d malformed blocks", c.Unparsed, c.Malformed)
	}
	g := c.Goroutines[1]
	if g.ID != 18 {
		t.Errorf("id = %d, want 18", g.ID)
	}
	if got := g.Frames[len(g.Frames)-1].Function; got != "example.com/app.(*Loader).refresh" {
		t.Errorf("deepest frame = %q, want the method receiver kept intact", got)
	}
	if got := g.Frames[len(g.Frames)-1].Line; got != 88 {
		t.Errorf("deepest frame line = %d, want 88", got)
	}
	if g.CreatedBy != "example.com/app.New" {
		t.Errorf("CreatedBy = %q, want the creation function without its goroutine number", g.CreatedBy)
	}
	for _, f := range g.Frames {
		if strings.Contains(f.File, "+0x") {
			t.Errorf("frame file %q still carries an instruction offset", f.File)
		}
	}
}

// TestFingerprintIgnoresArgumentValues is what makes merging possible at all.
//
// Every goroutine started by the same loop prints the same call chain with
// different argument values; keeping them would give a thousand goroutines a
// thousand fingerprints and the report would be unreadable.
func TestFingerprintIgnoresArgumentValues(t *testing.T) {
	c := captureOf(dumpAfter)
	var a, b Goroutine
	for _, g := range c.Goroutines {
		switch g.ID {
		case 31:
			a = g
		case 32:
			b = g
		}
	}
	if fingerprint(a.Frames) != fingerprint(b.Frames) {
		t.Fatalf("two goroutines on the same call chain got different fingerprints:\n%s\n---\n%s",
			fingerprint(a.Frames), fingerprint(b.Frames))
	}
	// The reverse: a different call site must not merge, or the report would
	// collapse unrelated code into one row. Same function one line further down
	// is a different call site and has to stay apart.
	shifted := captureOf(strings.Replace(dumpAfter, "/tmp/app/loader.go:88", "/tmp/app/loader.go:120", 1))
	if fingerprint(shifted.Goroutines[1].Frames) == fingerprint(c.Goroutines[1].Frames) {
		t.Error("the same function at a different line got the same fingerprint: the line is part of the call site")
	}
	if fingerprint(a.Frames) == fingerprint(c.Goroutines[0].Frames) {
		t.Error("goroutines in different functions merged: the fingerprint is too coarse")
	}
}

// TestFunctionNameKeepsMethodReceiver guards the one-character bug that would
// turn every method into its package name: trimming at the first "(" instead of
// the last cuts "net.(*conn).Close(0xc0...)" down to "net.".
func TestFunctionNameKeepsMethodReceiver(t *testing.T) {
	cases := map[string]string{
		"net.(*conn).Close(0xc000010018)":           "net.(*conn).Close",
		"main.main()":                               "main.main",
		"main.TestX.func1(0xc000012345)":            "main.TestX.func1",
		"os.(*File).read(0xc000014078, {0x0, 0x0})": "os.(*File).read",
	}
	for in, want := range cases {
		if got := functionName(in); got != want {
			t.Errorf("functionName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDiffMergesIdenticalStacks is the readability rule: a thousand goroutines
// in one function are one row with a count.
func TestDiffMergesIdenticalStacks(t *testing.T) {
	rep := Diff(captureOf(dumpBefore), captureOf(dumpAfter))

	if rep.Method != MethodGoroutineID {
		t.Fatalf("method = %q, want %q for a dump with readable headers", rep.Method, MethodGoroutineID)
	}
	if rep.New != 4 {
		t.Fatalf("New = %d, want 4 goroutines that were not in the first capture", rep.New)
	}
	if len(rep.Groups) != 1 {
		t.Fatalf("got %d groups, want the three identical stacks merged into 1: %+v", len(rep.Groups), rep.Groups)
	}
	g := rep.Groups[0]
	if g.Count != 3 {
		t.Errorf("group count = %d, want 3", g.Count)
	}
	if got := g.Focus().Function; got != "example.com/app.(*Loader).refresh" {
		t.Errorf("focus = %q, want the reader's own frame rather than runtime.gopark", got)
	}
	if g.CreatedBy != "example.com/app.New" {
		t.Errorf("CreatedBy = %q, want the unanimous creation site", g.CreatedBy)
	}
	if !strings.Contains(strings.Join(rep.Messages(), "\n"), "3 goroutine(s) sitting in example.com/app.(*Loader).refresh (loader.go:88)") {
		t.Errorf("the message does not name the function and its line:\n%s", strings.Join(rep.Messages(), "\n"))
	}
}

// TestDiffIgnoresGoroutinesThatWereAlreadyThere is the reverse assertion. A
// comparison that reported everything would be useless: it would answer "the
// whole program" to every question.
func TestDiffIgnoresGoroutinesThatWereAlreadyThere(t *testing.T) {
	before := captureOf(dumpBefore)
	// Same capture twice: nothing appeared, so nothing may be reported.
	rep := Diff(before, before)
	if rep.New != 0 || len(rep.Groups) != 0 {
		t.Fatalf("comparing a capture with itself produced %d new goroutines in %d groups",
			rep.New, len(rep.Groups))
	}
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Messages(), "\n"), "no goroutine appeared") {
		t.Errorf("silence has to be stated, not implied:\n%s", strings.Join(rep.Messages(), "\n"))
	}
}

// TestDiffExcludesRuntimeWorkers covers the noise that would otherwise be
// attributed to the checked code: the sweeper and the scavenger start on their
// own schedule, usually right after the first allocation.
func TestDiffExcludesRuntimeWorkers(t *testing.T) {
	rep := Diff(captureOf(dumpBefore), captureOf(dumpAfter))

	if rep.Filtered != 1 {
		t.Errorf("Filtered = %d, want the runtime worker counted and excluded", rep.Filtered)
	}
	for _, g := range rep.Groups {
		for _, f := range g.Frames {
			if strings.Contains(f.File, "/src/runtime/mgcsweep.go") {
				t.Errorf("the sweeper was listed as a suspect: %+v", g.Frames)
			}
		}
	}
	// Excluded is not hidden: the count is stated.
	if !strings.Contains(strings.Join(rep.Messages(), "\n"), "entirely inside the Go runtime") {
		t.Errorf("filtered goroutines were dropped silently:\n%s", strings.Join(rep.Messages(), "\n"))
	}
}

// TestDiffFallsBackToStackTextWhenHeadersAreUnreadable documents the fallback
// and its price. The header of goroutine 18 is deliberately mangled, which is
// what a dump from a foreign runtime or a truncated first line looks like.
func TestDiffFallsBackToStackTextWhenHeadersAreUnreadable(t *testing.T) {
	broken := strings.Replace(dumpBefore, "goroutine 18 [chan receive]:", "goroutine ? [chan receive]:", 1)
	rep := Diff(captureOf(broken), captureOf(strings.Replace(dumpAfter, "goroutine 18 [chan receive]:", "goroutine ? [chan receive]:", 1)))

	if rep.Method != MethodStackText {
		t.Fatalf("method = %q, want the fallback when a header cannot be parsed", rep.Method)
	}
	if !strings.Contains(strings.Join(rep.Messages(), "\n"), "compared by stack text") {
		t.Errorf("the fallback was not disclosed:\n%s", strings.Join(rep.Messages(), "\n"))
	}
	if rep.New != 4 {
		t.Errorf("New = %d, want 4: the multiset difference still finds the three new stacks and the worker", rep.New)
	}
}

// TestDiffRefusesWithoutABaseline covers the case that would otherwise convict
// the whole process: an empty first capture makes every goroutine look new.
func TestDiffRefusesWithoutABaseline(t *testing.T) {
	rep := Diff(Capture{At: at}, captureOf(dumpAfter))
	if len(rep.Groups) != 0 || rep.New != 0 {
		t.Fatalf("compared against an empty baseline: %d groups, %d new", len(rep.Groups), rep.New)
	}
	if !strings.Contains(strings.Join(rep.Messages(), "\n"), "baseline that was never taken") {
		t.Errorf("the refusal does not say why:\n%s", strings.Join(rep.Messages(), "\n"))
	}
}

// TestCaptureRefusesATruncatedDump is the branch that matters most: a dump that
// did not fit is a random subset of the goroutine set, and reporting from it
// would describe a subset of the process as if it were the process.
func TestCaptureRefusesATruncatedDump(t *testing.T) {
	// A real capture with a buffer far too small, not a simulated error: the
	// branch has to be reached the same way a runaway process would reach it.
	if _, err := captureGoroutines(64); !errors.Is(err, ErrTruncated) {
		t.Fatalf("captureGoroutines(64) error = %v, want ErrTruncated", err)
	}
	// And the generous path still works.
	c, err := CaptureGoroutines()
	if err != nil {
		t.Fatalf("a normal capture failed: %v", err)
	}
	if len(c.Goroutines) == 0 {
		t.Fatal("the running test process reported no goroutines at all")
	}
}

// TestCreatedByIsOnlyClaimedWhenUnanimous covers the small honesty rule: a row
// that merges goroutines started from two places must not name one of them.
func TestCreatedByIsOnlyClaimedWhenUnanimous(t *testing.T) {
	mixed := strings.Replace(dumpAfter, "created by example.com/app.New in goroutine 1\n\t/tmp/app/loader.go:41 +0x1a5\n\ngoroutine 33", "created by example.com/app.Warm in goroutine 1\n\t/tmp/app/loader.go:57 +0x1a5\n\ngoroutine 33", 1)
	rep := Diff(captureOf(dumpBefore), captureOf(mixed))
	if len(rep.Groups) != 1 {
		t.Fatalf("got %d groups, want the shared stack merged", len(rep.Groups))
	}
	if got := rep.Groups[0].CreatedBy; got != "" {
		t.Errorf("CreatedBy = %q, want empty: the group was created from more than one place", got)
	}
}

// TestMessagesAreLabelledAndDoNotClaimACause is the language gate, and the
// point of the whole layer. L3 may say "these goroutines were not here before";
// it may never say that one of them opened a descriptor.
func TestMessagesAreLabelledAndDoNotClaimACause(t *testing.T) {
	forbidden := []string{
		"caused", "cause", "because", "due to", "responsible", "explains", "led to",
		"opened by", "probably", "likely", "must have", "might be", "blame",
	}
	reports := []Report{
		Diff(captureOf(dumpBefore), captureOf(dumpAfter)),
		Diff(captureOf(dumpBefore), captureOf(dumpBefore)),
		Diff(Capture{At: at}, captureOf(dumpAfter)),
		Diff(captureOf(dumpBefore), Capture{At: at}),
		Diff(captureOf(strings.Replace(dumpBefore, "goroutine 18", "goroutine ?", 1)),
			captureOf(strings.Replace(dumpAfter, "goroutine 18", "goroutine ?", 1))),
	}
	scanned := 0
	for _, rep := range reports {
		msgs := rep.Messages()
		if len(msgs) == 0 {
			t.Fatal("a report rendered nothing at all: silence that is not stated reads as a pass")
		}
		for _, m := range msgs {
			scanned++
			if !strings.HasPrefix(m, "L3 sampling: ") {
				t.Errorf("message %q is not labelled: a line in a test log has no heading above it", m)
			}
			lower := strings.ToLower(m)
			for _, word := range forbidden {
				if strings.Contains(lower, word) {
					t.Errorf("message %q contains %q: L3 observes co-existence, never a cause", m, word)
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no messages were scanned: the gate proved nothing")
	}
}
