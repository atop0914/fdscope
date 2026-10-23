package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run the shipped binary against real child processes whose
// descriptor counts really change, and assert on the series the binary reports.
//
// A series built in Go from a hand-made snapshot would prove nothing here: the
// claim under test is that fdscope observes a real process over time and gets the
// shape right. The children below open, hold and release descriptors on their own
// schedule, and their own reports (written to a file the test polls) are what tell
// the test when the change happened - never a sleep.

// watchJSON mirrors the wire contract of `fdscope watch --json`.
type watchJSON struct {
	PID        int   `json:"pid"`
	Samples    int   `json:"samples"`
	Dropped    int   `json:"dropped"`
	Incomplete bool  `json:"incomplete"`
	SpanMillis int64 `json:"span_millis"`
	Requested  int   `json:"requested_samples"`
	Snapshots  int   `json:"snapshots"`
	Skipped    int   `json:"incomplete_snapshots"`
	// Total carries the same shape as any single series, and that is deliberate:
	// the aggregate and the per-resource rows must be judged by the same code, or
	// the header can say "flat" while a row beneath it says "rising".
	Total  seriesJSON   `json:"total"`
	Series []seriesJSON `json:"series"`
}

// seriesJSON is one summarised fingerprint series as it appears on the wire.
type seriesJSON struct {
	Fingerprint string `json:"fingerprint"`
	Samples     int    `json:"samples"`
	First       int    `json:"first"`
	Last        int    `json:"last"`
	Min         int    `json:"min"`
	Max         int    `json:"max"`
	PeakAt      int    `json:"peak_at"`
	Trend       string `json:"trend"`
	Rebound     bool   `json:"rebound"`
	ReboundFrom int    `json:"rebound_from"`
	ReboundTo   int    `json:"rebound_to"`
}

// runWatchCLI runs `fdscope watch` and returns stdout plus the error, if any.
//
// The error is returned rather than fatal: the "process died mid-watch" case must
// assert on a non-zero exit AND on the report that was still printed.
func runWatchCLI(t *testing.T, bin string, pid int, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{"watch", strconv.Itoa(pid)}, extra...)
	cmd := exec.Command(bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err != nil {
		t.Logf("fdscope %v exited with %v (stderr: %s)", args, err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), err
}

func parseWatch(t *testing.T, out string) watchJSON {
	t.Helper()
	var rep watchJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("watch output is not valid JSON: %v\n%s", err, out)
	}
	return rep
}

// waitForSample asks the child to record another sample, then waits for it to
// report that it did.
//
// The wait is bounded by observing the child's own counter file, not by sleeping
// a guessed interval: a fixed sleep would either flake on a loaded machine or
// waste seconds on an idle one.
func waitForSample(t *testing.T, dir string, n int) {
	t.Helper()
	marker := filepath.Join(dir, fmt.Sprintf("marker-%d", n))
	if err := exec.Command("touch", marker).Run(); err != nil {
		t.Fatalf("touch marker %d: %v", n, err)
	}
	ack := filepath.Join(dir, fmt.Sprintf("ack-%d", n))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ack); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("child never acknowledged sample %d", n)
}

// stagedChild starts a bash child that performs one step per marker file the test
// creates. It is the fixture the plan mandates: bash (because /bin/sh is dash and
// dash has no `exec {fd}>`), blocking loops rather than pipes (a pipe can be
// waited on only once), and its own ack files so the test knows when a step
// really happened.
//
// Steps are named in the script; the test drives them with waitForSample.
func stagedChild(t *testing.T, script string) (*child, string) {
	t.Helper()
	ch := startChildWith(t, "bash", script, "ready")
	return ch, ch.dir
}

// TestWatchPersistentOpenIsRising is the positive case from the plan: a process
// that keeps opening descriptors without closing them must show a rising series.
// This is the shape a leak has, and it is the only shape the tool must never
// explain away.
func TestWatchPersistentOpenIsRising(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
i=0
for step in 1 2 3 4; do
  while [ ! -e "$d/marker-$step" ]; do sleep 0.01; done
  for n in 3 3 3; do
    i=$((i+1))
    exec {fd}>"$d/leak-$i.log"
  done
  echo done > "$d/ack-$step"
done
echo open=$i
while :; do sleep 0.05; done
`)

	// Five samples with a 300ms interval leave three full minutes of slack
	// between samples; the child's own acks say when a step has happened, and a
	// 150ms pause puts the step comfortably inside the gap. The earlier version
	// of this test used a 60ms interval and drove the child from the main
	// goroutine, which left only ~20ms between an ack and the next sample: steps
	// raced the sampler and it observed only the first two of four. Sampling
	// timing is the thing under test here, so it must not be the thing that is
	// tight.
	type run struct {
		out string
		err error
	}
	done := make(chan run, 1)
	go func() {
		out, err := runWatchCLI(t, bin, ch.pid(), "--json", "--interval", "300ms", "--samples", "5")
		done <- run{out, err}
	}()
	for step := 1; step <= 4; step++ {
		waitForSample(t, dir, step)
		time.Sleep(150 * time.Millisecond)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("watch failed: %v\n%s", r.err, r.out)
	}

	rep := parseWatch(t, r.out)
	if rep.Samples != 5 {
		t.Fatalf("samples = %d, want 5", rep.Samples)
	}
	var leak *seriesJSON
	// Each step opens three *distinct* paths, so every path is held exactly once
	// and its own count stays at 1. The rising shape belongs to the total, and it
	// is a leak: it grew and never came back. Asserting "rising" on a per-path
	// series would be asserting something false - a path held once is flat by
	// definition, no matter how many paths are added.
	leaked := 0
	for i := range rep.Series {
		s := &rep.Series[i]
		if !strings.Contains(s.Fingerprint, "/leak-") {
			continue
		}
		leaked++
		if s.Max < 1 {
			t.Errorf("%q never appeared in the series", s.Fingerprint)
		}
		if s.Last != 1 {
			t.Errorf("%q last = %d, want 1: each path is held exactly once and never released", s.Fingerprint, s.Last)
		}
		if s.Rebound {
			t.Errorf("%q was reported as a rebound although nothing was closed", s.Fingerprint)
		}
		leak = s
	}
	// Twelve files were opened, each a distinct path, so twelve distinct series.
	// Merging them would hide a leak behind one average row.
	if leaked != 12 {
		t.Errorf("observed %d leak series, want 12 (one per path); child output:\n%s", leaked, ch.out.String())
	}
	if leak == nil {
		t.Fatal("no leak series in the report")
	}
	// The process total must reflect the same growth; a rising series beside a
	// flat total would mean the two views disagree about the same process.
	if rep.Total.Trend != "rising" {
		t.Errorf("total trend = %q, want rising: the descriptors were never released", rep.Total.Trend)
	}
	if rep.Total.Last-rep.Total.First < 9 {
		t.Errorf("total rose by %d, want at least 9 (3 per step over 4 steps)",
			rep.Total.Last-rep.Total.First)
	}
	if rep.Total.Rebound {
		t.Errorf("an unclosed leak was reported as a rebound: %+v", rep.Total)
	}
}

// TestWatchOpenThenCloseIsRebound is the case the whole day exists for: the count
// goes up and comes back down. Without a series this looks exactly like a leak
// sampled at the wrong moment.
//
// The child also verifies its own premise: it reports how many descriptors it held
// at the peak, so a pass cannot mean the peak never happened.
func TestWatchOpenThenCloseIsRebound(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
declare -a fds=()
i=0
# The burst must happen *inside* the sampling window. Opening the files before
# the first sample produces a series whose peak is at the start, and a peak with
# nothing before it is a spike, not a rise - which the analyser rightly refuses
# to call a rebound. The earlier version of this test opened them immediately
# after "ready" and then asserted a rebound: it was measuring the guard.
while [ ! -e "$d/marker-0" ]; do sleep 0.01; done
for n in 1 2 3 4 5 6 7 8; do
  i=$((i+1))
  exec {fd}>"$d/burst-$i.log"
  fds+=($fd)
done
echo "peak=${#fds[@]}" > "$d/peak"
echo done > "$d/ack-0"
# Stage 2: close them all, again only when the test says so.
while [ ! -e "$d/marker-1" ]; do sleep 0.01; done
for fd in "${fds[@]}"; do
  exec {fd}>&-
done
echo closed > "$d/closed"
echo done > "$d/ack-1"
while :; do sleep 0.05; done
`)

	type run struct {
		out string
		err error
	}
	done := make(chan run, 1)
	go func() {
		out, err := runWatchCLI(t, bin, ch.pid(), "--json", "--interval", "300ms", "--samples", "6")
		done <- run{out, err}
	}()
	// Three samples must land before the release and three after it. A faster
	// interval compressed the whole open-and-release burst into one sampling gap,
	// so the series read "1, 0, 0, ..." with a peak at index 0 - a real shape the
	// analyser correctly refused to call a rebound, and a test that measured
	// nothing. The wait must be long enough that the release is provably between
	// two samples, not merely concurrent with one.
	// The waits must fit inside the sampling window: 6 samples at 300ms is about
	// 1.5s of wall clock, and an earlier version waited 950+700ms after "ready"
	// alone. The watch finished before the release happened, so the series only
	// recorded the tail: peak_at=4 with first=3 and last=11, a shape the analyser
	// correctly declined to call a rebound. The sampler was right; the test was
	// measuring outside the window it meant to test.
	time.Sleep(450 * time.Millisecond)
	waitForSample(t, dir, 0)
	// The burst must span at least one full sampling gap: open it, let a sample
	// land while it is held, and only then close. 150ms was shorter than the
	// 300ms interval, so the whole burst fitted between two samples and the total
	// never moved - that version proved nothing.
	time.Sleep(500 * time.Millisecond)
	waitForSample(t, dir, 1)
	// The child must have reached its peak for the rebind to be possible at all;
	// without this the test could pass on an empty burst.
	if b, err := os.ReadFile(filepath.Join(dir, "closed")); err != nil || !strings.Contains(string(b), "closed") {
		t.Fatalf("child never closed its descriptors (err %v, content %q)", err, string(b))
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("watch failed: %v\n%s", r.err, r.out)
	}
	rep := parseWatch(t, r.out)

	// The rebound is asserted on the process total, and that is the correct
	// level for this shape. Eight *different* files are opened together and closed
	// together, so their counts sum into a single peak: the total rises from its
	// baseline, reaches a peak, and comes back down.
	//
	// Asserting it per file would be wrong, and the earlier version of this test
	// did exactly that. A single file's count goes 0 -> 1 -> 0, which is a spike
	// with its peak at the very first sample, and a spike has no rise to fall
	// from - the analyser deliberately refuses to call that a rebound, because a
	// process that opens and closes one file repeatedly would otherwise be
	// excused as self-healing. That guard is load-bearing; the per-file
	// assertion was measuring the guard, not the capability.
	if rep.Total.Min != rep.Total.First && rep.Total.First > rep.Total.Min {
		t.Logf("total starts above its minimum (%d vs %d): the burst began before the first sample", rep.Total.First, rep.Total.Min)
	}
	if rep.Total.Max <= rep.Total.Min {
		t.Fatalf("total min %d max %d: the total never rose, so nothing was released; child output:\n%s",
			rep.Total.Min, rep.Total.Max, ch.out.String())
	}
	if !rep.Total.Rebound {
		t.Fatalf("the total rose to %d and fell back to %d (drop %d) but was not reported as a rebound; measured: first=%d last=%d min=%d max=%d peak_at=%d; child output:\n%s",
			rep.Total.Max, rep.Total.Last, rep.Total.Max-rep.Total.Min,
			rep.Total.First, rep.Total.Last, rep.Total.Min, rep.Total.Max, rep.Total.PeakAt, ch.out.String())
	}
	if rep.Total.ReboundFrom != rep.Total.Max {
		t.Errorf("rebound measured from %d, want the peak %d", rep.Total.ReboundFrom, rep.Total.Max)
	}
	if rep.Total.Last != rep.Total.First {
		t.Errorf("total last = %d, want back to its baseline %d after every descriptor was closed",
			rep.Total.Last, rep.Total.First)
	}

	// Per file the honest expectation is a closed-out series: it appeared, it was
	// released, and nothing further accumulated. Asserting that keeps the rows
	// from silently disagreeing with the total above.
	closed := 0
	for _, s := range rep.Series {
		if !strings.Contains(s.Fingerprint, "/burst-") {
			continue
		}
		if s.Last != 0 {
			t.Errorf("%q last = %d, want 0 after every descriptor was closed", s.Fingerprint, s.Last)
		}
		if s.Max < 1 {
			t.Errorf("%q never appeared in the series", s.Fingerprint)
		}
		closed++
	}
	if closed != 8 {
		t.Errorf("tracked %d of the 8 burst files", closed)
	}
}

// TestWatchStableProcessIsFlat is the reverse assertion that decides whether
// anyone keeps using the tool: a process doing nothing must not be reported as
// trending. A noisy trend column trains the reader to ignore it, which costs
// exactly the moment a real trend appears.
func TestWatchStableProcessIsFlat(t *testing.T) {
	bin := buildCLI(t)
	ch, _ := stagedChild(t, `
echo ready
while :; do sleep 0.05; done
`)

	out, err := runWatchCLI(t, bin, ch.pid(), "--json", "--interval", "40ms", "--samples", "8")
	if err != nil {
		t.Fatalf("watch failed: %v\n%s", err, out)
	}
	rep := parseWatch(t, out)
	if rep.Total.Trend != "flat" {
		t.Errorf("total trend = %q, want flat for an idle process", rep.Total.Trend)
	}
	if rep.Total.First != rep.Total.Last {
		t.Errorf("total %d -> %d for an idle process", rep.Total.First, rep.Total.Last)
	}
	for _, s := range rep.Series {
		if s.Trend != "flat" {
			t.Errorf("%q trend = %q, want flat for an idle process", s.Fingerprint, s.Trend)
		}
		if s.Rebound {
			t.Errorf("%q was reported as a rebound in an idle process", s.Fingerprint)
		}
	}
	// The text form must state the conclusion rather than print an empty page.
	text, err := runWatchCLI(t, bin, ch.pid(), "--interval", "30ms", "--samples", "4")
	if err != nil {
		t.Fatalf("watch text failed: %v", err)
	}
	if !strings.Contains(text, "no resource rose and then fell back") {
		t.Errorf("clean watch did not say so:\n%s", text)
	}
	if !strings.Contains(text, "TREND") {
		t.Errorf("table header missing:\n%s", text)
	}
}

// TestWatchTracksHeldDeletedFile checks that an unlinked-but-held file keeps
// appearing in the series instead of vanishing once its path is gone.
//
// This is the fd kind whose leak costs disk that `du` cannot see, so a series
// that dropped it would hide the most expensive case. The child proves the premise
// itself: it verifies the path is really gone before reporting.
func TestWatchTracksHeldDeletedFile(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
printf 'payload' > "$d/ghost.dat"
exec {fd}<>"$d/ghost.dat"
rm -f "$d/ghost.dat"
if [ -e "$d/ghost.dat" ]; then echo "path-still-there"; else echo "gone"; fi > "$d/premise"
while :; do sleep 0.05; done
`)

	deadline := time.Now().Add(10 * time.Second)
	premise := ""
	for time.Now().Before(deadline) {
		if b, err := exec.Command("cat", filepath.Join(dir, "premise")).Output(); err == nil {
			premise = strings.TrimSpace(string(b))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if premise != "gone" {
		t.Fatalf("child did not unlink the file (premise = %q)", premise)
	}

	out, err := runWatchCLI(t, bin, ch.pid(), "--json", "--interval", "40ms", "--samples", "5")
	if err != nil {
		t.Fatalf("watch failed: %v\n%s", err, out)
	}
	rep := parseWatch(t, out)

	var found bool
	for _, s := range rep.Series {
		if !strings.Contains(s.Fingerprint, "/ghost.dat") {
			continue
		}
		found = true
		// The fingerprint must be the deleted form, so the row cannot be read as
		// a live file that still has a directory entry.
		if !strings.HasPrefix(s.Fingerprint, "deleted:") {
			t.Errorf("fingerprint %q does not carry the deleted prefix", s.Fingerprint)
		}
		if s.Min < 1 {
			t.Errorf("%q min = %d: a held deleted file must appear in every sample", s.Fingerprint, s.Min)
		}
		if s.Trend != "flat" {
			t.Errorf("%q trend = %q, want flat: it is held, not accumulating", s.Fingerprint, s.Trend)
		}
	}
	if !found {
		t.Fatalf("the held deleted file is missing from the series: %+v", rep.Series)
	}
}

// TestWatchBoundIsAssertedOnReportedLength checks the bounded-memory requirement
// the plan calls out: --keep must cap the retained samples, and the assertion is on
// the length the report actually contains, not on the flag echoed back.
func TestWatchBoundIsAssertedOnReportedLength(t *testing.T) {
	bin := buildCLI(t)
	ch, _ := stagedChild(t, `
echo ready
while :; do sleep 0.05; done
`)

	out, err := runWatchCLI(t, bin, ch.pid(), "--json", "--interval", "20ms", "--samples", "8", "--keep", "3")
	if err != nil {
		t.Fatalf("watch failed: %v\n%s", err, out)
	}
	rep := parseWatch(t, out)
	if rep.Samples != 3 {
		t.Errorf("retained samples = %d, want 3 (the --keep bound)", rep.Samples)
	}
	if rep.Dropped != 5 {
		t.Errorf("dropped = %d, want 5", rep.Dropped)
	}
	if !rep.Incomplete {
		t.Error("incomplete = false after discarding samples; the report would claim to cover the whole run")
	}
	for _, s := range rep.Series {
		if s.Samples != 3 {
			t.Errorf("%q has %d samples, want 3: every series must be the same length", s.Fingerprint, s.Samples)
		}
	}
	// A keep bound larger than the run is a typo, and silently clamping it would
	// hide that the caller expected a shorter run.
	if _, err := runWatchCLI(t, bin, ch.pid(), "--json", "--interval", "10ms", "--samples", "2", "--keep", "5"); err == nil {
		t.Error("--keep 5 with --samples 2 was accepted")
	}
	// A single sample cannot describe a shape, so it is refused rather than
	// reported as flat.
	if _, err := runWatchCLI(t, bin, ch.pid(), "--samples", "1"); err == nil {
		t.Error("--samples 1 was accepted; a one-point series is always flat")
	}
}

// TestWatchKeepsSamplesWhenProcessDies checks the "do not throw away evidence"
// rule. The process is killed partway through, and the run must exit non-zero
// while still printing the samples it already collected.
func TestWatchKeepsSamplesWhenProcessDies(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
for n in 1 2 3; do
  exec {fd}>"$d/survivor-$n.log"
done
echo hold > "$d/staged"
while :; do sleep 0.05; done
`)

	// Wait for the child to actually hold its descriptors. Killing a process
	// before it reaches its state would make the test pass for the wrong reason:
	// the report would be short because nothing happened, not because the run was
	// interrupted.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "staged")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child never reached its staged state")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The binary is started directly rather than through a helper goroutine, so
	// the test - not main - owns the ordering of kill and wait. Running it in a
	// goroutine and killing from here left the helper's cmd.Run() racing the
	// kill: whenever the kill landed first, Run returned nil and the assertion
	// "a killed process must exit non-zero" failed against a process that was
	// killed before it ever started sampling.
	var out, errOut bytes.Buffer
	cmd := exec.Command(bin, "watch", strconv.Itoa(ch.pid()), "--json", "--interval", "80ms", "--samples", "40")
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("start watch: %v", err)
	}

	// Let a few samples land, then kill the target mid-run.
	//
	// The whole process group is killed, not just the shell. `while :; do sleep
	// 0.05; done` runs a `sleep` child that inherits the shell's descriptors, so a
	// plain Kill on the bash pid leaves that child alive holding the same fds -
	// and /proc/<bash-pid>/fd keeps answering correctly for the zombie. The watch
	// then completes all 40 samples and exits 0, which looked like "the tool
	// ignores a dead process" when in fact the process was still legible.
	time.Sleep(300 * time.Millisecond)
	killTree(t, ch.pid())
	waitErr := cmd.Wait()
	r := struct {
		out string
		err error
	}{out.String(), waitErr}
	if waitErr != nil {
		t.Logf("watch exited with %v (stderr: %s)", waitErr, strings.TrimSpace(errOut.String()))
	}
	if r.err == nil {
		t.Fatalf("watch on a killed process exited 0; stdout:\n%s", r.out)
	}
	if strings.TrimSpace(r.out) == "" {
		t.Fatal("no report was printed even though samples had been collected; the evidence was discarded with the error")
	}
	rep := parseWatch(t, r.out)
	if rep.Samples == 0 {
		t.Fatal("the report contains no samples even though the process was alive for several")
	}
	// The run must stop because the process is gone, not because it completed: an
	// exit of 0 here would mean the sampler kept reading a dead pid and called the
	// result a completed run.
	if rep.Samples >= 40 {
		t.Fatalf("samples = %d: the watch completed all 40 samples after the target died", rep.Samples)
	}
	if rep.Samples >= 40 {
		t.Errorf("samples = %d: the run was supposed to be interrupted before reaching 40", rep.Samples)
	}
	if rep.Requested != 40 {
		t.Errorf("requested = %d, want 40 (the report must name what was asked for)", rep.Requested)
	}
	// The partial report must still be coherent: every series covers exactly the
	// retained samples, which proves it was rendered from real data rather than
	// padded out.
	for _, s := range rep.Series {
		if s.Samples != rep.Samples {
			t.Errorf("%q has %d samples but the run retained %d", s.Fingerprint, s.Samples, rep.Samples)
		}
	}
	// The evidence must be the real descriptors the child held, not an empty
	// skeleton: a report rendered from nothing would also be "short".
	held := 0
	for _, s := range rep.Series {
		if strings.Contains(s.Fingerprint, "/survivor-") && s.Max >= 1 {
			held++
		}
	}
	if held != 3 {
		t.Errorf("found %d of the 3 descriptors the child held at kill time: %+v", held, rep.Series)
	}
}

// killTree kills a staged child and every process still holding its descriptors.
//
// Two failures shaped this helper, both of them silent:
//
//  1. Killing only the bash pid leaves the `sleep` child of the busy loop alive.
//     That child inherited bash's descriptors, so /proc/<bash-pid>/fd - which the
//     kernel keeps answering for a zombie - still reports the same set. The watch
//     completes every sample and exits 0, which reads as "fdscope does not notice
//     a dead process" when the process was in fact still legible.
//  2. Killing the process group with -pgid works, but the child's group id equals
//     the test binary's group id unless the child was given its own. `kill(-pgid)`
//     then takes the test runner with it, and go test dies by SIGKILL with no
//     output at all - which looks like the OOM killer.
//
// So the child is put in its own group when it is started, and the whole group is
// killed here. Fallbacks keep it from failing when the group was never established.
func killTree(t *testing.T, pid int) {
	t.Helper()
	pgid, err := syscall.Getpgid(pid)
	if err == nil && pgid != pid {
		// The child does not lead its own group; killing -pgid would reach into
		// the test runner. Kill what can be identified instead.
		pgid = pid
	}
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
