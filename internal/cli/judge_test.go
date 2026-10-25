package cli

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests assert on the two things the verdict adds to `watch`: what it says,
// and the exit code a CI job branches on.
//
// Both are asserted against real child processes. A verdict tested only against a
// hand-built timeline would prove the renderer works and nothing about the claim -
// and the claim is the whole feature.

// judgeJSON mirrors the wire shape of `fdscope watch --judge --json`.
//
// The verdict is nested under "verdict" so the same document also carries the shape
// report: two top-level JSON values on stdout is not a document any parser accepts.
type judgeJSON struct {
	PID     int    `json:"pid"`
	Samples int    `json:"samples"`
	Summary string `json:"summary"`
	Verdict struct {
		Leaking bool `json:"leaking"`
		Total   struct {
			Leak       bool   `json:"leak"`
			Confidence string `json:"confidence"`
			Reason     string `json:"reason"`
			Evidence   struct {
				WindowSamples int  `json:"window_samples"`
				BaselineValue int  `json:"baseline_value"`
				Growth        int  `json:"growth"`
				Constant      bool `json:"constant"`
				Limit         int  `json:"limit"`
				Remaining     int  `json:"remaining"`
			} `json:"evidence"`
		} `json:"total"`
		Series []struct {
			Fingerprint string `json:"fingerprint"`
			Leak        bool   `json:"leak"`
		} `json:"series"`
	} `json:"verdict"`
}

// TestWatchJudgeConvictsARealLeak is the positive case: a child that opens
// descriptors and keeps them must be convicted, and the process must exit with the
// code CI matches on.
//
// The exit code is asserted before the text, because a run that prints the right
// word and exits 0 is indistinguishable from a clean run to the only consumer that
// matters.
func TestWatchJudgeConvictsARealLeak(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
i=0
for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
  while [ ! -e "$d/marker-$step" ]; do sleep 0.01; done
  for n in 1 2 3 4; do
    i=$((i+1))
    exec {fd}>"$d/leak-$i.log"
  done
  echo done > "$d/ack-$step"
done
echo open=$i
while :; do sleep 0.05; done
`)

	type run struct {
		out string
		err error
	}
	done := make(chan run, 1)
	go func() {
		out, err := runWatchCLI(t, bin, ch.pid(), "--judge", "--json",
			"--interval", "150ms", "--samples", "24")
		done <- run{out, err}
	}()
	for step := 1; step <= 18; step++ {
		waitForSample(t, dir, step)
		time.Sleep(200 * time.Millisecond)
	}
	r := <-done

	// The premise: the child was driven to open 68 files and closed none. Assert it
	// rather than
	// assume it - a fixture that opened fewer would leave the rise below the
	// growth floor, and the verdict would then be right for the wrong reason.
	opened, globErr := filepath.Glob(filepath.Join(dir, "leak-*.log"))
	if globErr != nil {
		t.Fatalf("glob: %v", globErr)
	}
	// Seventeen driven steps of four, plus whatever the last step added before the
	// sampler stopped. The floor is the driven ones: the verdict must be reachable
	// from growth the test deliberately caused, not from a race.
	if len(opened) < 68 {
		t.Fatalf("the child opened %d of the 68 descriptors it was driven to open: the fixture did not "+
			"create the leak it tests. child output:\n%s", len(opened), ch.out.String())
	}

	// Assert the exit code the process actually returned, not errors.Is on the
	// sentinel: the sentinel travels inside the library, and by the time main has
	// turned it into an exit status the identity is gone. A test that checked the
	// sentinel would pass while the binary exited 0.
	var exitErr *exec.ExitError
	if !errors.As(r.err, &exitErr) {
		t.Fatalf("watching an unclosed fan-out returned %v, want a non-zero exit\n%s", r.err, r.out)
	}
	if got := exitErr.ExitCode(); got != ExitLeakFound {
		t.Fatalf("exit = %d, want %d: a process holding every descriptor it opened must convict\n%s",
			got, ExitLeakFound, r.out)
	}

	var rep judgeJSON
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatalf("--judge --json is not one valid JSON document: %v\n%s", err, r.out)
	}
	if !rep.Verdict.Leaking {
		t.Fatalf("leaking = false, want true for a monotonically rising count\n%s", r.out)
	}
	if !rep.Verdict.Total.Leak {
		t.Errorf("total.leak = false, want true: the rise is on the process total\n%s", r.out)
	}
	// The rise happened inside the window, so it is a watched leak and must not be
	// excused as "growth predates the window".
	if rep.Verdict.Total.Evidence.Constant {
		t.Errorf("evidence.constant = true, but the child was opening descriptors throughout: %s", r.out)
	}
	if rep.Verdict.Total.Evidence.Growth <= 0 {
		t.Errorf("evidence.growth = %d, want a positive rise: the verdict must carry its numbers",
			rep.Verdict.Total.Evidence.Growth)
	}
	if rep.Summary == "" {
		t.Error("summary is empty: the one-line conclusion is what a CI log gets read from")
	}
	// The per-path rows are flat - each path is held exactly once - so the leak
	// must be attributed to the total and not to a fabricated series.
	for _, s := range rep.Verdict.Series {
		if s.Leak && !strings.Contains(s.Fingerprint, "leak-") {
			t.Errorf("%q was convicted but is not part of the fixture", s.Fingerprint)
		}
	}
}

// TestWatchJudgeClearsAHealthyProcess is the reverse assertion, and it is the more
// important of the two: a tool that convicts a steady process is worse than no tool.
//
// The child opens a fixed set of files, then only touches them. Nothing grows, so
// there is nothing to convict - and the exit code must be zero.
func TestWatchJudgeClearsAHealthyProcess(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
# A fixed working set: opened once, then only reopened. This is every well-behaved
# process - a pool at its steady state - and it must not be convicted.
for n in 1 2 3 4 5 6 7 8; do
  exec {fd}>"$d/steady-$n.log"
done
echo ready
for step in 1 2 3 4 5 6; do
  while [ ! -e "$d/marker-$step" ]; do sleep 0.01; done
  # Touch the existing files: the count must not move.
  for n in 1 2 3 4 5 6 7 8; do
    : > "$d/steady-$n.log"
  done
  echo done > "$d/ack-$step"
done
while :; do sleep 0.05; done
`)

	type run struct {
		out string
		err error
	}
	done := make(chan run, 1)
	go func() {
		out, err := runWatchCLI(t, bin, ch.pid(), "--judge", "--json",
			"--interval", "250ms", "--samples", "10")
		done <- run{out, err}
	}()
	for step := 1; step <= 6; step++ {
		waitForSample(t, dir, step)
		time.Sleep(130 * time.Millisecond)
	}
	r := <-done

	if r.err != nil {
		t.Fatalf("a steady process was convicted (exit %v); a false alarm costs the tool its reader\n%s",
			r.err, r.out)
	}
	var rep judgeJSON
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatalf("--judge --json is not one valid JSON document: %v\n%s", err, r.out)
	}
	if rep.Verdict.Leaking {
		t.Fatalf("leaking = true for a fixed working set\n%s", r.out)
	}
	// The constant window must be reported as a fact even when it is not a leak:
	// a reader deciding whether to trust "no leak" needs to know the count never
	// moved at all.
	if !rep.Verdict.Total.Evidence.Constant {
		t.Errorf("evidence.constant = false for a fixed working set; the series never changed")
	}
}

// TestWatchWithoutJudgeIsSilent pins that the verdict is opt-in.
//
// `watch` reports shapes. A rising series is also a pool warming up, so a tool that
// volunteered a verdict on every run would teach its reader to skip the word.
func TestWatchWithoutJudgeIsSilent(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
for step in 1 2 3 4; do
  while [ ! -e "$d/marker-$step" ]; do sleep 0.01; done
  exec {fd}>"$d/x-$step.log"
  echo done > "$d/ack-$step"
done
while :; do sleep 0.05; done
`)
	type run struct {
		out string
		err error
	}
	done := make(chan run, 1)
	go func() {
		out, err := runWatchCLI(t, bin, ch.pid(), "--interval", "200ms", "--samples", "5")
		done <- run{out, err}
	}()
	for step := 1; step <= 4; step++ {
		waitForSample(t, dir, step)
		time.Sleep(100 * time.Millisecond)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("plain watch failed: %v\n%s", r.err, r.out)
	}
	for _, word := range []string{"verdict:", "LEAK", "no leak"} {
		if strings.Contains(r.out, word) {
			t.Errorf("plain watch printed %q without --judge; the verdict must be opt-in:\n%s",
				word, r.out)
		}
	}
}

// TestJudgeTableCarriesItsEvidence checks the human-readable renderer: the verdict
// word must be present and so must the numbers behind it.
//
// A verdict without its evidence is an opinion, and an operator told "LEAK" asks
// "how do you know" - the answer has to be on the same screen.
func TestJudgeTableCarriesItsEvidence(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := stagedChild(t, `
echo ready
i=0
for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do
  while [ ! -e "$d/marker-$step" ]; do sleep 0.01; done
  for n in 1 2 3 4; do
    i=$((i+1))
    exec {fd}>"$d/leak-$i.log"
  done
  echo done > "$d/ack-$step"
done
echo open=$i
while :; do sleep 0.05; done
`)
	type run struct {
		out string
		err error
	}
	done := make(chan run, 1)
	go func() {
		out, err := runWatchCLI(t, bin, ch.pid(), "--judge", "--interval", "150ms", "--samples", "24")
		done <- run{out, err}
	}()
	for step := 1; step <= 18; step++ {
		waitForSample(t, dir, step)
		time.Sleep(200 * time.Millisecond)
	}
	r := <-done
	if r.err == nil {
		t.Fatalf("expected a leak exit for an unclosed fan-out\n%s", r.out)
	}
	for _, want := range []string{"verdict: LEAK", "window:", "reason:", "GROWTH", "RATE", "BASELINE"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("table is missing %q; the verdict must carry the numbers behind it:\n%s", want, r.out)
		}
	}
}

// TestJudgeExitCodeIsDistinctFromFailure pins the two exit codes apart.
//
// CI branches on 2 meaning "a leak was found" and 1 meaning "the run failed". If a
// failed run also left 1 indistinguishable from a leak, a job could not tell "the
// audit could not run" from "the audit found nothing".
func TestJudgeExitCodeIsDistinctFromFailure(t *testing.T) {
	if ExitLeakFound == 1 {
		t.Fatal("ExitLeakFound must not be 1: that is reserved for a run that failed")
	}
	// A pid that cannot exist: the run must fail, not convict.
	bin := buildCLI(t)
	out, err := runWatchCLI(t, bin, 4194304, "--judge", "--samples", "3", "--interval", "10ms")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("watching a non-existent pid returned %v, want a process failure\n%s", err, out)
	}
	if got := exitErr.ExitCode(); got == ExitLeakFound {
		t.Fatalf("a failed run exited %d, the same code as a found leak\n%s", got, out)
	}
}
