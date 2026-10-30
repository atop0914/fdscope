package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sixDigitSecondCount matches a duration printed as five or more digits of
// seconds. It is the shape of the value the previous round printed - "crossed in
// about 524278s" - which was arithmetically right and unusable.
var sixDigitSecondCount = regexp.MustCompile(`\b\d{5,}s\b`)

// These tests run the shipped binary against real child processes, because the
// contract under test is the one a CI job consumes: three exit codes and a
// document. A test that called runCheck and inspected the returned error would
// pass while the binary exited 0 - the sentinel that carries "leak found" does
// not survive the trip through main, which is how an exit-code bug hides.

// checkJSON mirrors the wire shape of `fdscope check --json`.
type checkJSON struct {
	PID            int   `json:"pid"`
	IntervalMillis int64 `json:"interval_millis"`
	Snapshots      int   `json:"snapshots"`
	Incomplete     int   `json:"incomplete_snapshots"`
	WindowMillis   int64 `json:"window_millis"`
	Thresholds     struct {
		MinGrowth        int     `json:"min_growth"`
		MinGrowthRatio   float64 `json:"min_growth_ratio"`
		MinRatePerSecond float64 `json:"min_rate_per_second"`
		MinWindowMillis  int64   `json:"min_window_millis"`
		MinSamples       int     `json:"min_samples"`
		Warmup           float64 `json:"warmup"`
	} `json:"thresholds"`
	Totals  []int  `json:"totals"`
	Summary string `json:"summary"`
	// Headroom and Projection are the Day 6 additions. They are asserted through
	// the wire rather than from the Go structs because the three limit states are
	// only useful if they survive into the document a CI job parses.
	Headroom struct {
		PID       int    `json:"pid"`
		Used      int    `json:"used"`
		Limit     int    `json:"limit"`
		Hard      int    `json:"limit_hard"`
		State     string `json:"limit_state"`
		Unlimited bool   `json:"unlimited"`
		Known     bool   `json:"limit_known"`
	} `json:"headroom"`
	Projection struct {
		State         string  `json:"state"`
		Limit         int     `json:"limit"`
		Remaining     int     `json:"remaining"`
		RatePerSecond float64 `json:"rate_per_second"`
		RateSamples   int     `json:"rate_samples"`
		ETASeconds    float64 `json:"eta_seconds"`
		Confidence    string  `json:"confidence"`
		Note          string  `json:"note"`
	} `json:"projection"`
	Verdict struct {
		Leaking bool `json:"leaking"`
		Total   struct {
			Leak       bool   `json:"leak"`
			Confidence string `json:"confidence"`
			Reason     string `json:"reason"`
			Evidence   struct {
				WindowSamples  int `json:"window_samples"`
				Growth         int `json:"growth"`
				GrowthRequired int `json:"growth_required"`
				RiseStartIndex int `json:"rise_start_index"`
				RiseSamples    int `json:"rise_samples"`
			} `json:"evidence"`
		} `json:"total"`
	} `json:"verdict"`
}

// runCheckCLI runs `fdscope check` and returns stdout, stderr and the error.
//
// The stderr is returned because the three exit codes are only meaningful
// together with the sentence that explains them: "1" alone does not say whether
// the pid was missing or the window was too short.
func runCheckCLI(t *testing.T, bin string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"check"}, args...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), err
}

// exitCodeOf asserts that err is a non-zero exit and returns its code.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("returned %v, want a non-zero exit", err)
	}
	return exitErr.ExitCode()
}

// leakyChild opens one descriptor every 50ms and never closes any.
//
// It drives itself rather than waiting for the test to touch markers: `check` is
// a single blocking call, so a fixture that only moved when the test poked it
// would be sampling a process that was not doing anything - and would then be
// testing the opposite of what it claims.
func leakyChild(t *testing.T) (*child, string) {
	t.Helper()
	return stagedChild(t, `
echo ready
i=0
while :; do
  i=$((i+1))
  exec {fd}>"$d/leak-$i.log"
  sleep 0.05
done
`)
}

// TestCheckConvictsARealLeakAndExitsTwo is the positive case, and asserts the
// exit code before the text: a run that prints the right word and exits 0 is
// indistinguishable from a clean run to the only consumer that matters.
func TestCheckConvictsARealLeakAndExitsTwo(t *testing.T) {
	bin := buildCLI(t)
	ch, dir := leakyChild(t)

	out, errOut, err := runCheckCLI(t, bin, strconv.Itoa(ch.pid()), "--json",
		"--interval", "100ms", "--samples", "12", "--min-growth", "5")

	if got := exitCodeOf(t, err); got != ExitLeakFound {
		t.Fatalf("exit = %d, want %d for a process holding every descriptor it opened\nstdout:\n%s\nstderr:\n%s",
			got, ExitLeakFound, out, errOut)
	}

	// The premise, asserted rather than assumed: a fixture that opened fewer than
	// the growth floor would leave the verdict correct for the wrong reason.
	opened, globErr := filepath.Glob(filepath.Join(dir, "leak-*.log"))
	if globErr != nil {
		t.Fatalf("glob: %v", globErr)
	}
	if len(opened) < 10 {
		t.Fatalf("the child opened only %d descriptors during the window: it did not create the leak "+
			"this test asserts on. child output:\n%s", len(opened), ch.out.String())
	}

	var rep checkJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--json did not produce a parseable document: %v\n%s", err, out)
	}
	if !rep.Verdict.Leaking {
		t.Fatalf("verdict.leaking = false for a process that opened %d descriptors and closed none: %+v",
			len(opened), rep.Verdict)
	}
	if !rep.Verdict.Total.Leak {
		t.Fatalf("the leak was not attributed to the process total: %+v", rep.Verdict.Total)
	}

	// Auditability: the verdict must rest on a series, the series must show the
	// rise, and the growth the verdict names must be that rise.
	if len(rep.Totals) != 12 {
		t.Fatalf("recorded %d samples, want the 12 requested: %v", len(rep.Totals), rep.Totals)
	}
	rise := rep.Totals[len(rep.Totals)-1] - rep.Totals[0]
	if rise < 5 {
		t.Fatalf("the verdict claims a leak but the recorded series rose %d (%v): the numbers and the "+
			"conclusion disagree", rise, rep.Totals)
	}
	if rep.Verdict.Total.Evidence.Growth < rep.Thresholds.MinGrowth {
		t.Fatalf("evidence growth = %d is below the floor of %d the document reports as applied",
			rep.Verdict.Total.Evidence.Growth, rep.Thresholds.MinGrowth)
	}

	// The thresholds echoed are the ones applied, not the flags as typed: the
	// fields left at zero must appear as their defaults, or the document would
	// report comparisons that never happened.
	if rep.Thresholds.MinGrowth != 5 {
		t.Fatalf("thresholds.min_growth = %d, want the 5 that was passed", rep.Thresholds.MinGrowth)
	}
	if rep.Thresholds.Warmup != 0.2 || rep.Thresholds.MinSamples != 4 || rep.Thresholds.MinGrowthRatio != 0.10 {
		t.Fatalf("thresholds were not resolved to the defaults that were actually used: %+v", rep.Thresholds)
	}
	if !strings.Contains(rep.Summary, "leak") {
		t.Fatalf("summary = %q, want it to state the verdict", rep.Summary)
	}
}

// TestCheckClearsAHealthyProcessAndExitsZero is the reverse assertion, and the one
// that decides whether the command is usable at all: a process that fills a fixed
// set of descriptors at startup and holds it must not be convicted, however many
// it holds.
func TestCheckClearsAHealthyProcessAndExitsZero(t *testing.T) {
	bin := buildCLI(t)
	// The marker is printed after the opens, not before. It is what the test waits
	// for, and the test asserts that the level held for the whole window - so the
	// marker has to mean "the level is established". Printed first, the sampler could
	// start while the loop was still opening and record 25 -> 28, which is a real
	// observation of a real race in the fixture, not in the tool.
	ch, _ := stagedChild(t, `
i=0
while [ $i -lt 25 ]; do
  i=$((i+1))
  exec {fd}>"$d/hold-$i.log"
done
echo ready
while :; do sleep 0.05; done
`)

	out, errOut, err := runCheckCLI(t, bin, strconv.Itoa(ch.pid()), "--json",
		"--interval", "50ms", "--samples", "10")

	if err != nil {
		t.Fatalf("a process holding a fixed 25 descriptors was not cleared: %v\nstdout:\n%s\nstderr:\n%s",
			err, out, errOut)
	}
	var rep checkJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--json did not produce a parseable document: %v\n%s", err, out)
	}
	if rep.Verdict.Leaking {
		t.Fatalf("a process that opened nothing during the window was convicted: %+v", rep.Verdict)
	}
	if len(rep.Totals) == 0 {
		t.Fatal("no series was recorded: a clean verdict with no evidence behind it is not a clean verdict")
	}
	// The level held, rather than drifting: the verdict is only right if the
	// window really was the shape the criteria were written for.
	if first, last := rep.Totals[0], rep.Totals[len(rep.Totals)-1]; last != first {
		t.Fatalf("the fixture did not hold a level (%d -> %d, %v): it is not testing what it claims",
			first, last, rep.Totals)
	}

	// The headroom is still reported on a clean run - "not leaking" must not hide
	// that a process is sitting close to its limit - and the limit state is the
	// one the container really has.
	if !rep.Headroom.Known {
		t.Fatalf("headroom.limit_known = false for a live process: %+v", rep.Headroom)
	}
	if rep.Headroom.State != "known" {
		t.Fatalf("headroom.limit_state = %q, want known", rep.Headroom.State)
	}
	if rep.Headroom.Limit <= 0 {
		t.Fatalf("headroom.limit = %d, want the process's real soft limit", rep.Headroom.Limit)
	}
	if rep.Headroom.Used != rep.Totals[len(rep.Totals)-1] {
		t.Fatalf("headroom.used = %d, want the last sample's total %d",
			rep.Headroom.Used, rep.Totals[len(rep.Totals)-1])
	}

	// The reverse assertion for the projection: a flat window produces no ETA.
	// A countdown here would be a prediction manufactured out of no growth.
	if rep.Projection.ETASeconds != 0 {
		t.Fatalf("projection.eta_seconds = %v on a flat window; a non-leak must not be given a countdown",
			rep.Projection.ETASeconds)
	}
	if rep.Projection.State != "no-growth" {
		t.Fatalf("projection.state = %q, want no-growth", rep.Projection.State)
	}
}

// TestCheckReportsHeadroomAgainstARealLowLimit is the acceptance case for Day 6:
// a real child raises nothing but lowers its own RLIMIT_NOFILE, fills most of it,
// and then leaks into the remainder. The limit, the remaining count and the ETA
// must all come from that process rather than from a fixture.
func TestCheckReportsHeadroomAgainstARealLowLimit(t *testing.T) {
	bin := buildCLI(t)
	// 40 descriptors held, then one every 100ms. The limit is 64, so the window
	// ends with roughly a dozen descriptors left and the child does not hit
	// EMFILE mid-run - a fixture that died would turn this into a test of the
	// "lost the target" path instead.
	ch, dir := stagedChild(t, `
ulimit -n 64
echo ready
i=0
while [ $i -lt 30 ]; do
  i=$((i+1))
  exec {fd}>"$d/fill-$i.log"
done
while :; do
  i=$((i+1))
  exec {fd}>"$d/leak-$i.log"
  sleep 0.1
done
`)

	out, errOut, err := runCheckCLI(t, bin, strconv.Itoa(ch.pid()), "--json",
		"--interval", "100ms", "--samples", "12", "--min-growth", "5")

	if got := exitCodeOf(t, err); got != ExitLeakFound {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, ExitLeakFound, out, errOut)
	}
	var rep checkJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--json did not produce a parseable document: %v\n%s", err, out)
	}

	// The premise: the child really did lower its own limit, so the number below
	// is read from /proc/<pid>/limits and not from the test's imagination.
	if rep.Headroom.Limit != 64 {
		t.Fatalf("headroom.limit = %d, want the 64 the child set with ulimit", rep.Headroom.Limit)
	}
	if !rep.Headroom.Known || rep.Headroom.State != "known" {
		t.Fatalf("headroom limit state = %q (known=%t), want known", rep.Headroom.State, rep.Headroom.Known)
	}
	if rep.Headroom.Hard < 64 {
		t.Fatalf("headroom.limit_hard = %d, want the hard column of the limits file", rep.Headroom.Hard)
	}
	last := rep.Totals[len(rep.Totals)-1]
	if rep.Headroom.Used != last {
		t.Fatalf("headroom.used = %d, want the last sample's total %d", rep.Headroom.Used, last)
	}
	if want := 64 - last; rep.Headroom.Limit-rep.Headroom.Used != want {
		t.Fatalf("remaining = %d, want %d (64 - %d open)", rep.Headroom.Limit-rep.Headroom.Used, want, last)
	}

	// The ETA must be reproducible from the document itself: the rate has to
	// describe the judged window's own series, in descriptors per *second*.
	//
	// This is where the old unit bug lived. It divided the remaining descriptors
	// by descriptors-per-*sample*, so on a 100ms interval the countdown came out
	// ten times too long - arithmetically consistent with nothing, and impossible
	// to notice without comparing the rate against the series it came from.
	if rep.Projection.State != "projected" {
		t.Fatalf("projection.state = %q, want projected: %+v", rep.Projection.State, rep.Projection)
	}
	ev := rep.Verdict.Total.Evidence
	if ev.RiseSamples < 2 || ev.RiseStartIndex < 0 || ev.RiseStartIndex+ev.RiseSamples > len(rep.Totals) {
		t.Fatalf("the verdict's rise window (%d at %d) does not fit the series (%d samples)",
			ev.RiseSamples, ev.RiseStartIndex, len(rep.Totals))
	}
	rise := rep.Totals[ev.RiseStartIndex : ev.RiseStartIndex+ev.RiseSamples]
	observedRate := float64(rise[len(rise)-1]-rise[0]) / (float64(len(rise)-1) * 0.1)
	if observedRate <= 0 {
		t.Fatalf("the judged window did not rise (%v), so there is no rate to check against", rise)
	}
	if diff := rep.Projection.RatePerSecond - observedRate; diff > observedRate*0.2 || diff < -observedRate*0.2 {
		t.Fatalf("projection.rate = %.3f/s, but the series it claims to describe rose %.3f/s (%v)",
			rep.Projection.RatePerSecond, observedRate, rise)
	}
	wantETA := float64(rep.Projection.Remaining) / observedRate
	if diff := rep.Projection.ETASeconds - wantETA; diff > wantETA*0.2 || diff < -wantETA*0.2 {
		t.Fatalf("eta_seconds = %.2f, want %.2f +/-20%% (remaining %d at %.3f/s)",
			rep.Projection.ETASeconds, wantETA, rep.Projection.Remaining, observedRate)
	}
	// A sanity floor on the fixture: if the child had stopped opening, the
	// series above would be flat and this test would be asserting on nothing.
	if observedRate < 1 {
		t.Fatalf("the child opened descriptors at only %.3f/s; it was not leaking during the window", observedRate)
	}
	if rep.Projection.Note == "" {
		t.Fatal("projection.note is empty: an ETA must carry the basis it was computed from")
	}

	// The reason string is what an operator reads first, and it must be the same
	// story with a readable unit.
	reason := rep.Verdict.Total.Reason
	if sixDigitSecondCount.MatchString(reason) {
		t.Fatalf("reason = %q contains a six-digit second count", reason)
	}
	if !strings.Contains(reason, "below the limit of 64") {
		t.Fatalf("reason = %q, want it to name the limit of 64", reason)
	}

	// And the same numbers must be on the table for a human reading the log.
	out2, errOut2, err2 := runCheckCLI(t, bin, strconv.Itoa(ch.pid()),
		"--interval", "100ms", "--samples", "12", "--min-growth", "5")
	if got := exitCodeOf(t, err2); got != ExitLeakFound {
		t.Fatalf("table run exit = %d, want %d\n%s\n%s", got, ExitLeakFound, out2, errOut2)
	}
	if !strings.Contains(out2, "left of 64") {
		t.Fatalf("the table does not show the headroom against 64:\n%s", out2)
	}
	if sixDigitSecondCount.MatchString(out2) {
		t.Fatalf("the table contains a six-digit second count:\n%s", out2)
	}
	// The fixture's files exist, so the leak was real and not a phantom of the
	// sampler: this anchors the whole test to a side effect.
	opened, globErr := filepath.Glob(filepath.Join(dir, "leak-*.log"))
	if globErr != nil {
		t.Fatalf("glob: %v", globErr)
	}
	if len(opened) < 8 {
		t.Fatalf("the child opened only %d leaked files during the window", len(opened))
	}
}

// TestCheckFailsWhenTheTargetDisappears covers the exit code that carries the
// whole point of the command: a run that lost its target halfway through has
// collected evidence but cannot support a verdict, and answering "no leak" there
// would pass a job whose target is broken.
//
// The child is made to die late enough that four or five samples were collected
// before it went. That detail is the test: with fewer than the judge's minimum the
// refusal would come from the "not enough samples" rule instead, and this test
// would then pass while the "an interrupted run is not a verdict" rule was broken.
func TestCheckFailsWhenTheTargetDisappears(t *testing.T) {
	bin := buildCLI(t)
	ch, _ := stagedChild(t, `
echo ready
sleep 0.45
exit 0
`)

	out, errOut, err := runCheckCLI(t, bin, strconv.Itoa(ch.pid()), "--interval", "100ms", "--samples", "12")

	got := exitCodeOf(t, err)
	if got == ExitLeakFound {
		t.Fatalf("exit = %d: a process that died was reported as a leak\nstdout:\n%s\nstderr:\n%s", got, out, errOut)
	}
	if got != 1 {
		t.Fatalf("exit = %d, want 1 for a check that could not complete\nstdout:\n%s\nstderr:\n%s", got, out, errOut)
	}
	if !strings.Contains(errOut, "stopped after") {
		t.Fatalf("stderr does not say the run was cut short:\n%s", errOut)
	}
	// The number of samples salvaged belongs in the message: "stopped" alone
	// leaves the reader unable to tell a near-miss from an immediate failure.
	if !strings.Contains(errOut, "of 12 samples") {
		t.Fatalf("stderr does not say how much of the window was salvaged:\n%s", errOut)
	}
}

// TestCheckRefusesAWindowTooShortToJudge is the refusal edge. Three samples
// cannot separate a pool warming up from a leak, and the command must say so
// with exit 1 rather than pass a job on a window that proves nothing.
func TestCheckRefusesAWindowTooShortToJudge(t *testing.T) {
	bin := buildCLI(t)
	ch, _ := stagedChild(t, `
echo ready
while :; do sleep 0.05; done
`)

	out, errOut, err := runCheckCLI(t, bin, strconv.Itoa(ch.pid()), "--interval", "10ms", "--samples", "3")

	if got := exitCodeOf(t, err); got != 1 {
		t.Fatalf("exit = %d, want 1 for a window that cannot support a verdict\nstdout:\n%s\nstderr:\n%s",
			got, out, errOut)
	}
	if !strings.Contains(errOut, "not enough samples") {
		t.Fatalf("stderr does not name the reason:\n%s", errOut)
	}
}

// TestCheckFailsOnAMissingProcess keeps "no such process" out of the leak bucket.
func TestCheckFailsOnAMissingProcess(t *testing.T) {
	bin := buildCLI(t)

	out, errOut, err := runCheckCLI(t, bin, "4194304", "--interval", "10ms", "--samples", "4")

	if got := exitCodeOf(t, err); got != 1 {
		t.Fatalf("exit = %d, want 1 for a pid that does not exist\nstdout:\n%s\nstderr:\n%s", got, out, errOut)
	}
	if !strings.Contains(errOut, "process not found") {
		t.Fatalf("stderr does not identify the missing process:\n%s", errOut)
	}
}

// TestCheckRejectsUsageErrors keeps malformed invocations out of both other
// buckets, and out of the report: a usage error must not print a verdict.
func TestCheckRejectsUsageErrors(t *testing.T) {
	bin := buildCLI(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no pid", nil, "exactly one pid"},
		{"two pids", []string{"1", "2"}, "exactly one pid"},
		{"not a pid", []string{"self"}, "invalid pid"},
		{"one sample", []string{"1", "--samples", "1"}, "at least 2"},
		{"negative growth", []string{"1", "--min-growth", "-1"}, "must not be negative"},
		{"zero interval", []string{"1", "--interval", "0s"}, "must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, err := runCheckCLI(t, bin, tc.args...)
			if got := exitCodeOf(t, err); got != 1 {
				t.Fatalf("exit = %d, want 1 for a usage error", got)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Fatalf("stderr does not mention %q:\n%s", tc.want, errOut)
			}
			if strings.TrimSpace(out) != "" {
				t.Fatalf("a usage error printed a report:\n%s", out)
			}
		})
	}
}

// TestCheckTableNamesTheSeries keeps the human output auditable: the reader must
// be able to see the shape the verdict was computed on, not just the conclusion.
func TestCheckTableNamesTheSeries(t *testing.T) {
	bin := buildCLI(t)
	ch, _ := leakyChild(t)

	out, errOut, err := runCheckCLI(t, bin, strconv.Itoa(ch.pid()),
		"--interval", "100ms", "--samples", "10", "--min-growth", "5")

	if got := exitCodeOf(t, err); got != ExitLeakFound {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, ExitLeakFound, out, errOut)
	}
	for _, want := range []string{"totals:", "verdict: LEAK", "thresholds:", "process total: LEAK"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the table does not contain %q:\n%s", want, out)
		}
	}
	// The verdict must not be the only line: an operator told "LEAK" asks "how do
	// you know", and the answer has to be on the same screen.
	if !strings.Contains(out, "GROWTH") {
		t.Fatalf("the table shows the verdict without its evidence:\n%s", out)
	}
}

// TestSeriesLineTruncationDoesNotLie covers the one place the table shortens the
// series: an omission that is not stated would read as the whole window.
func TestSeriesLineTruncationDoesNotLie(t *testing.T) {
	short := []int{1, 2, 3}
	if got := seriesLine(short); got != "1 2 3" {
		t.Fatalf("seriesLine(%v) = %q, want every value", short, got)
	}

	long := make([]int, 100)
	for i := range long {
		long[i] = i
	}
	got := seriesLine(long)
	if !strings.Contains(got, fmt.Sprintf("%d samples omitted", 100-40)) {
		t.Fatalf("the truncated line does not say how many samples are missing: %q", got)
	}
	if !strings.Contains(got, "--json has all") {
		t.Fatalf("the truncated line does not say where the rest is: %q", got)
	}
	if !strings.HasPrefix(got, "0 1 ") || !strings.HasSuffix(got, strconv.Itoa(99)) {
		t.Fatalf("the truncated line does not keep both ends of the window: %q", got)
	}
}
