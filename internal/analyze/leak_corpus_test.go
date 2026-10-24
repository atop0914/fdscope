package analyze

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/probe"
	"github.com/atop0914/fdscope/internal/timeline"
)

// This file is the corpus: the shapes the verdict must never convict, each paired
// with a shape one criterion away that it must convict.
//
// The two failures of a leak detector are not symmetric. A missed leak costs a later
// investigation; a false alarm costs the tool, because an operator told "leak" three
// times by a healthy service stops reading the output - and then the tool occupies
// the place where a working alarm would have been.
//
// The pairing is what makes the corpus evidence. A negative case alone is satisfied
// by a detector that always says "not a leak"; a positive case alone by one that
// always says "leak". Each pair below differs in exactly the dimension one criterion
// is supposed to notice, and the assertion names that criterion.

// seriesOf builds a timeline with regular sample spacing from per-fingerprint count
// sequences.
//
// The counts are handed to timeline.Timeline rather than to a mock, so the judge
// reads them through the same accessors it uses in production.
func seriesOf(t *testing.T, fps map[string][]int, interval time.Duration) *timeline.Timeline {
	t.Helper()
	n := 0
	for _, c := range fps {
		if len(c) > n {
			n = len(c)
		}
	}
	if n == 0 {
		t.Fatal("seriesOf needs at least one series")
	}
	tl, err := timeline.New(4242, n)
	if err != nil {
		t.Fatalf("timeline.New: %v", err)
	}
	base := time.Now().UnixNano()
	for i := 0; i < n; i++ {
		counts := map[string]int{}
		total := 0
		for fp, cs := range fps {
			if i >= len(cs) || cs[i] == 0 {
				continue
			}
			counts[fp] = cs[i]
			total += cs[i]
		}
		if err := tl.Add(timeline.Sample{
			Taken:  base + int64(i)*int64(interval),
			Total:  total,
			Counts: counts,
		}); err != nil {
			t.Fatalf("Add sample %d: %v", i, err)
		}
	}
	return tl
}

// mustGlob returns the paths matching pattern, failing the test if the pattern
// matches nothing.
//
// A count of zero is the interesting failure here, so it is not left to a length
// comparison: glob against an empty directory returns no error, and a fixture that
// silently created nothing would then be indistinguishable from one whose premise
// failed for a real reason.
func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	return matches
}

// takenStamps collects the sample timestamps, for deriving the sampling period the
// way the analyser does.
func takenStamps(tl *timeline.Timeline) []int64 {
	out := make([]int64, 0, tl.Len())
	for _, s := range tl.Samples() {
		out = append(out, s.Taken)
	}
	return out
}

// judgeOne judges one fingerprint series and returns its verdict.
func judgeOne(t *testing.T, tl *timeline.Timeline, fp string, opts LeakOptions) LeakVerdict {
	t.Helper()
	v, err := JudgeSeries(tl.FingerprintSeries(fp), samplingPeriod(takenStamps(tl)), opts)
	if err != nil {
		t.Fatalf("JudgeSeries: %v", err)
	}
	return v
}

// ramp rises linearly from base to base+total over n samples.
func ramp(base, total, n int) []int {
	out := make([]int, n)
	for i := range out {
		if n == 1 {
			out[i] = base
			continue
		}
		out[i] = base + total*i/(n-1)
	}
	return out
}

// descend falls linearly from from to to over n samples.
//
// It exists because ramp(from, to) only interpolates when to > from: written as
// ramp(600, 50, 24) it produces a climb from 600 to 50 by taking negative steps, so
// a release written with it is silently a further rise. Two fixtures were wrong in
// exactly that way before this helper was added.
func descend(from, to, n int) []int {
	out := make([]int, n)
	for i := range out {
		if n == 1 {
			out[i] = from
			continue
		}
		out[i] = from - (from-to)*i/(n-1)
	}
	out[n-1] = to
	return out
}

// fill returns n copies of v.
func fill(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// tail extends a series by holding its last value.
func tail(xs []int, extra int) []int {
	out := append([]int{}, xs...)
	if len(xs) == 0 {
		return out
	}
	for i := 0; i < extra; i++ {
		out = append(out, xs[len(xs)-1])
	}
	return out
}

// TestPoolWarmupIsNotALeak is negative case one: a connection pool that fills and
// then holds.
//
// This is the most convincing false positive a descriptor tool can produce, because
// the count really does rise steeply and really does stop high. Only the fact that it
// stopped separates it from a leak - and during the fill the two are literally the
// same shape, which is why no test on step sizes alone can distinguish them.
func TestPoolWarmupIsNotALeak(t *testing.T) {
	// Fills from 10 to 210 over the first 24 samples, then holds for 76.
	cs := tail(ramp(10, 200, 24), 76)
	tl := seriesOf(t, map[string][]int{"socket": cs}, 100*time.Millisecond)

	v := judgeOne(t, tl, "socket", DefaultLeakOptions())
	if v.Leak {
		t.Fatalf("a warmed-up pool was reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
	if v.Evidence.RateSustained {
		t.Errorf("a fill that stopped was reported as continuous growth: %+v", v.Evidence)
	}
	if v.Evidence.FallbackAfterPeak != 0 {
		t.Errorf("a pool that never released anything cannot have fallen back: %+v", v.Evidence)
	}
}

// TestWarmupThenLeakIsALeak is the control for it: the same fill, still growing
// afterwards. Without this pair the negative case above would also pass for a judge
// that ignores everything after the baseline.
func TestWarmupThenLeakIsALeak(t *testing.T) {
	cs := append(tail(ramp(10, 200, 24), 76), ramp(210, 400, 100)...)
	tl := seriesOf(t, map[string][]int{"socket": cs}, 100*time.Millisecond)

	v := judgeOne(t, tl, "socket", DefaultLeakOptions())
	if !v.Leak {
		t.Fatalf("a pool that kept growing after warming up was not reported: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
}

// TestBatchOpenThenCloseIsNotALeak is negative case two: a batch job opens a large
// number of descriptors, works, and closes them.
//
// The process total ends where it started, so even a naive endpoint comparison
// passes; the control below keeps the burst and removes only the closing.
func TestBatchOpenThenCloseIsNotALeak(t *testing.T) {
	cs := append(fill(50, 3), ramp(50, 550, 8)...)
	cs = append(cs, fill(600, 3)...)
	cs = append(cs, descend(600, 50, 24)...)
	cs = append(cs, fill(50, 25)...)
	tl := seriesOf(t, map[string][]int{"file:/data/batch": cs}, 100*time.Millisecond)

	v := judgeOne(t, tl, "file:/data/batch", DefaultLeakOptions())
	if v.Leak {
		t.Fatalf("a batch that released everything was reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
	if v.Evidence.Monotonic {
		t.Errorf("the series fell back but the evidence calls it monotonic: %+v", v.Evidence)
	}
	if v.Evidence.FallbackAfterPeak < 100 {
		t.Errorf("fallback after peak = %d, want at least 100 (600 -> 50)", v.Evidence.FallbackAfterPeak)
	}
}

// TestBatchThatNeverClosesIsALeak keeps the burst and removes the release, and keeps
// growing afterwards so that the difference under test is the release alone.
func TestBatchThatNeverClosesIsALeak(t *testing.T) {
	cs := append(fill(50, 3), ramp(50, 550, 8)...)
	cs = append(cs, fill(600, 3)...)
	cs = append(cs, ramp(600, 1200, 49)...)
	tl := seriesOf(t, map[string][]int{"file:/data/batch": cs}, 100*time.Millisecond)

	v := judgeOne(t, tl, "file:/data/batch", DefaultLeakOptions())
	if !v.Leak {
		t.Fatalf("a burst that never released and kept growing was not reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
}

// TestPeriodicSpikeIsNotALeak is negative case three: a scheduled job opens a fixed
// number of descriptors every cycle and closes them, and the run happens to stop
// mid-cycle so the series ends above where it started.
func TestPeriodicSpikeIsNotALeak(t *testing.T) {
	cycle := append(ramp(20, 120, 5), descend(120, 20, 5)...)
	cs := []int{}
	for i := 0; i < 8; i++ {
		cs = append(cs, cycle...)
	}
	// Stop partway up the last spike.
	cs = append(cs, 20, 40, 70)
	tl := seriesOf(t, map[string][]int{"socket": cs}, 200*time.Millisecond)

	v := judgeOne(t, tl, "socket", DefaultLeakOptions())
	if v.Leak {
		t.Fatalf("a periodic spike was reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
	if v.Evidence.Monotonic {
		t.Errorf("a repeated spike was called monotonic: %+v", v.Evidence)
	}
}

// TestDirectoryWalkIsNotALeak is negative case four: a walk opens descriptors in a
// single leap and releases them.
//
// The leap clears both growth floors and the average rate, so only the shape of the
// growth separates it: one step among many flat samples is a fan-out, not a climb.
func TestDirectoryWalkIsNotALeak(t *testing.T) {
	cs := append(fill(30, 30), ramp(30, 270, 4)...)
	cs = append(cs, fill(300, 10)...)
	cs = append(cs, 30, 30, 30, 30)
	tl := seriesOf(t, map[string][]int{"file:/src": cs}, 200*time.Millisecond)

	v := judgeOne(t, tl, "file:/src", DefaultLeakOptions())
	if v.Leak {
		t.Fatalf("a directory walk was reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
}

// TestFixedFanOutIsNotALeak isolates the continuity criterion: descriptors opened in
// one step and held.
//
// It clears the growth floors and the average rate, so only "did the rise span the
// window" can reject it.
func TestFixedFanOutIsNotALeak(t *testing.T) {
	cs := append(fill(20, 5), 300)
	cs = append(cs, fill(300, 40)...)
	tl := seriesOf(t, map[string][]int{"socket": cs}, 100*time.Millisecond)

	v := judgeOne(t, tl, "socket", DefaultLeakOptions())
	if v.Leak {
		t.Fatalf("a fixed fan-out was reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
	if v.Evidence.RateSustained {
		t.Errorf("a single leap was counted as continuous growth: %+v", v.Evidence)
	}
}

// TestSteadyLeakIsALeak is the positive case the whole package exists for: a process
// that keeps opening descriptors and never closes them, sampled densely enough for
// the per-gap shape to be visible.
func TestSteadyLeakIsALeak(t *testing.T) {
	cs := ramp(100, 200, 120)
	tl := seriesOf(t, map[string][]int{"socket": cs}, 100*time.Millisecond)

	v := judgeOne(t, tl, "socket", DefaultLeakOptions())
	if !v.Leak {
		t.Fatalf("a steady climb of 200 descriptors was not reported: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
	if v.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high for a complete 11.9s window", v.Confidence)
	}
	if !v.Evidence.Monotonic || !v.Evidence.RateSustained {
		t.Errorf("a linear climb must be both monotonic and continuous: %+v", v.Evidence)
	}
}

// TestTinyGrowthIsNotALeak guards the absolute floor: 1 -> 5 descriptors is a 400%
// rise and a boring fact.
func TestTinyGrowthIsNotALeak(t *testing.T) {
	cs := ramp(1, 5, 40)
	tl := seriesOf(t, map[string][]int{"file:/tmp/x": cs}, 100*time.Millisecond)
	v := judgeOne(t, tl, "file:/tmp/x", DefaultLeakOptions())
	if v.Leak {
		t.Fatalf("1 -> 5 descriptors was reported as a leak: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
	if v.Evidence.GrowthRequired < 10 {
		t.Errorf("growth floor = %d, want at least the absolute minimum of 10", v.Evidence.GrowthRequired)
	}
}

// TestSlowRiseBelowRateFloor is not a leak: a process that gains a descriptor every
// few seconds is indistinguishable from churn inside a short window, and the rate
// floor is what keeps the tool from calling it one.
func TestSlowRiseBelowRateFloor(t *testing.T) {
	// 12 descriptors over 10 seconds: 1.2/s, far below the 5/s floor used here.
	cs := ramp(1000, 12, 40)
	tl := seriesOf(t, map[string][]int{"socket": cs}, 250*time.Millisecond)
	opts := DefaultLeakOptions()
	opts.MinRatePerSecond = 5
	v := judgeOne(t, tl, "socket", opts)
	if v.Leak {
		t.Fatalf("a 1.2 descriptors/second rise was reported as a leak with a 5/s floor: %s\nevidence: %+v", v.Reason, v.Evidence)
	}
}

// TestShortSeriesIsRefusedNotExcused guards the calm-direction lie: a series too short
// to judge must say so, not report "no leak".
func TestShortSeriesIsRefusedNotExcused(t *testing.T) {
	tl := seriesOf(t, map[string][]int{"socket": {10, 120, 300}}, 100*time.Millisecond)
	v := judgeOne(t, tl, "socket", DefaultLeakOptions())
	if v.Leak {
		t.Fatal("three samples cannot establish a leak")
	}
	if v.Confidence != ConfidenceNone {
		t.Fatalf("confidence = %q, want %q: an unjudgeable series must not be a confident negative",
			v.Confidence, ConfidenceNone)
	}
	if v.Reason == "" {
		t.Fatal("a refusal must say why")
	}
}

// TestEvictedSamplesDowngradeConfidence is the coverage criterion: a leak seen through
// an incomplete window is still reported, but never as high confidence.
func TestEvictedSamplesDowngradeConfidence(t *testing.T) {
	tl, err := timeline.New(4242, 10)
	if err != nil {
		t.Fatalf("timeline.New: %v", err)
	}
	base := time.Now().UnixNano()
	for i := 0; i < 40; i++ {
		if err := tl.Add(timeline.Sample{
			Taken:  base + int64(i)*int64(time.Second),
			Total:  100 + i*10,
			Counts: map[string]int{"socket": 100 + i*10},
		}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if !tl.Incomplete() {
		t.Fatal("the fixture did not evict anything; the case would prove nothing")
	}
	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if !rep.Leaking {
		t.Fatalf("the retained window shows continuous growth but nothing was reported: %+v", rep.Total)
	}
	if rep.Total.Confidence != ConfidenceLow {
		t.Errorf("total confidence = %q, want %q: evicted samples make the start of the growth unknowable",
			rep.Total.Confidence, ConfidenceLow)
	}
	if !rep.Incomplete || rep.Dropped != 30 {
		t.Errorf("report must state the eviction: incomplete=%v dropped=%d, want true/30", rep.Incomplete, rep.Dropped)
	}
}

// TestLeakOptionsRejectImpossibleValues pins the configuration contract. Every case is
// a sign error or an out-of-range fraction, which are the mistakes callers make here.
func TestLeakOptionsRejectImpossibleValues(t *testing.T) {
	cases := []struct {
		name string
		opts LeakOptions
	}{
		{"negative growth", LeakOptions{MinGrowth: -1}},
		{"negative ratio", LeakOptions{MinGrowthRatio: -0.1}},
		{"negative rate", LeakOptions{MinRatePerSecond: -1}},
		{"warmup at one", LeakOptions{Warmup: 1}},
		{"warmup above one", LeakOptions{Warmup: 1.5}},
		{"negative window", LeakOptions{MinWindowMillis: -1}},
		{"negative limit", LeakOptions{Limit: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tl := seriesOf(t, map[string][]int{"socket": ramp(10, 100, 40)}, 100*time.Millisecond)
			if _, err := Judge(tl, tc.opts); err == nil {
				t.Fatalf("%s was accepted; a rejected configuration must fail loudly", tc.name)
			}
		})
	}
}

// TestJudgeRejectsImpossiblePeriod guards the clock contract: the analyser derives
// timestamps from the period it is given, so an impossible period must be refused
// rather than producing a rate computed against negative time.
func TestJudgeRejectsImpossiblePeriod(t *testing.T) {
	tl := seriesOf(t, map[string][]int{"socket": ramp(10, 100, 40)}, 100*time.Millisecond)
	if _, err := JudgeSeries(tl.FingerprintSeries("socket"), -1, DefaultLeakOptions()); err == nil {
		t.Fatal("a negative sampling period was accepted")
	}
}

// TestRealProcessLeakIsConvicted is the one case that is not synthetic: a real child
// process that really opens descriptors and never closes them, sampled through the
// production probe.
//
// The synthetic corpus proves the criteria are internally consistent. It cannot prove
// the pipeline, because it feeds the judge counts manufactured to be judged. This test
// samples a real /proc, so a regression anywhere in probe, timeline or verdict shows
// up here - and it is the test that caught the judged window starting mid-fill, which
// every synthetic case had been shaped to avoid.
//
// The child opens its descriptors *after* sampling starts, on markers, and only one
// per step. Opening them all up front was the first version of this fixture, and it
// could never pass: the sampler began with the leak already complete, so the series
// was flat for its whole length. That is not a defect in the detector - it is the
// case the "growth predates the window" rule exists for - but it is not what this test
// is meant to measure.
func TestRealProcessLeakIsConvicted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-process sampling in short mode")
	}
	dir := t.TempDir()

	// bash rather than sh: /bin/sh is dash here, and dash has no `exec {fd}>`.
	script := `
d="$1"
# Lower the limit inside the child: rlimit is inherited at exec, so calling
# setrlimit from the test process changes the test's own limit and not this
# process's. 200 is high enough for the 100 descriptors opened below and low enough
# that holding them is a real fraction of capacity.
ulimit -n 200
echo ready
i=0
for step in $(seq 1 20); do
  while [ ! -e "$d/marker-$step" ]; do sleep 0.01; done
  for n in 1 2 3 4 5; do
    i=$((i+1))
    exec {fd}>"$d/leak-$i.log"
  done
  echo done > "$d/ack-$step"
done
echo "opened=$i"
while :; do sleep 0.05; done
`
	cmd := exec.Command("bash", "-c", script, "bash", dir)
	// Its own session, so cleanup can kill the process group without reaching into
	// this test binary: `go test` and the child otherwise share a group, and
	// kill(-pgid) then takes the test runner with it, which reads as an OOM kill.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		if pgid, gerr := syscall.Getpgid(pid); gerr == nil && pgid == pid {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Read until EOF rather than stopping at the marker: the pipe holds 64KiB and a
	// child that keeps writing would block forever in write(2), which looks exactly
	// like a slow sampler.
	ready := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		signalled := false
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 && !signalled {
				signalled = true
				close(ready)
			}
			if rerr != nil {
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("child never reported ready")
	}

	// Drive the child to completion *first*, then sample. Two earlier arrangements
	// failed, both instructively:
	//
	//   - opening every descriptor before sampling began left the sampler watching a
	//     flat line, which is the "growth predates the window" case, not this one
	//   - driving and sampling concurrently meant the window often ended while the
	//     child had already stopped, producing a trailing plateau that the continuity
	//     criterion read - correctly - as a fill that had finished
	//
	// Sequential is also the more honest claim: "a process that has leaked up to N
	// descriptors is reported as leaking" is what needs proving, and it needs the
	// child's full growth to be inside the observation.
	//
	// Each step opens five descriptors and waits for the child's own acknowledgement,
	// so a slow machine changes when the work finishes, never whether it happened.
	const steps = 20
	for step := 1; step <= steps; step++ {
		marker := filepath.Join(dir, fmt.Sprintf("marker-%d", step))
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			t.Fatalf("marker %d: %v", step, err)
		}
		ack := filepath.Join(dir, fmt.Sprintf("ack-%d", step))
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, serr := os.Stat(ack); serr == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("child never acknowledged step %d", step)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Prove the premise before judging: the child really holds what it opened.
	opened := len(mustGlob(t, filepath.Join(dir, "leak-*.log")))
	if opened != steps*5 {
		t.Fatalf("child opened %d of the %d descriptors it was asked for: the fixture did not create the leak it tests",
			opened, steps*5)
	}

	// Sampled while the count is constant: the descriptors are all open and none are
	// closed, so the series is flat at an elevated level. That is the shape the
	// "growth predates the window" rule must convict - and it is the shape a real
	// incident is actually discovered in.
	// The limit is lowered so that the constant count is a meaningful fraction of it:
	// a process holding 103 descriptors against a 4096 limit is unremarkable, and the
	// verdict must not convict it. Against a 200 limit it is a process about to die.
	//
	// The child lowers its own limit before opening anything (see the script above),
	// which is the only place that works: rlimit is inherited at exec, so a call from
	// this process would change the test's limit and leave the child at 4096 - which
	// is exactly what the first version did, and why the rule never fired.
	tl, err := probe.NewProbe().SampleTimeline(pid, 20, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if !rep.Leaking {
		t.Fatalf("a process holding %d unclosed descriptors was not reported as leaking: total %+v", opened, rep.Total)
	}
	// The verdict must be honest about what it is: the growth happened before the
	// window opened, so it may not be claimed at high confidence.
	if rep.Total.Confidence != ConfidenceLow {
		t.Errorf("confidence = %q, want low: the growth predates the window", rep.Total.Confidence)
	}
	if !strings.Contains(rep.Total.Reason, "before sampling began") {
		t.Errorf("the reason must say the growth happened before the observation: %q", rep.Total.Reason)
	}
	if !rep.Leaking {
		t.Fatalf("a process that opened descriptors and closed none was not reported as leaking: total %+v", rep.Total)
	}
	// The opened files must all appear in the report, each held exactly once. They are
	// not individually convictable - a file held once has no trend of its own, and the
	// verdict for it is correctly flat - so the assertion is on their presence, which
	// is what a reader needs in order to act: "this process holds 100 log files" is
	// the actionable line, and it comes from the per-fingerprint rows.
	present := 0
	for _, v := range rep.Series {
		if strings.HasPrefix(v.Fingerprint, "file:"+dir) {
			present++
			if v.Evidence.RestValue != 1 {
				t.Errorf("%q: held %d descriptors, want exactly 1", v.Fingerprint, v.Evidence.RestValue)
			}
		}
	}
	if present < steps*5 {
		t.Errorf("only %d of the %d opened files appear in the report", present, steps*5)
	}
}
