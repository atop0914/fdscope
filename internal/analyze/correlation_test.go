package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/timeline"
)

// buildCorrelatedTimeline assembles a judged window from per-fingerprint counts and the
// process-level counters taken with each sample.
//
// The total is summed from the counts rather than passed in, because the two must
// agree: a total that disagreed with its own series would let the attribution and
// the correlation disagree about whether anything rose.
func buildCorrelatedTimeline(t *testing.T, counts map[string][]int, counters []model.ProcessCounters, limit model.OpenLimit) *timeline.Timeline {
	t.Helper()
	n := len(counters)
	tl, err := timeline.New(1, n)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		sample := timeline.Sample{
			Taken:    int64(i+1) * int64(200*time.Millisecond),
			Counts:   map[string]int{},
			Limit:    limit,
			Counters: counters[i],
		}
		for fp, vals := range counts {
			if i < len(vals) && vals[i] > 0 {
				sample.Counts[fp] = vals[i]
				sample.Total += vals[i]
			}
		}
		if err := tl.Add(sample); err != nil {
			t.Fatal(err)
		}
	}
	return tl
}

// leakingCounts is the canonical leak shape: a settled level for the first third of
// the window, then a steady climb that never falls back.
func leakingCounts() []int {
	out := make([]int, 20)
	for i := range out {
		if i < 8 {
			out[i] = 20
		} else {
			out[i] = 20 + 4*(i-7)
		}
	}
	return out
}

// flatCounters builds a window of counters that never moves.
func flatCounters(n int) []model.ProcessCounters {
	out := make([]model.ProcessCounters, n)
	for i := range out {
		out[i] = model.ProcessCounters{
			Threads:       model.NewCounter(5),
			SyscallsRead:  model.NewCounter(900),
			SyscallsWrite: model.NewCounter(300),
			RSSBytes:      model.NewCounter(32 << 20),
		}
	}
	return out
}

// TestJudgeCorrelatesTheOnsetWithACounterThatMoved is the Day 8 positive case at the
// judgement layer: the descriptors start climbing at sample 8, and so does the
// resident set. The correlation must be anchored to that same sample.
func TestJudgeCorrelatesTheOnsetWithACounterThatMoved(t *testing.T) {
	counters := flatCounters(20)
	for i := 8; i < 20; i++ {
		counters[i].RSSBytes = model.NewCounter(int64(32<<20) + int64(i-7)*(4<<20))
	}
	tl := buildCorrelatedTimeline(t, map[string][]int{"file:/var/log/app.log": leakingCounts()}, counters, model.UnknownLimit())

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Leaking {
		t.Fatalf("fixture did not leak, so there is no onset to correlate: %+v", rep.Total)
	}
	if rep.CorrelationAnchor != "(total)" {
		t.Errorf("anchor = %q, want the process total", rep.CorrelationAnchor)
	}
	if len(rep.Correlations) != 1 {
		t.Fatalf("correlations = %+v, want exactly the resident set", rep.Correlations)
	}
	c := rep.Correlations[0]
	if c.Counter != model.CounterRSS {
		t.Errorf("counter = %q, want rss", c.Counter)
	}
	// The onset is where the count left its settled level, so the baseline is the
	// last settled sample: index 7, at the 32MiB resting value.
	if c.Baseline != 32<<20 {
		t.Errorf("baseline = %d, want the pre-rise reading %d", c.Baseline, 32<<20)
	}
	if c.Overlap != 12 || c.Window != 12 {
		t.Errorf("overlap/window = %d/%d, want 12/12", c.Overlap, c.Window)
	}
	// The other two counters were readable and did not move, and they must be ruled
	// out in words rather than quietly dropped.
	found := false
	for _, n := range rep.CorrelationNotes {
		if strings.Contains(n, "threads did not move") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %v, want the flat thread count to be ruled out by name", rep.CorrelationNotes)
	}
}

// TestJudgeAttachesNoCorrelationToACleanRun is the reverse assertion at the
// judgement layer: a process that holds its level must produce no correlation block
// at all, not an empty one.
func TestJudgeAttachesNoCorrelationToACleanRun(t *testing.T) {
	held := make([]int, 20)
	for i := range held {
		held[i] = 40
	}
	tl := buildCorrelatedTimeline(t, map[string][]int{"file:/var/lib/state.db": held}, flatCounters(20), model.KnownLimit(4096))

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Leaking {
		t.Fatalf("fixture leaked unexpectedly: %+v", rep.Total)
	}
	if len(rep.Correlations) != 0 || rep.CorrelationAnchor != "" || len(rep.CorrelationNotes) != 0 {
		t.Fatalf("a clean run carries a correlation block: %+v", rep)
	}
}

// TestJudgeSaysWhenNoCounterMoved is the honesty case for a leak nothing accompanied.
//
// The block is empty and the notes say why, which is a finding: the growth was not
// accompanied by new threads, new writes or new memory, so the reader should stop
// looking for an obvious companion activity.
func TestJudgeSaysWhenNoCounterMoved(t *testing.T) {
	tl := buildCorrelatedTimeline(t, map[string][]int{"file:/var/log/app.log": leakingCounts()}, flatCounters(20), model.UnknownLimit())

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Leaking {
		t.Fatalf("fixture did not leak: %+v", rep.Total)
	}
	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none when nothing moved", rep.Correlations)
	}
	if rep.CorrelationAnchor == "" {
		t.Error("anchor is empty, but the reader still needs to know what was examined")
	}
	if len(rep.CorrelationNotes) == 0 {
		t.Fatal("no notes: an empty block with no explanation reads as 'not looked at'")
	}
}

// TestJudgeRefusesToCorrelateAGrowthThatPredatesTheWindow covers the constant-window
// leak - descriptors all opened before sampling began.
//
// There is no rise inside the window, so there is no onset, and the report must say
// that rather than correlate the counters against an arbitrary sample.
func TestJudgeRefusesToCorrelateAGrowthThatPredatesTheWindow(t *testing.T) {
	held := make([]int, 20)
	for i := range held {
		held[i] = 100
	}
	// A count this close to the limit is the only way a constant window convicts.
	tl := buildCorrelatedTimeline(t, map[string][]int{"socket": held}, flatCounters(20), model.KnownLimit(150))

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Leaking {
		t.Fatalf("a constant count at 67%% of the limit must convict: %+v", rep.Total)
	}
	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none without an onset", rep.Correlations)
	}
	if !anyContains(rep.CorrelationNotes, "predates the window") {
		t.Errorf("notes = %v, want the missing onset to be stated", rep.CorrelationNotes)
	}
}

// TestJudgeAnchorsOnTheLeakingSeriesWhenTheTotalIsFlat proves the anchor follows the
// evidence rather than always being the total.
//
// A resource can climb while another releases just as much, leaving the process total
// level. The correlation still has an answer - when did the climbing resource start -
// and it must be taken against that series, not against a total that never moved.
func TestJudgeAnchorsOnTheLeakingSeriesWhenTheTotalIsFlat(t *testing.T) {
	// A climbs 0 -> 60 while B drains 60 -> 0, step for step, so the total holds at
	// 60 for the whole window. Both series move; only one of them grows.
	a := []int{0, 0, 0, 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 60}
	b := []int{60, 60, 60, 60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0, 0}
	tl := buildCorrelatedTimeline(t, map[string][]int{"socket": a, "file:/var/log/app.log": b}, flatCounters(20), model.KnownLimit(4096))

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total.Leak {
		t.Fatalf("the process total was level (60 the whole window) yet was convicted: %+v", rep.Total)
	}
	if !rep.Leaking {
		t.Fatalf("the climbing resource was not convicted, so the fixture proves nothing: %+v", rep.Series)
	}
	if rep.CorrelationAnchor == "" || rep.CorrelationAnchor == "(total)" {
		t.Fatalf("anchor = %q, want the leaking resource rather than a level total", rep.CorrelationAnchor)
	}
}

// anyContains reports whether any note mentions sub.
func anyContains(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}
