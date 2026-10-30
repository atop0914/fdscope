package correlate

import (
	"strings"
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// knownSeries builds a counter series whose every sample was readable.
func knownSeries(name model.CounterName, vals ...int64) model.CounterSeries {
	known := make([]bool, len(vals))
	for i := range known {
		known[i] = true
	}
	return model.CounterSeries{Counter: name, Values: vals, Known: known}
}

// unknownAt marks the given indices unreadable, the shape of a counter that was
// denied for part of the window.
func unknownAt(cs model.CounterSeries, idx ...int) model.CounterSeries {
	for _, i := range idx {
		cs.Known[i] = false
	}
	return cs
}

// find returns the correlation for name, if the report has one.
func find(rep Report, name model.CounterName) (Correlation, bool) {
	for _, c := range rep.Correlations {
		if c.Counter == name {
			return c, true
		}
	}
	return Correlation{}, false
}

// notesContain reports whether any note mentions any of the given fragments.
func notesContain(rep Report, fragments ...string) bool {
	for _, n := range rep.Notes {
		for _, f := range fragments {
			if strings.Contains(n, f) {
				return true
			}
		}
	}
	return false
}

// TestCompareReportsACounterThatMoved is the base case: the descriptors started
// growing at sample 4, and syscw started climbing at the same time.
func TestCompareReportsACounterThatMoved(t *testing.T) {
	// Baseline at index 3 (1000), then 4000..4004 over the window.
	syscw := knownSeries(model.CounterSyscallsWrite, 1000, 1000, 1000, 1000, 4000, 4001, 4002, 4003, 4004)
	rep := Compare([]model.CounterSeries{syscw}, 9, 4)

	if rep.Onset != 4 || rep.Window != 5 {
		t.Fatalf("onset/window = %d/%d, want 4/5", rep.Onset, rep.Window)
	}
	if len(rep.Correlations) != 1 {
		t.Fatalf("correlations = %+v, want exactly syscw", rep.Correlations)
	}
	c := rep.Correlations[0]
	if c.Counter != model.CounterSyscallsWrite {
		t.Errorf("counter = %q, want syscw", c.Counter)
	}
	if c.Baseline != 1000 || c.Latest != 4004 {
		t.Errorf("baseline/latest = %d/%d, want 1000/4004", c.Baseline, c.Latest)
	}
	if c.Delta != 3004 {
		t.Errorf("delta = %d, want 3004", c.Delta)
	}
	if c.DeltaPct == nil || *c.DeltaPct < 300 || *c.DeltaPct > 301 {
		t.Errorf("delta_pct = %v, want about 300%%", c.DeltaPct)
	}
	if c.Overlap != 5 || c.Window != 5 {
		t.Errorf("overlap/window = %d/%d, want 5/5", c.Overlap, c.Window)
	}
	if c.Confidence != ConfidenceLow {
		// Five readable samples is the low band on purpose: the bands describe
		// evidence, and five points is thin evidence.
		t.Errorf("confidence = %q, want low for five samples", c.Confidence)
	}
	if !strings.Contains(c.Note, "correlation") {
		t.Errorf("note %q does not say it is a correlation", c.Note)
	}
}

// TestCompareStaysQuietWhenNothingMoved is the reverse assertion that decides
// whether L2 is usable.
//
// This is the shape of a process that grows descriptors without doing any I/O:
// plain `exec {fd}>/dev/null` in a loop. If the correlation layer reported syscw or
// syscr here it would be inventing activity, and the section would be worthless on
// every real run.
func TestCompareStaysQuietWhenNothingMoved(t *testing.T) {
	flat := knownSeries(model.CounterSyscallsWrite, 500, 500, 500, 500, 500, 500, 500, 500)
	threads := knownSeries(model.CounterThreads, 4, 4, 4, 4, 4, 4, 4, 4)
	rss := knownSeries(model.CounterRSS, 32<<20, 32<<20, 32<<20, 32<<20, 32<<20, 32<<20, 32<<20, 32<<20)

	rep := Compare([]model.CounterSeries{flat, threads, rss}, 8, 4)

	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none for counters that did not move", rep.Correlations)
	}
	if !notesContain(rep, "did not move") {
		t.Errorf("notes = %v, want the counters that were ruled out to be named", rep.Notes)
	}
}

// TestCompareNeverReadsUnknownAsZero is the honesty assertion for a counter that
// stops being readable mid-window.
//
// A zero-filling implementation would see syscw go 1000 -> 0 and report a 100%
// fall - a confident correlation derived from readings that never happened. The
// correct behaviour is to report nothing and say how many readings it had.
func TestCompareNeverReadsUnknownAsZero(t *testing.T) {
	syscw := unknownAt(knownSeries(model.CounterSyscallsWrite, 1000, 5000, 5000, 5000, 5000, 5000), 1, 2, 3, 4, 5)
	rep := Compare([]model.CounterSeries{syscw}, 6, 1)

	if c, ok := find(rep, model.CounterSyscallsWrite); ok {
		t.Fatalf("correlation %+v was derived from unreadable samples; unknown must not be read as 0", c)
	}
	if !notesContain(rep, "readable sample") {
		t.Errorf("notes = %v, want the unreadable counter to be accounted for", rep.Notes)
	}
}

// TestCompareRefusesWhenTheRiseBeganAtTheFirstSample covers the case the plan calls
// "the onset predates the window".
//
// With no sample before the rise there is no baseline, and comparing against the
// rise's own first value would report a smaller change that describes a different
// interval than the growth does. Refusing and saying so is the honest answer.
func TestCompareRefusesWhenTheRiseBeganAtTheFirstSample(t *testing.T) {
	syscw := knownSeries(model.CounterSyscallsWrite, 10, 100, 200, 300, 400, 500)
	rep := Compare([]model.CounterSeries{syscw}, 6, 0)

	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none without a pre-window baseline", rep.Correlations)
	}
	if !notesContain(rep, "first sample", "predates the window") {
		t.Errorf("notes = %v, want the missing baseline to be stated", rep.Notes)
	}
}

// TestCompareRefusesOnAConstantWindow covers a leak discovered after the fact: the
// series never rises inside the window, so stablePrefix returns the sample count and
// there is no onset to speak of.
func TestCompareRefusesOnAConstantWindow(t *testing.T) {
	syscw := knownSeries(model.CounterSyscallsWrite, 10, 10, 10, 10)
	rep := Compare([]model.CounterSeries{syscw}, 4, 4)

	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none for a window with no rise in it", rep.Correlations)
	}
	if !notesContain(rep, "predates the window") {
		t.Errorf("notes = %v, want the absence of a rise to be stated", rep.Notes)
	}
}

// TestCompareRequiresEnoughReadings pins the overlap floor.
func TestCompareRequiresEnoughReadings(t *testing.T) {
	// Baseline readable, one readable sample inside the window, the rest denied.
	rss := unknownAt(knownSeries(model.CounterRSS, 8<<20, 40<<20, 40<<20, 40<<20, 40<<20), 2, 3, 4)
	rep := Compare([]model.CounterSeries{rss}, 5, 1)

	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none from a single readable sample", rep.Correlations)
	}
	if !notesContain(rep, "readable sample") {
		t.Errorf("notes = %v, want the shortfall to be stated", rep.Notes)
	}
}

// TestCompareSkipsWhenTheBaselineIsUnreadable proves the baseline is not guessed.
func TestCompareSkipsWhenTheBaselineIsUnreadable(t *testing.T) {
	threads := unknownAt(knownSeries(model.CounterThreads, 3, 12, 12, 12, 12), 3)
	rep := Compare([]model.CounterSeries{threads}, 5, 4)

	if len(rep.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none without a readable baseline", rep.Correlations)
	}
	if !notesContain(rep, "before the window") {
		t.Errorf("notes = %v, want the missing baseline to be stated", rep.Notes)
	}
}

// TestCompareReportsASurgeFromZeroWithoutAPercentage pins the baseline-zero case.
//
// A process that had written nothing and then started writing is the clearest
// signal this layer can offer, so it must not be dropped - but a percentage of zero
// does not exist, and printing 0% (or +Inf) would both be wrong in different ways.
// The delta is reported and the percentage is omitted.
func TestCompareReportsASurgeFromZeroWithoutAPercentage(t *testing.T) {
	syscw := knownSeries(model.CounterSyscallsWrite, 0, 900, 950, 990, 1000)
	rep := Compare([]model.CounterSeries{syscw}, 5, 1)

	c, ok := find(rep, model.CounterSyscallsWrite)
	if !ok {
		t.Fatalf("correlations = %+v, want the surge from zero to be reported", rep.Correlations)
	}
	if c.Baseline != 0 || c.Delta != 1000 {
		t.Errorf("baseline/delta = %d/%d, want 0/1000", c.Baseline, c.Delta)
	}
	if c.DeltaPct != nil {
		t.Errorf("delta_pct = %v, want it omitted when the baseline is zero", *c.DeltaPct)
	}
	if !strings.Contains(c.Note, "correlation") {
		t.Errorf("note %q does not say it is a correlation", c.Note)
	}
}

// TestCompareReportsOnlyTheCountersThatMoved is the specificity assertion: within
// one window, a counter that moved is named and its neighbours are not.
func TestCompareReportsOnlyTheCountersThatMoved(t *testing.T) {
	threads := knownSeries(model.CounterThreads, 4, 4, 4, 4, 4, 4)
	syscw := knownSeries(model.CounterSyscallsWrite, 100, 100, 900, 1500, 2000, 2400)
	rss := knownSeries(model.CounterRSS, 10<<20, 10<<20, 10<<20, 10<<20, 10<<20, 10<<20)

	rep := Compare([]model.CounterSeries{threads, syscw, rss}, 6, 2)

	if len(rep.Correlations) != 1 {
		t.Fatalf("correlations = %+v, want only syscw", rep.Correlations)
	}
	if rep.Correlations[0].Counter != model.CounterSyscallsWrite {
		t.Errorf("counter = %q, want syscw", rep.Correlations[0].Counter)
	}
}

// TestCompareReportsAFallingCounterAsFalling proves a counter that dropped is
// reported with its sign rather than filtered into silence.
//
// Threads falling while descriptors rise is real (work moved from a pool to a
// stream of connections), and a section that silently dropped negative deltas would
// hide the one counter that disagreed with the growth.
func TestCompareReportsAFallingCounterAsFalling(t *testing.T) {
	threads := knownSeries(model.CounterThreads, 20, 18, 14, 10, 8)
	rep := Compare([]model.CounterSeries{threads}, 5, 1)

	c, ok := find(rep, model.CounterThreads)
	if !ok {
		t.Fatalf("correlations = %+v, want the falling thread count to be reported", rep.Correlations)
	}
	if c.Delta != -12 {
		t.Errorf("delta = %d, want -12", c.Delta)
	}
	if !strings.Contains(c.Note, "fell") {
		t.Errorf("note %q does not state the direction", c.Note)
	}
}

// TestConfidenceDescribesOverlap pins the bands, which are the only thing the
// confidence field is allowed to mean.
func TestConfidenceDescribesOverlap(t *testing.T) {
	cases := []struct {
		overlap int
		want    Confidence
	}{
		{3, ConfidenceLow},
		{5, ConfidenceLow},
		{6, ConfidenceMedium},
		{11, ConfidenceMedium},
		{12, ConfidenceHigh},
		{25, ConfidenceHigh},
	}
	for _, tc := range cases {
		if got := confidenceFor(tc.overlap); got != tc.want {
			t.Errorf("confidenceFor(%d) = %q, want %q", tc.overlap, got, tc.want)
		}
	}
}

// TestNotesCarryNoCausalLanguage is the language gate, and it is the most
// important test in this package.
//
// Every behavioural test above would still pass if a note said "syscw writes caused
// these descriptors to leak". The promise that L2 never claims a cause lives in
// prose, so it is checked like prose - the same way the L1 rules are checked.
func TestNotesCarryNoCausalLanguage(t *testing.T) {
	forbidden := []string{
		"caused", "cause", "because", "due to", "responsible", "explains",
		"led to", "opened by", "probably", "likely", "must have", "might be",
	}
	// The notes worth scanning are the product of real comparisons, so the gate
	// runs over the notes of several shapes rather than over a string literal.
	reports := []Report{
		Compare([]model.CounterSeries{knownSeries(model.CounterSyscallsWrite, 1, 2, 900, 950, 990)}, 5, 2),
		Compare([]model.CounterSeries{knownSeries(model.CounterThreads, 20, 18, 10, 8, 4)}, 5, 1),
		Compare([]model.CounterSeries{knownSeries(model.CounterRSS, 0, 40<<20, 40<<20, 40<<20, 40<<20)}, 5, 1),
		Compare([]model.CounterSeries{knownSeries(model.CounterSyscallsWrite, 5, 5, 5, 5, 5)}, 5, 1),
		Compare([]model.CounterSeries{knownSeries(model.CounterSyscallsWrite, 5, 5, 5)}, 3, 0),
		Compare(nil, 3, 2),
	}
	checked := 0
	for _, rep := range reports {
		for _, n := range rep.Notes {
			checked++
			lower := strings.ToLower(n)
			for _, word := range forbidden {
				if strings.Contains(lower, word) {
					t.Errorf("note %q contains %q: L2 may report co-occurrence but never a cause", n, word)
				}
			}
		}
		for _, c := range rep.Correlations {
			checked++
			lower := strings.ToLower(c.Note)
			if !strings.Contains(lower, "correlation") {
				t.Errorf("note %q does not contain the word correlation", c.Note)
			}
			for _, word := range forbidden {
				if strings.Contains(lower, word) {
					t.Errorf("note %q contains %q: L2 may report co-occurrence but never a cause", c.Note, word)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no notes were scanned: the gate proved nothing")
	}
}

// TestEveryCounterHasARule guards against a counter that exists in the model but can
// never be reported, which would look like "the counter never moves".
func TestEveryCounterHasARule(t *testing.T) {
	var proto model.ProcessCounters
	for _, name := range proto.Names() {
		if _, ok := rules[name]; !ok {
			t.Errorf("counter %q has no reporting floor, so it can never be correlated", name)
		}
	}
}
