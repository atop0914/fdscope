package analyze

import (
	"strings"
	"testing"

	"github.com/atop0914/fdscope/internal/timeline"
)

// buildTimeline turns one fingerprint's count sequence into a real timeline.
//
// The values are handed to timeline.Timeline rather than to a mock: the analyser
// reads its input through Samples/TotalSeries/FingerprintSeries, and a stand-in
// would let a change in the container's semantics pass unnoticed here.
func buildTimeline(t *testing.T, fp string, counts []int) *timeline.Timeline {
	t.Helper()
	tl, err := timeline.New(4242, len(counts)+1)
	if err != nil {
		t.Fatalf("timeline.New: %v", err)
	}
	total := 0
	for i, c := range counts {
		counts := map[string]int{}
		if c > 0 {
			counts[fp] = c
		}
		total += c
		if err := tl.Add(timeline.Sample{Taken: int64(i+1) * 1_000_000, Total: total, Counts: counts}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	return tl
}

// TestLeakRisingSeriesIsNotARebound is the second reverse assertion in the plan:
// a series that only grows must never be called a rebound. If it were, the single
// case the tool exists for would be excused as "it came back down".
func TestLeakRisingSeriesIsNotARebound(t *testing.T) {
	tl := buildTimeline(t, "file:/app/log", []int{1, 1, 2, 3, 4, 5, 6, 7})
	rep, err := Analyze(tl, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	s := seriesByName(t, rep, "file:/app/log")
	if s.Trend != TrendRising {
		t.Errorf("trend = %q, want %q for 1..7", s.Trend, TrendRising)
	}
	if s.Rebound {
		t.Errorf("a monotonically rising series was reported as a rebound: from %d to %d", s.ReboundFrom, s.ReboundTo)
	}
	if s.Max != 7 || s.Last != 7 || s.Min != 1 || s.First != 1 {
		t.Errorf("summary = %+v, want min 1 max 7 first 1 last 7", s)
	}
	if s.PeakAt != 7 {
		// The peak of a rising series is its last point (index 7 of 8); getting
		// this wrong would mean the peak search stopped early.
		t.Errorf("peak index = %d, want 7 (the last of 8 samples)", s.PeakAt)
	}
}

// TestRiseThenReleaseIsARebound is the positive case: a batch job opens a large
// number of descriptors and releases them. This is the shape two snapshots cannot
// tell apart from a leak - take the samples at the peak and at the end and the
// verdict flips depending on where you happened to look.
func TestRiseThenReleaseIsARebound(t *testing.T) {
	tl := buildTimeline(t, "socket", []int{2, 8, 15, 20, 20, 9, 3, 2})
	rep, err := Analyze(tl, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	s := seriesByName(t, rep, "socket")
	if !s.Rebound {
		t.Fatalf("rise to 20 then fall to 2 was not reported as a rebound: %+v", s)
	}
	if s.ReboundFrom != 20 || s.ReboundTo != 2 {
		t.Errorf("rebound from %d to %d, want 20 to 2", s.ReboundFrom, s.ReboundTo)
	}
	if got := s.Drop(); got != 18 {
		t.Errorf("Drop() = %d, want 18", got)
	}
	if s.Trend != TrendFlat {
		// 2 -> 2 is flat, and that is the honest answer: the resource is back
		// where it started even though it went a long way in between.
		t.Errorf("trend = %q, want %q for 2 -> 2", s.Trend, TrendFlat)
	}
	if s.Max != 20 || s.PeakAt != 3 {
		// The peak is first reached at index 3; index 4 equals it but is not a
		// new peak, and attributing the fall to the later index would make the
		// series look cleaner than it was.
		t.Errorf("max = %d at %d, want 20 first reached at 3", s.Max, s.PeakAt)
	}
}

// TestWobbleWithinThresholdIsNotARebound is the reverse assertion the plan calls
// out explicitly: a series oscillating 100<->105 must stay quiet. Descriptor
// counts jitter by a few even in a healthy process, and reporting that jitter as
// a rebound teaches the reader to ignore the column.
//
// Both directions are asserted on the same shape with different thresholds, which
// is what proves the threshold is consulted rather than hard-coded: peak 105 with
// a low of 100 is a drop of 5, so it must rebound at threshold 3 and stay quiet at
// threshold 10.
func TestWobbleWithinThresholdIsNotARebound(t *testing.T) {
	wobble := []int{100, 103, 101, 105, 102, 100, 104, 105}

	tight, err := Analyze(buildTimeline(t, "socket", wobble), Options{ReboundThreshold: 10})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	s := seriesByName(t, tight, "socket")
	if s.Rebound {
		t.Errorf("a 100..105 wobble was reported as a rebound with threshold 10 (from %d to %d)",
			s.ReboundFrom, s.ReboundTo)
	}
	if s.Trend != TrendRising {
		// 100 -> 105 is a net rise of 5, well past the flat tolerance of 2. This
		// is the honest answer: the wobble did not come back to where it started.
		// The rebound assertion below is the one that must stay quiet.
		t.Errorf("trend = %q, want %q: 100 -> 105 is a net rise", s.Trend, TrendRising)
	}

	loose, err := Analyze(buildTimeline(t, "socket", wobble), DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	d := seriesByName(t, loose, "socket")
	if !d.Rebound || d.ReboundFrom != 105 || d.ReboundTo != 100 {
		t.Errorf("with the default threshold the 105 -> 100 drop should rebound, got %+v", d)
	}
}

// TestStableSeriesIsFlatWithNoNoise is the third reverse assertion: a process
// doing nothing must not produce a direction. A slope over three samples of
// 100/101/100 is nonzero in floating point, which is exactly the kind of fake
// precision the endpoint comparison avoids.
func TestStableSeriesIsFlatWithNoNoise(t *testing.T) {
	for _, counts := range [][]int{
		{7, 7, 7, 7, 7},
		{100, 101, 100, 99, 100},
		{5, 6, 5, 7, 6},
	} {
		tl := buildTimeline(t, "socket", counts)
		rep, err := Analyze(tl, DefaultOptions())
		if err != nil {
			t.Fatalf("Analyze(%v): %v", counts, err)
		}
		s := seriesByName(t, rep, "socket")
		if s.Trend != TrendFlat {
			t.Errorf("series %v trend = %q, want %q", counts, s.Trend, TrendFlat)
		}
		if s.Rebound {
			t.Errorf("series %v was reported as a rebound (from %d to %d)", counts, s.ReboundFrom, s.ReboundTo)
		}
	}
}

// TestFallingSeriesIsNotARebound pins the "the peak must be preceded by a rise"
// clause. A process draining 100 -> 80 -> 60 is recovering, and reporting that as
// a rebound would make every shutdown look like a batch job.
func TestFallingSeriesIsNotARebound(t *testing.T) {
	tl := buildTimeline(t, "socket", []int{100, 90, 80, 60, 40})
	rep, err := Analyze(tl, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	s := seriesByName(t, rep, "socket")
	if s.Rebound {
		t.Errorf("a series that only falls was called a rebound: from %d to %d", s.ReboundFrom, s.ReboundTo)
	}
	if s.Trend != TrendFalling {
		t.Errorf("trend = %q, want %q", s.Trend, TrendFalling)
	}
}

// TestPartialRecoveryReportsDeepestDrop checks that the reported low is the
// deepest point after the peak, not the last value. A series at 100 -> 40 -> 80
// has released 60 descriptors at its best moment; reporting "-20" because it
// climbed back would understate what was proven.
func TestPartialRecoveryReportsDeepestDrop(t *testing.T) {
	from, to, ok := DetectRebound([]int{5, 100, 40, 80}, 3)
	if !ok {
		t.Fatal("100 -> 40 -> 80 was not detected as a rebound")
	}
	if from != 100 || to != 40 {
		t.Errorf("rebound from %d to %d, want 100 to 40 (deepest after peak)", from, to)
	}
}

// TestDetectReboundBoundaries covers the edges a threshold-based rule always has:
// an exact-threshold drop counts, one short of it does not, and a single sample
// cannot rebound.
func TestDetectReboundBoundaries(t *testing.T) {
	// A shape that genuinely rises and then falls, used to pin the threshold
	// boundary: 10 -> 20 is the rise, and the fall from 20 is what varies.
	if _, _, ok := DetectRebound([]int{10, 20, 17}, 3); !ok {
		t.Error("a drop of exactly the threshold was not counted")
	}
	if _, _, ok := DetectRebound([]int{10, 20, 18}, 3); ok {
		t.Error("a drop one short of the threshold was counted")
	}
	// A series that only rises has no fall to measure: the peak is the last
	// sample, and the run-up to it is not a rebound.
	if _, _, ok := DetectRebound([]int{10, 13}, 3); ok {
		t.Error("a two-point rising series was reported as a rebound")
	}
	if _, _, ok := DetectRebound([]int{10}, 3); ok {
		t.Error("a single sample was reported as a rebound")
	}
	if _, _, ok := DetectRebound([]int{10, 20, 5}, 0); ok {
		t.Error("a zero threshold was accepted; every series would rebound")
	}
	// A series that is still at its peak has not fallen yet.
	if _, _, ok := DetectRebound([]int{1, 2, 3}, 1); ok {
		t.Error("a series ending at its peak was reported as a rebound")
	}
}

// TestOptionsRejectNegativeThresholds guards the "sign error" case: a negative
// value is a caller bug, and clamping it to the default would hide that while
// producing a plausible report.
func TestOptionsRejectNegativeThresholds(t *testing.T) {
	tl := buildTimeline(t, "socket", []int{1, 2, 3})
	if _, err := Analyze(tl, Options{FlatTolerance: -1}); err == nil {
		t.Error("a negative flat tolerance was accepted")
	}
	if _, err := Analyze(tl, Options{ReboundThreshold: -3}); err == nil {
		t.Error("a negative rebound threshold was accepted")
	}
	if _, err := Analyze(tl, Options{}); err != nil {
		t.Errorf("the zero Options value was rejected: %v (it documents the defaults)", err)
	}
}

// TestAnalyzeRejectsEmptyTimeline is the "nothing collected" case. An empty report
// renders as "no descriptor changed", which is a confident lie about a run that
// observed nothing at all.
func TestAnalyzeRejectsEmptyTimeline(t *testing.T) {
	tl, err := timeline.New(99, 4)
	if err != nil {
		t.Fatalf("timeline.New: %v", err)
	}
	if _, err := Analyze(tl, DefaultOptions()); err == nil {
		t.Error("Analyze accepted a timeline with no samples")
	}
	if _, err := Analyze(nil, DefaultOptions()); err == nil {
		t.Error("Analyze accepted a nil timeline")
	}
}

// TestReportGroupsDirections checks the derived views. They are computed from the
// summaries so that a reader filtering by direction sees the same rows as the
// table, and this test pins that they do not drift.
func TestReportGroupsDirections(t *testing.T) {
	tl, err := timeline.New(7, 8)
	if err != nil {
		t.Fatalf("timeline.New: %v", err)
	}
	// Three fingerprints in one timeline: one rising, one rise-then-release,
	// one flat.
	rising := []int{1, 2, 3, 4, 5, 6}
	batch := []int{2, 9, 12, 3, 2, 2}
	stable := []int{4, 4, 4, 4, 4, 4}
	total := 0
	for i := range rising {
		total = rising[i] + batch[i] + stable[i]
		err := tl.Add(timeline.Sample{
			Taken:  int64(i+1) * 1_000_000,
			Total:  total,
			Counts: map[string]int{"file:/rising": rising[i], "socket": batch[i], "pipe": stable[i]},
		})
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	rep, err := Analyze(tl, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.Samples != 6 || rep.Incomplete || rep.Dropped != 0 {
		t.Errorf("report header = samples %d dropped %d incomplete %v, want 6/0/false",
			rep.Samples, rep.Dropped, rep.Incomplete)
	}
	if rep.SpanMillis != 5 {
		t.Errorf("span = %dms, want 5ms", rep.SpanMillis)
	}

	var risingRows, reboundedRows []string
	for _, s := range rep.Rising() {
		risingRows = append(risingRows, s.Fingerprint)
	}
	for _, s := range rep.Rebounded() {
		reboundedRows = append(reboundedRows, s.Fingerprint)
	}
	if len(risingRows) != 1 || risingRows[0] != "file:/rising" {
		t.Errorf("Rising() = %v, want [file:/rising]", risingRows)
	}
	if len(reboundedRows) != 1 || reboundedRows[0] != "socket" {
		t.Errorf("Rebounded() = %v, want [socket]", reboundedRows)
	}

	// Ordering: largest peak first, so the resource that mattered most is at the
	// top of the table.
	if len(rep.Series) != 3 {
		t.Fatalf("series = %d rows, want 3", len(rep.Series))
	}
	if rep.Series[0].Fingerprint != "socket" || rep.Series[0].Max != 12 {
		t.Errorf("first row = %q max %d, want socket max 12", rep.Series[0].Fingerprint, rep.Series[0].Max)
	}
	// The peak time must point at the sample the peak was found in, not at the
	// last sample.
	if rep.Series[0].PeakAt != 2 || rep.Series[0].PeakTime != 3_000_000 {
		t.Errorf("socket peak at %d (time %d), want index 2 time 3000000",
			rep.Series[0].PeakAt, rep.Series[0].PeakTime)
	}
}

func seriesByName(t *testing.T, rep Report, fp string) Summary {
	t.Helper()
	for _, s := range rep.Series {
		if s.Fingerprint == fp {
			return s
		}
	}
	names := make([]string, 0, len(rep.Series))
	for _, s := range rep.Series {
		names = append(names, s.Fingerprint)
	}
	t.Fatalf("no series for %q; have %s", fp, strings.Join(names, ", "))
	return Summary{}
}
