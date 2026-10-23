package timeline

import (
	"strings"
	"testing"
)

// mkSample builds a sample with one fingerprint count. The Taken value is
// derived from n so every helper call produces an ordered series.
func mkSample(n int64, fp string, count int) Sample {
	return Sample{
		Taken:  n,
		Total:  count,
		Counts: map[string]int{fp: count},
	}
}

// TestNewRejectsImpossibleArguments guards the two ways a timeline can be built
// so that it silently retains nothing. A zero capacity is the dangerous one: the
// store would accept samples and immediately evict them, and every summarised
// series would read flat - which is exactly the false conclusion this package
// exists to prevent.
func TestNewRejectsImpossibleArguments(t *testing.T) {
	if _, err := New(0, 10); err == nil {
		t.Error("New(0, 10) accepted a zero pid")
	}
	if _, err := New(1234, 0); err == nil {
		t.Error("New(1234, 0) accepted a zero capacity; a timeline that retains nothing reports every series as flat")
	}
	if _, err := New(1234, -1); err == nil {
		t.Error("New(1234, -1) accepted a negative capacity")
	}
	tl, err := New(1234, 3)
	if err != nil {
		t.Fatalf("New(1234, 3): %v", err)
	}
	if tl.PID() != 1234 || tl.Capacity() != 3 || tl.Len() != 0 {
		t.Errorf("New returned pid=%d capacity=%d len=%d, want 1234/3/0", tl.PID(), tl.Capacity(), tl.Len())
	}
}

// TestBoundIsAssertedOnRealLength is the acceptance criterion from the plan:
// the retained length must stop growing, and the assertion is on the length the
// container actually reports - not on the configured capacity echoed back.
func TestBoundIsAssertedOnRealLength(t *testing.T) {
	const capacity = 5
	tl, err := New(1, capacity)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 1; i <= 50; i++ {
		if err := tl.Add(mkSample(int64(i), "file:/a", i)); err != nil {
			t.Fatalf("Add #%d: %v", i, err)
		}
		if got := len(tl.Samples()); got > capacity {
			t.Fatalf("after %d samples the retained length is %d, want <= %d", i, got, capacity)
		}
	}
	if got := tl.Len(); got != capacity {
		t.Errorf("retained length = %d, want exactly %d once the bound is reached", got, capacity)
	}
	if got := tl.Dropped(); got != 50-capacity {
		t.Errorf("dropped = %d, want %d", got, 50-capacity)
	}
	if !tl.Incomplete() {
		t.Error("Incomplete() = false after discarding samples; a report would claim to cover the whole period")
	}

	// The retained window must be the newest one, in order. An eviction that
	// kept the oldest samples would pass a length check while reporting a
	// history that ended long ago.
	samples := tl.Samples()
	for i := 1; i < len(samples); i++ {
		if samples[i].Taken <= samples[i-1].Taken {
			t.Fatalf("retained samples are not ordered at %d: %d then %d", i, samples[i-1].Taken, samples[i].Taken)
		}
	}
	if want := int64(50); samples[len(samples)-1].Taken != want {
		t.Errorf("newest retained sample = %d, want %d", samples[len(samples)-1].Taken, want)
	}
	if want := int64(50 - capacity + 1); samples[0].Taken != want {
		t.Errorf("oldest retained sample = %d, want %d", samples[0].Taken, want)
	}
}

// TestIncompleteOnlyAfterEviction is the reverse assertion for the "partial
// history" flag: a report that always says "incomplete" is as misleading as one
// that never does, because operators stop reading the warning.
func TestIncompleteOnlyAfterEviction(t *testing.T) {
	tl, err := New(1, 4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 1; i <= 4; i++ {
		if err := tl.Add(mkSample(int64(i), "file:/a", 1)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if tl.Incomplete() {
		t.Error("Incomplete() = true while every sample still fits; the warning would be noise")
	}
	if tl.Dropped() != 0 {
		t.Errorf("dropped = %d, want 0", tl.Dropped())
	}
	if err := tl.Add(mkSample(5, "file:/a", 1)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !tl.Incomplete() || tl.Dropped() != 1 {
		t.Errorf("after eviction: incomplete=%v dropped=%d, want true/1", tl.Incomplete(), tl.Dropped())
	}
}

// TestAddRejectsUnorderedSamples guards the ordering precondition that every
// trend computation depends on. The alternative - sorting on read - would hide a
// caller that appends samples from the wrong clock source.
func TestAddRejectsUnorderedSamples(t *testing.T) {
	tl, err := New(1, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tl.Add(mkSample(100, "file:/a", 1)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := tl.Add(mkSample(200, "file:/a", 2)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := tl.Add(mkSample(200, "file:/a", 3)); err == nil {
		t.Error("Add accepted a duplicate timestamp")
	}
	if err := tl.Add(mkSample(150, "file:/a", 3)); err == nil {
		t.Error("Add accepted a sample older than the last one")
	}
	if err := tl.Add(Sample{Taken: 0}); err == nil {
		t.Error("Add accepted a zero Taken value")
	}
	if tl.Len() != 2 {
		t.Errorf("rejected samples were retained: len = %d, want 2", tl.Len())
	}
}

// TestAddCopiesCallerMap is the failure mode a watch loop hits immediately: the
// loop reuses one counts map, and without a copy every retained sample becomes
// the newest one. The series then looks perfectly flat even as the process leaks.
func TestAddCopiesCallerMap(t *testing.T) {
	tl, err := New(1, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	counts := map[string]int{"file:/a": 1}
	for i := 1; i <= 3; i++ {
		counts["file:/a"] = i
		if err := tl.Add(Sample{Taken: int64(i), Total: i, Counts: counts}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	// Mutate the caller's map after the fact; history must not follow.
	counts["file:/a"] = 999

	got := tl.FingerprintSeries("file:/a").Counts
	want := []int{1, 2, 3}
	if len(got) != len(want) {
		t.Fatalf("series = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("series = %v, want %v (history was aliased to the caller's map)", got, want)
		}
	}
}

// TestFingerprintSeriesZeroFills checks the fill-in rule: a resource absent from
// a sample is a zero, not a hole. A series with holes cannot be compared with
// another fingerprint's series and would make "released" and "not measured"
// look identical.
func TestFingerprintSeriesZeroFills(t *testing.T) {
	tl, err := New(1, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	samples := []Sample{
		{Taken: 1, Total: 3, Counts: map[string]int{"file:/a": 1, "socket": 2}},
		{Taken: 2, Total: 2, Counts: map[string]int{"socket": 2}},
		{Taken: 3, Total: 4, Counts: map[string]int{"file:/a": 4, "socket": 0}},
	}
	for _, s := range samples {
		if err := tl.Add(s); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	if got, want := tl.FingerprintSeries("file:/a").Counts, []int{1, 0, 4}; !equalInts(got, want) {
		t.Errorf("file:/a series = %v, want %v", got, want)
	}
	// A fingerprint never seen in the window still produces a series of the
	// right length, all zeros: a caller comparing lengths must never have to
	// special-case it.
	if got, want := tl.FingerprintSeries("file:/never").Counts, []int{0, 0, 0}; !equalInts(got, want) {
		t.Errorf("unknown fingerprint series = %v, want %v", got, want)
	}
	if got, want := tl.TotalSeries().Counts, []int{3, 2, 4}; !equalInts(got, want) {
		t.Errorf("total series = %v, want %v", got, want)
	}
	// The total comes from the stored field, not from summing the map, so it must
	// not silently become 4 where the stored total says 2.
	if got := tl.TotalSeries().Counts[1]; got != 2 {
		t.Errorf("total at sample 1 = %d, want 2 (stored total, not a sum of counts)", got)
	}
}

// TestFingerprintsKeepsVanishedResources ensures the listing is the union over
// the window. Deriving it from the newest sample would hide a resource that was
// opened and closed repeatedly - often the most interesting one.
func TestFingerprintsKeepsVanishedResources(t *testing.T) {
	tl, err := New(1, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = tl.Add(Sample{Taken: 1, Total: 2, Counts: map[string]int{"file:/gone": 1, "socket": 1}})
	_ = tl.Add(Sample{Taken: 2, Total: 1, Counts: map[string]int{"socket": 1}})

	got := tl.Fingerprints()
	want := []string{"file:/gone", "socket"}
	if len(got) != len(want) {
		t.Fatalf("Fingerprints() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Fingerprints() = %v, want %v (sorted)", got, want)
		}
	}
	if last, ok := tl.Last(); !ok || last.Taken != 2 {
		t.Errorf("Last() = %+v/%v, want sample at 2", last, ok)
	}
	if first, ok := tl.First(); !ok || first.Taken != 1 {
		t.Errorf("First() = %+v/%v, want sample at 1", first, ok)
	}
}

// TestEmptyTimelineReadsAreSafe covers the zero-sample case: reports are rendered
// after sampling, and a process that died before the first sample must produce an
// empty report rather than a panic.
func TestEmptyTimelineReadsAreSafe(t *testing.T) {
	tl, err := New(7, 3)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := tl.Last(); ok {
		t.Error("Last() reported a sample for an empty timeline")
	}
	if _, ok := tl.First(); ok {
		t.Error("First() reported a sample for an empty timeline")
	}
	if got := tl.TotalSeries().Counts; len(got) != 0 {
		t.Errorf("TotalSeries() = %v, want empty", got)
	}
	if got := tl.Fingerprints(); len(got) != 0 {
		t.Errorf("Fingerprints() = %v, want empty", got)
	}
	if tl.Incomplete() {
		t.Error("Incomplete() = true for an empty timeline")
	}
}

// TestSetStartTimeRefusesRecycledPID is the diff package's restart guard applied
// to the series: appending across a restart would splice two unrelated processes
// into one trend.
func TestSetStartTimeRefusesRecycledPID(t *testing.T) {
	tl, err := New(9, 4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tl.SetStartTime(0); err == nil {
		t.Error("SetStartTime(0) accepted an unknown start time")
	}
	if err := tl.SetStartTime(555); err != nil {
		t.Fatalf("SetStartTime(555): %v", err)
	}
	if err := tl.SetStartTime(555); err != nil {
		t.Fatalf("re-setting the same start time must be allowed: %v", err)
	}
	err = tl.SetStartTime(556)
	if err == nil {
		t.Fatal("SetStartTime accepted a different start time")
	}
	if !strings.Contains(err.Error(), "restarted") {
		t.Errorf("error %q does not say the process restarted", err)
	}
	if tl.StartTime() != 555 {
		t.Errorf("StartTime() = %d, want 555", tl.StartTime())
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
