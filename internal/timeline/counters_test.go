package timeline

import (
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// TestAddKeepsCounters pins the field the Sample copy would otherwise drop.
//
// Add rebuilds each sample field by field so that a caller reusing one map cannot
// rewrite history; a new field that is not listed in that rebuild is silently
// zeroed, and every correlation downstream would then be computed against zeros
// that look like readings.
func TestAddKeepsCounters(t *testing.T) {
	tl, err := New(1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := tl.Add(Sample{
		Taken:  1,
		Total:  3,
		Counts: map[string]int{"file:/a": 3},
		Counters: model.ProcessCounters{
			Threads:       model.NewCounter(7),
			SyscallsWrite: model.NewCounter(42),
		},
	}); err != nil {
		t.Fatal(err)
	}

	got := tl.Samples()[0].Counters
	if want := model.NewCounter(7); got.Threads != want {
		t.Errorf("threads = %+v, want %+v", got.Threads, want)
	}
	if want := model.NewCounter(42); got.SyscallsWrite != want {
		t.Errorf("syscw = %+v, want %+v", got.SyscallsWrite, want)
	}
}

// TestCounterSeriesAlignsWithSamples proves a counter series is as long as the
// timeline and that an unreadable sample stays at its own index.
//
// Dropping unknown samples would shift every later reading one index left, and the
// correlation would then compare the counter at sample 9 with descriptors at
// sample 10 - a silent off-by-one that no report could reveal.
func TestCounterSeriesAlignsWithSamples(t *testing.T) {
	tl, err := New(1, 8)
	if err != nil {
		t.Fatal(err)
	}
	readings := []model.Counter{
		model.NewCounter(10),
		model.UnknownCounter(),
		model.NewCounter(30),
	}
	for i, r := range readings {
		if err := tl.Add(Sample{
			Taken:    int64(i + 1),
			Total:    i + 1,
			Counts:   map[string]int{"file:/a": i + 1},
			Counters: model.ProcessCounters{SyscallsWrite: r},
		}); err != nil {
			t.Fatal(err)
		}
	}

	var syscw model.CounterSeries
	for _, cs := range tl.CounterSeries() {
		if cs.Counter == model.CounterSyscallsWrite {
			syscw = cs
		}
	}
	if syscw.Counter == "" {
		t.Fatalf("no syscw series: %+v", tl.CounterSeries())
	}
	if len(syscw.Values) != tl.Len() || len(syscw.Known) != tl.Len() {
		t.Fatalf("series length = %d/%d, want %d", len(syscw.Values), len(syscw.Known), tl.Len())
	}
	if want := []bool{true, false, true}; !equalBools(syscw.Known, want) {
		t.Errorf("known = %v, want %v", syscw.Known, want)
	}
	if got, want := syscw.Values[2], int64(30); got != want {
		t.Errorf("values[2] = %d, want %d", got, want)
	}
}

// TestCounterSeriesNamesEveryCounter guards against a counter that exists in the
// struct but never reaches a report.
func TestCounterSeriesNamesEveryCounter(t *testing.T) {
	tl, err := New(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := tl.Add(Sample{Taken: 1, Total: 0, Counts: map[string]int{}}); err != nil {
		t.Fatal(err)
	}
	series := tl.CounterSeries()

	var proto model.ProcessCounters
	want := proto.Names()
	if len(series) != len(want) {
		t.Fatalf("got %d series, want %d (%v)", len(series), len(want), want)
	}
	seen := make(map[model.CounterName]bool, len(series))
	for _, cs := range series {
		seen[cs.Counter] = true
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("counter %q has no series", name)
		}
	}
}

// TestCounterSeriesSurvivesEviction proves the ring buffer keeps counters with the
// sample they belong to.
func TestCounterSeriesSurvivesEviction(t *testing.T) {
	tl, err := New(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := tl.Add(Sample{
			Taken:    int64(i + 1),
			Total:    i,
			Counts:   map[string]int{},
			Counters: model.ProcessCounters{SyscallsWrite: model.NewCounter(int64(100 + i))},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !tl.Incomplete() {
		t.Fatal("expected eviction to be reported")
	}
	var syscw model.CounterSeries
	for _, cs := range tl.CounterSeries() {
		if cs.Counter == model.CounterSyscallsWrite {
			syscw = cs
		}
	}
	if want := []int64{102, 103, 104}; !equalInt64s(syscw.Values, want) {
		t.Errorf("values = %v, want the three most recent %v", syscw.Values, want)
	}
}

func equalBools(a, b []bool) bool {
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

func equalInt64s(a, b []int64) bool {
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
