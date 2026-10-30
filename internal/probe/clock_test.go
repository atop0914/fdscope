package probe

import (
	"os"
	"testing"
	"time"
)

// TestStampClockMeasuresElapsedNotTheWallClock pins the property the sampling loop
// depends on: intervals come from the monotonic reading, not from re-reading a clock
// that something else can move.
//
// The injected wall clock is frozen, so an implementation that read it per sample would
// hand the timeline identical timestamps - which it refuses to append - and the run
// would stop with "sample out of order" for a process that was perfectly healthy.
func TestStampClockMeasuresElapsedNotTheWallClock(t *testing.T) {
	frozen := time.Date(2026, 10, 30, 20, 0, 0, 0, time.UTC)
	offset := time.Duration(0)
	clk := &stampClock{
		base:    frozen,
		elapsed: func() time.Duration { return offset },
	}

	var stamps []int64
	for i := 0; i < 4; i++ {
		stamps = append(stamps, clk.stamp())
		offset += 200 * time.Millisecond
	}
	for i := 1; i < len(stamps); i++ {
		if stamps[i] <= stamps[i-1] {
			t.Fatalf("stamp %d (%d) is not after %d: the run's time axis is not increasing",
				i, stamps[i], stamps[i-1])
		}
		if got, want := stamps[i]-stamps[i-1], int64(200*time.Millisecond); got != want {
			t.Errorf("gap %d = %dns, want the elapsed %dns", i, got, want)
		}
	}
	if clk.steps != 0 {
		t.Errorf("steps = %d, want 0 for a clock that only moved forward", clk.steps)
	}
}

// TestStampClockNeverGoesBackwards covers the correction the guard exists for.
//
// A clock that steps backwards must not make the series non-increasing: the timeline
// rejects such a sample and the whole run dies with it. The stamp is forced forward and
// the correction is counted, so "the window is a little shorter than its labels" is a
// fact the caller can see rather than infer.
func TestStampClockNeverGoesBackwards(t *testing.T) {
	frozen := time.Date(2026, 10, 30, 20, 0, 0, 0, time.UTC)
	offsets := []time.Duration{0, 200 * time.Millisecond, -300 * time.Millisecond, -100 * time.Millisecond}
	i := 0
	clk := &stampClock{
		base:    frozen,
		elapsed: func() time.Duration { return offsets[i] },
	}

	var stamps []int64
	for i = 0; i < len(offsets); i++ {
		stamps = append(stamps, clk.stamp())
	}
	for j := 1; j < len(stamps); j++ {
		if stamps[j] <= stamps[j-1] {
			t.Fatalf("stamp %d (%d) is not after %d: a backwards clock reached the timeline", j, stamps[j], stamps[j-1])
		}
	}
	if clk.steps == 0 {
		t.Error("steps = 0, but the clock went backwards twice: the correction must be counted")
	}
}

// TestWatchSurvivesAFrozenWallClock is the same property through the sampler, because
// that is where the timeline sees the stamps.
//
// It is the shape the machine actually produced: a wall clock that stops agreeing with
// itself mid-run. Here it is frozen outright rather than stepped, which is the harsher
// version - every sample would carry the same timestamp.
func TestWatchSurvivesAFrozenWallClock(t *testing.T) {
	frozen := time.Date(2026, 10, 30, 20, 0, 0, 0, time.UTC)
	p := NewProbe()
	res, err := p.Watch(os.Getpid(), 3, WatchConfig{
		Interval: 30 * time.Millisecond,
		Capacity: 3,
		Now:      func() time.Time { return frozen },
	})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if res.Err != nil {
		t.Fatalf("Watch stopped: %v", res.Err)
	}
	if res.Timeline.Len() != 3 {
		t.Fatalf("retained %d samples, want 3", res.Timeline.Len())
	}
	samples := res.Timeline.Samples()
	for i := 1; i < len(samples); i++ {
		if samples[i].Taken <= samples[i-1].Taken {
			t.Fatalf("sample %d is not later than %d: the sampler kept wall-clock order",
				samples[i].Taken, samples[i-1].Taken)
		}
	}
	// The counters must still be attached: this test exists for the time axis, but a
	// sampler that dropped the readings while fixing it would pass the assertions above.
	if !samples[0].Counters.Threads.Known {
		t.Error("the sample carries no thread count: the counters were lost on the way")
	}
}
