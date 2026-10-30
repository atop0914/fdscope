package probe

import (
	"errors"
	"fmt"
	"time"

	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/timeline"
)

// WatchConfig controls a sampling run.
type WatchConfig struct {
	// Interval is the delay between the start of consecutive samples. The
	// effective spacing is this value rounded up by however long a snapshot
	// took, which matters on a process holding tens of thousands of
	// descriptors: sampling such a process can take longer than a short
	// interval, and drifting is honest whereas reporting a spacing the run did
	// not achieve is not.
	Interval time.Duration
	// Capacity bounds how many samples are retained. Older samples are evicted,
	// which is what keeps a days-long watch from turning the auditing tool into
	// the leak it is looking for.
	Capacity int
	// Now overrides the clock used to timestamp samples. Nil means time.Now.
	// It is injectable so the ordering and monotonicity rules can be tested
	// without sleeping.
	Now func() time.Time
}

// WatchResult is the outcome of a sampling run.
//
// The timeline is returned even when Err is set. A run that collected forty
// samples and then lost the process has forty samples of evidence, and discarding
// them because the last read failed is the single most wasteful thing a sampling
// tool can do: the abrupt end of a series is often the most interesting part of
// it.
type WatchResult struct {
	// Timeline holds every retained sample, oldest first, regardless of Err.
	Timeline *timeline.Timeline
	// Snapshots is how many snapshots were captured, including any that were
	// rejected as incomplete.
	Snapshots int
	// Incomplete counts snapshots that could not be read fully. They are not
	// appended to the timeline: a partial snapshot looks exactly like a
	// descriptor released, and a series built from them would show releases that
	// never happened.
	Incomplete int
	// Err is the error that stopped the run, if any. io.EOF-equivalent success
	// leaves it nil.
	Err error
	// ClockSteps counts samples whose timestamp had to be forced forward because the
	// run's clock went backwards. Zero on a healthy machine; a non-zero value says
	// the time axis was corrected and the window is a little shorter than the labels
	// suggest.
	ClockSteps int
}

// OK reports whether the run completed its requested number of samples.
func (r WatchResult) OK() bool { return r.Err == nil }

// stop records why the run ended early and returns the result.
//
// The error is carried inside the result rather than returned alongside it, and
// that is the point: Watch always returns a nil error from its internal failure
// paths so that a caller cannot accidentally discard the timeline by writing
// `if err != nil { return }`. The samples collected before the failure are the
// evidence the caller came for - a series that ends abruptly is usually the most
// interesting part - so the failure is reported as data, and the caller decides
// how to surface it.
func (r WatchResult) stop(err error) WatchResult {
	r.Err = err
	return r
}

// Watch samples pid count times, spaced interval apart, and returns the retained
// timeline.
//
// Every sample is a real read of /proc. Nothing is interpolated or synthesised:
// the series a report shows is exactly the sequence the kernel answered, and a
// sample that could not be read is counted rather than invented.
//
// The run stops early on the first read error, because every later snapshot would
// fail the same way and busy-looping against a dead process helps nobody. The
// partial timeline is still returned - see WatchResult.
func (p *Probe) Watch(pid, count int, cfg WatchConfig) (WatchResult, error) {
	if !IsSupported() {
		return WatchResult{}, ErrNotLinux
	}
	if pid <= 0 {
		return WatchResult{}, fmt.Errorf("invalid pid %d", pid)
	}
	if count < 1 {
		return WatchResult{}, fmt.Errorf("sample count must be at least 1, got %d", count)
	}
	if cfg.Interval < 0 {
		return WatchResult{}, fmt.Errorf("interval must not be negative, got %s", cfg.Interval)
	}
	if cfg.Capacity < 1 {
		return WatchResult{}, fmt.Errorf("timeline capacity must be at least 1, got %d", cfg.Capacity)
	}
	// The clock is read once and every later stamp is measured from it, so that a
	// wall-clock correction cannot make the series go backwards. See stampClock.
	clk := newStampClock(cfg.Now)

	tl, err := timeline.New(pid, cfg.Capacity)
	if err != nil {
		return WatchResult{}, err
	}

	res := WatchResult{Timeline: tl}
	start, err := p.StartTime(pid)
	if err != nil {
		return res.stop(err), nil
	}
	if err := tl.SetStartTime(start); err != nil {
		return res.stop(err), nil
	}

	for i := 0; i < count; i++ {
		if i > 0 && cfg.Interval > 0 {
			time.Sleep(cfg.Interval)
		}

		snap, snapErr := p.Snapshot(pid)
		if snapErr != nil {
			return res.stop(snapErr), nil
		}
		res.Snapshots++

		// Re-read the start time every round. A pid that was recycled mid-run
		// produces a timeline whose counts jump to an unrelated process's, and
		// that splice is indistinguishable from a leak in the series.
		instStart, startErr := p.StartTime(pid)
		if startErr != nil {
			return res.stop(startErr), nil
		}
		if setErr := tl.SetStartTime(instStart); setErr != nil {
			return res.stop(setErr), nil
		}

		if !snap.Complete() {
			// Not appended, but the run continues: a single busy sample is
			// churn, and aborting on it would make the sampler unusable against
			// any process under load. The count is reported so a report can say
			// the series has gaps.
			res.Incomplete++
			continue
		}

		sample := timeline.Sample{
			Taken:    clk.stamp(),
			Total:    snap.Len(),
			Limit:    snap.OpenLimit,
			Counts:   make(map[string]int, snap.Len()),
			Counters: snap.Counters,
		}
		for _, d := range snap.Descriptors {
			sample.Counts[d.Fingerprint]++
		}
		if addErr := tl.Add(sample); addErr != nil {
			return res.stop(addErr), nil
		}
	}

	res.Err = nil
	res.ClockSteps = clk.steps
	return res, nil
}

// ErrWatchAborted is returned by callers that stop a watch before its sample
// count is reached. It exists so that "the operator interrupted the watch" is not
// confused with "the process died", which are the same shape in the timeline.
var ErrWatchAborted = errors.New("watch aborted before reaching the requested sample count")

// SampleFromSnapshot converts a snapshot into one timeline sample.
//
// It is exported so tests and embedders can build a series from snapshots they
// took themselves without re-implementing the counting rule - and so the rule
// lives in exactly one place. The two must never disagree: a report groups by
// fingerprint, and a sample that counted differently would show a resource split
// across two rows.
func SampleFromSnapshot(s model.Snapshot) timeline.Sample {
	sample := timeline.Sample{
		Taken:    s.Taken,
		Total:    s.Len(),
		Limit:    s.OpenLimit,
		Counts:   make(map[string]int, s.Len()),
		Counters: s.Counters,
	}
	for _, d := range s.Descriptors {
		sample.Counts[d.Fingerprint]++
	}
	return sample
}

// SampleTimeline samples pid count times into a fresh timeline, skipping
// incomplete snapshots exactly as Watch does.
//
// It is Watch without the verdict-facing extras: no snapshot bookkeeping, no
// start-time reuse rules beyond the ones the timeline itself enforces, and the
// error is returned directly. It exists for callers that judge the timeline
// themselves - the analyzer's tests sample a real leaking process through this,
// so that the path they exercise is the production path and not a second counting
// rule that could drift from it.
//
// Unlike Watch, a read error is returned alongside the timeline rather than
// swallowed into the result: there is no report to salvage here, and a caller
// judging the samples must know that the series ends early.
func (p *Probe) SampleTimeline(pid, count int, interval time.Duration) (*timeline.Timeline, error) {
	if !IsSupported() {
		return nil, ErrNotLinux
	}
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	if count < 1 {
		return nil, fmt.Errorf("sample count must be at least 1, got %d", count)
	}
	if interval < 0 {
		return nil, fmt.Errorf("interval must not be negative, got %s", interval)
	}

	tl, err := timeline.New(pid, count)
	if err != nil {
		return nil, err
	}
	start, err := p.StartTime(pid)
	if err != nil {
		return nil, err
	}
	if err := tl.SetStartTime(start); err != nil {
		return nil, err
	}

	clk := newStampClock(nil)
	for i := 0; i < count; i++ {
		if i > 0 && interval > 0 {
			time.Sleep(interval)
		}
		snap, snapErr := p.Snapshot(pid)
		if snapErr != nil {
			return tl, snapErr
		}
		// A pid recycled mid-run would splice two unrelated descriptor sets
		// into one series, which is indistinguishable from a leak.
		instStart, startErr := p.StartTime(pid)
		if startErr != nil {
			return tl, startErr
		}
		if setErr := tl.SetStartTime(instStart); setErr != nil {
			return tl, setErr
		}
		if !snap.Complete() {
			continue
		}
		sample := SampleFromSnapshot(snap)
		// The stamp comes from the run's clock, not from the snapshot: the snapshot's
		// own time is a wall-clock reading, and a step between two of them would be
		// rejected here for a reason that has nothing to do with the process.
		sample.Taken = clk.stamp()
		if addErr := tl.Add(sample); addErr != nil {
			return tl, addErr
		}
	}
	return tl, nil
}
