// Package timeline holds the descriptor history of one process: a bounded
// sequence of samples, each recording how many descriptors shared every
// fingerprint at one instant.
//
// The package exists because two snapshots cannot answer the question that
// matters. "The count went from 100 to 140" is equally consistent with a leak, a
// connection pool warming up, and a batch job in flight; only the shape of the
// series between the endpoints separates them. internal/analyze does the judging,
// but it can only judge what this package kept.
//
// Bounded memory is not an optimisation here, it is a correctness requirement.
// `fdscope watch` is meant to run against a service for days. A container that
// keeps every sample would leak memory in the very tool that is supposed to find
// descriptor leaks, and the first thing the operator would see is fdscope's own
// process growing - which would discredit the report entirely.
package timeline

import (
	"fmt"
	"sort"

	"github.com/atop0914/fdscope/internal/model"
)

// Sample is the fingerprint breakdown of one observation.
//
// Counts is keyed by fingerprint and holds the number of descriptors that shared
// it, which is the same aggregation every report groups by. A fingerprint that
// disappeared from a sample is simply absent from that sample's map rather than
// present with a zero count: absence and zero would otherwise have to be
// distinguished at every read site, and one of them would eventually be missed.
type Sample struct {
	// Taken is the observation time in Unix nanoseconds.
	Taken int64
	// Total is the number of descriptors counted in this sample. It is stored
	// rather than summed from Counts because a snapshot may have contained
	// entries the normaliser could not attribute, and re-deriving the total
	// would quietly drop them.
	Total int
	// Counts maps fingerprint to the number of descriptors holding it.
	Counts map[string]int
	// Limit is the process's descriptor limit at this sample: a finite number,
	// "unlimited", or unknown. It is recorded per sample rather than once
	// because a process may raise its own limit while being watched, and a
	// headroom figure computed against a limit that has since changed would be
	// a lie.
	Limit model.OpenLimit
	// Counters holds the process-level readings taken with this sample. They
	// are carried per sample rather than in a side table so that a counter and
	// the descriptor counts it is compared against can never drift apart by an
	// index: both are the same sample or neither is.
	Counters model.ProcessCounters
}

// Count returns the number of descriptors that held fp in this sample, or 0 when
// the fingerprint was absent. Callers cannot tell "absent" from "zero" through
// this method, which is deliberate: for a count, absent and zero are the same
// fact, and making them distinguishable has never been worth the confusion.
func (s Sample) Count(fp string) int { return s.Counts[fp] }

// Timeline is the bounded history of one process.
//
// The zero value is usable but retains nothing; use New to get a real capacity.
// It is not safe for concurrent use: a watcher appends from one goroutine and
// every report reads the result after sampling has stopped, so a mutex would add
// contention to the sampling path for no caller's benefit.
type Timeline struct {
	// pid is the process the history belongs to.
	pid int
	// start identifies the process instance via /proc/<pid>/stat field 22.
	// A pid alone cannot: the kernel hands a freed pid to the next process.
	start uint64
	// capacity is the maximum number of retained samples.
	capacity int
	// samples is a ring buffer of size capacity once it fills.
	samples []Sample
	// next is the ring write position; len(samples) < capacity means the
	// buffer is not yet full and samples[0:len] holds the history in order.
	next int
	// dropped counts samples evicted by the capacity bound. It is reported so
	// that a summariser can say the history is partial instead of implying it
	// observed the process from the start.
	dropped int
}

// New creates a timeline for pid with room for capacity samples.
//
// capacity must be positive. A zero-capacity timeline would silently retain
// nothing and every summarised series would look flat - the exact failure mode
// this package is meant to prevent - so it is rejected at construction.
func New(pid int, capacity int) (*Timeline, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid %d", pid)
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("timeline capacity must be positive, got %d", capacity)
	}
	return &Timeline{pid: pid, capacity: capacity}, nil
}

// PID is the process this history describes.
func (t *Timeline) PID() int { return t.pid }

// Capacity is the maximum number of retained samples.
func (t *Timeline) Capacity() int { return t.capacity }

// StartTime is the process start time recorded by SetStartTime, or 0.
func (t *Timeline) StartTime() uint64 { return t.start }

// SetStartTime records the process instance identity.
//
// It refuses to overwrite a different non-zero value, because that means the pid
// was recycled: continuing to append samples across a restart would produce a
// series that looks like one process leaking while it is really two processes
// with unrelated descriptor sets. Callers must start a new timeline instead.
func (t *Timeline) SetStartTime(start uint64) error {
	if start == 0 {
		return fmt.Errorf("start time must be non-zero: without it a reused pid is indistinguishable from the same process")
	}
	if t.start != 0 && t.start != start {
		return fmt.Errorf("process %d restarted during sampling (start time %d -> %d)", t.pid, t.start, start)
	}
	t.start = start
	return nil
}

// Add appends a sample, evicting the oldest one when the capacity is reached.
//
// Eviction is the whole point of the bound: the timeline keeps the most recent
// window and reports how much it had to discard, so a report can say "last 60 of
// 5000 samples" rather than pretending the history starts at the process start.
func (t *Timeline) Add(s Sample) error {
	if s.Taken <= 0 {
		return fmt.Errorf("sample taken time must be positive")
	}
	if n := len(t.samples); n > 0 {
		// Samples must be ordered by time: every trend computation walks the
		// slices in order and would silently produce a negative slope from a
		// misordered pair.
		last := t.samples[t.index(n-1)]
		if s.Taken <= last.Taken {
			return fmt.Errorf("sample out of order: %d is not after %d", s.Taken, last.Taken)
		}
	}

	// Copy the map so that a caller mutating its own snapshot cannot retroactively
	// rewrite history. Without this, a watch loop that reuses one map would turn
	// every retained sample into the latest one, and the series would look flat.
	cp := Sample{Taken: s.Taken, Total: s.Total, Limit: s.Limit, Counts: make(map[string]int, len(s.Counts)), Counters: s.Counters}
	for fp, c := range s.Counts {
		cp.Counts[fp] = c
	}

	if len(t.samples) < t.capacity {
		t.samples = append(t.samples, cp)
		return nil
	}
	t.samples[t.next] = cp
	t.next = (t.next + 1) % t.capacity
	t.dropped++
	return nil
}

// Len is the number of retained samples.
func (t *Timeline) Len() int { return len(t.samples) }

// Dropped is the number of samples evicted by the capacity bound.
func (t *Timeline) Dropped() int { return t.dropped }

// index maps a logical position (0 = oldest retained) to its slot in the ring.
func (t *Timeline) index(i int) int {
	if len(t.samples) < t.capacity {
		return i
	}
	return (t.next + i) % t.capacity
}

// Samples returns the retained samples oldest first.
//
// A copy is returned so that a caller ranging over the result cannot race with a
// concurrent Add, and so that appending to the result does not corrupt the ring.
func (t *Timeline) Samples() []Sample {
	out := make([]Sample, len(t.samples))
	for i := range out {
		out[i] = t.samples[t.index(i)]
	}
	return out
}

// Series is the value of one fingerprint over time.
//
// Absent samples are filled in with zero rather than dropped, because a series
// with holes cannot be compared with another fingerprint: the reader would see
// two sequences of different lengths and have no way to know whether a resource
// was released or merely not sampled.
type Series struct {
	// Fingerprint identifies the resource.
	Fingerprint string `json:"fingerprint"`
	// Counts holds one value per retained sample, oldest first. Its length
	// always equals the timeline length.
	Counts []int `json:"counts"`
}

// TotalSeries is the descriptor total over time, oldest first.
//
// It is a Series rather than a bare []int so that the same summarising code can
// describe the process total and an individual fingerprint without a second
// implementation that would eventually disagree with the first.
func (t *Timeline) TotalSeries() Series {
	samples := t.Samples()
	counts := make([]int, len(samples))
	for i, s := range samples {
		counts[i] = s.Total
	}
	return Series{Fingerprint: "(total)", Counts: counts}
}

// FingerprintSeries returns the value of fp over time, zero-filled where absent.
func (t *Timeline) FingerprintSeries(fp string) Series {
	samples := t.Samples()
	counts := make([]int, len(samples))
	for i, s := range samples {
		counts[i] = s.Count(fp)
	}
	return Series{Fingerprint: fp, Counts: counts}
}

// Fingerprints lists every fingerprint observed at least once in the retained
// window, sorted for deterministic output.
//
// A fingerprint that appeared and then vanished is still listed: a resource that
// was opened a hundred times and closed each time is interesting, and deriving
// the list from the newest sample alone would hide it.
func (t *Timeline) Fingerprints() []string {
	seen := make(map[string]struct{})
	for _, s := range t.samples {
		for fp := range s.Counts {
			seen[fp] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for fp := range seen {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

// Limit returns the most recent descriptor limit the window established.
//
// The most recent, not the first: a process that raised its limit mid-run is now
// constrained by the new value, and the headroom figure must follow. A sample
// whose limit could not be read does not overwrite an earlier answer - "I could
// not read it this time" is not news about the limit - but "unlimited" does,
// because it is an answer.
func (t *Timeline) Limit() model.OpenLimit {
	for i := len(t.samples) - 1; i >= 0; i-- {
		l := t.samples[t.index(i)].Limit
		if !l.Unknown() {
			return l
		}
	}
	return model.UnknownLimit()
}

// Last returns the newest retained sample.
func (t *Timeline) Last() (Sample, bool) {
	if len(t.samples) == 0 {
		return Sample{}, false
	}
	return t.samples[t.index(len(t.samples)-1)], true
}

// First returns the oldest retained sample.
func (t *Timeline) First() (Sample, bool) {
	if len(t.samples) == 0 {
		return Sample{}, false
	}
	return t.samples[t.index(0)], true
}

// CounterSeries returns one named series per process-level counter, oldest sample
// first, in the fixed order ProcessCounters.Names defines.
//
// Every series is as long as the timeline, including the samples where the
// counter could not be read: those carry Known=false rather than a zero, so a
// consumer cannot mistake "the kernel did not answer" for "the value was 0". A
// series that dropped unknown samples instead would silently shift every later
// index and misalign the counter with the descriptor counts it is compared to.
func (t *Timeline) CounterSeries() []model.CounterSeries {
	samples := t.Samples()
	var proto model.ProcessCounters
	names := proto.Names()
	out := make([]model.CounterSeries, 0, len(names))
	for _, name := range names {
		cs := model.CounterSeries{
			Counter: name,
			Values:  make([]int64, len(samples)),
			Known:   make([]bool, len(samples)),
		}
		for i, s := range samples {
			c := s.Counters.Get(name)
			cs.Values[i], cs.Known[i] = c.Value, c.Known
		}
		out = append(out, cs)
	}
	return out
}

// Incomplete reports whether samples were evicted, meaning the retained window
// does not cover the whole observed period.
// Reports must say so: "the count rose from 100 to 140 across 60 samples" reads
// as the full story, and if 5000 samples were discarded the earliest change -
// usually the interesting one - happened before the window begins.
func (t *Timeline) Incomplete() bool { return t.dropped > 0 }
