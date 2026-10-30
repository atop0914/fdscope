package probe

import "time"

// stampClock produces the observation time for each sample of one run.
//
// The wall clock is read once, at the start, and every later stamp is that reading
// plus the elapsed monotonic time. Reading the wall clock per sample looks simpler
// and is wrong: the wall clock is adjusted by NTP and by the hypervisor, and a step
// backwards makes the next sample "before" the previous one. The timeline refuses to
// append an out-of-order sample - correctly, because a misordered series produces a
// negative slope - so a clock correction would abort a run that had measured
// everything it was asked to.
//
// Measured: a 3s check inside Docker Desktop on Windows aborted twice in one evening
// with "sample out of order: ... is not after ...", each time by about half a second.
// Nothing about the target process had changed; the clock had.
//
// The monotonic reading cannot step, so durations stay true to what was observed. The
// absolute timestamps drift from the wall clock by whatever correction happened
// during the run, which is the honest trade: the interval between two samples is a
// measurement, while the epoch is a label.
type stampClock struct {
	// base is the wall clock at the start of the run.
	base time.Time
	// elapsed is the monotonic time since the run started. It is a field so that a
	// clock that steps can be tested without waiting for one to happen.
	elapsed func() time.Duration
	// last is the most recent stamp, kept so the sequence can never go backwards
	// even if the elapsed source misbehaves.
	last int64
	// steps counts stamps that had to be forced forward. It stays zero on a healthy
	// machine, and a non-zero value says the time axis of the run was corrected.
	steps int
}

// newStampClock starts a run's clock. now may be nil, meaning time.Now.
func newStampClock(now func() time.Time) *stampClock {
	if now == nil {
		now = time.Now
	}
	start := time.Now()
	return &stampClock{
		base:    now(),
		elapsed: func() time.Duration { return time.Since(start) },
	}
}

// stamp returns the observation time for the next sample, in Unix nanoseconds.
func (c *stampClock) stamp() int64 {
	t := c.base.Add(c.elapsed()).UnixNano()
	if t <= c.last {
		// The guard is not redundant with the monotonic basis: an injected clock (or a
		// platform without a monotonic reading) can still produce a step, and a single
		// duplicate timestamp would make the run fail to append at all.
		t = c.last + 1
		c.steps++
	}
	c.last = t
	return t
}
