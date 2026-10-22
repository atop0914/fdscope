//go:build linux

package probe

import (
	"fmt"
	"time"

	"github.com/atop0914/fdscope/internal/model"
)

// SamplePair is two snapshots of one process taken a known interval apart.
//
// Both start times are returned because the process may exit and have its pid
// reused between the two reads; a caller comparing the snapshots must be able
// to prove it observed the same process twice, and the start time is the only
// cheap identity the kernel exposes.
type SamplePair struct {
	Before      model.Snapshot
	After       model.Snapshot
	BeforeStart uint64
	AfterStart  uint64
}

// SnapshotsOf takes count snapshots spaced delay apart and returns the first and
// the last, along with the process start time observed at each point.
//
// Only the endpoints are returned on purpose: a diff of the endpoints is what
// answers "what changed while I watched", and keeping the intermediate samples
// would invite callers to average over them - a judgement (leak or not) that
// belongs to the analyser, not to the probe.
func (p *Probe) SnapshotsOf(pid, count int, delay time.Duration) (SamplePair, error) {
	if pid <= 0 {
		return SamplePair{}, fmt.Errorf("invalid pid %d", pid)
	}
	if count < 1 {
		return SamplePair{}, fmt.Errorf("count must be at least 1, got %d", count)
	}
	if delay < 0 {
		return SamplePair{}, fmt.Errorf("delay must not be negative, got %s", delay)
	}

	first, err := p.Snapshot(pid)
	if err != nil {
		return SamplePair{}, err
	}
	firstStart, err := p.StartTime(pid)
	if err != nil {
		return SamplePair{}, err
	}

	pair := SamplePair{Before: first, After: first, BeforeStart: firstStart, AfterStart: firstStart}
	for i := 1; i < count; i++ {
		if delay > 0 {
			time.Sleep(delay)
		}
		next, snapErr := p.Snapshot(pid)
		if snapErr != nil {
			return SamplePair{}, snapErr
		}
		nextStart, startErr := p.StartTime(pid)
		if startErr != nil {
			return SamplePair{}, startErr
		}
		pair.After, pair.AfterStart = next, nextStart
	}
	return pair, nil
}
