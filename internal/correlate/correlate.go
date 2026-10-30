// Package correlate answers the second question an operator asks after "is it
// leaking": "what was the process doing when it started?"
//
// It answers it weakly, and the weakness is the design. /proc never records which
// code path opened a descriptor, so the only honest statement available is
// "these two things changed in the same window, over N samples". That is L2, and
// it sits below L1 (which restates what the fingerprint already says) precisely
// because it is an observation about timing rather than about the resource.
//
// Three rules follow from that, and every line of this package exists to keep
// them:
//
//	no direction  - a correlation is never printed as a cause. The note carries
//	                the word "correlation" and none of the causal vocabulary; a
//	                test scans every note for the forbidden words.
//	silence by default - a counter that did not move, or that could not be read
//	                across enough samples, produces nothing at all. A section
//	                listing four counters on every run teaches the reader to skip
//	                the section.
//	unknown is not zero - an unreadable counter is skipped, never compared as if
//	                the kernel had answered 0. "This process never wrote" and "I
//	                could not see its writes" are different facts, and only one of
//	                them belongs in a report about what happened.
package correlate

import (
	"fmt"
	"math"

	"github.com/atop0914/fdscope/internal/model"
)

// Confidence states how much a correlation deserves to be believed.
//
// It describes the evidence and nothing else: how many samples of the window had
// a readable reading. It is deliberately not a probability that the counter
// caused the growth - computing one would require a model of the process that
// /proc does not provide, and inventing it is exactly the overreach this package
// refuses.
type Confidence string

const (
	// ConfidenceHigh means the whole window had readable readings and the window
	// is long enough to see a trend.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium means enough samples to compare, but few enough that a
	// spike could pass for a trend.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow means the comparison rests on the minimum number of samples.
	ConfidenceLow Confidence = "low"
)

// Thresholds for reporting, stated as constants because they are heuristics about
// shape rather than per-process numbers an operator would tune.
const (
	// minOverlap is the fewest readable samples in the window that can support a
	// comparison. Two samples are one gap, and one gap cannot tell a step from a
	// climb.
	minOverlap = 3
	// highOverlap is where the confidence stops being a caveat. Twelve samples of
	// a twenty-five sample check is most of the window.
	highOverlap = 12
	// mediumOverlap is where the comparison stops resting on the bare minimum.
	mediumOverlap = 6
)

// rule is the per-counter test for "did this move enough to be worth mentioning".
//
// Two floors rather than one, and both must be cleared. A percentage alone reads a
// syscall counter going 4000 -> 4200 as a 5% event while a thread count going
// 2 -> 3 is a 50% event; an absolute floor alone reads a busier version of the
// same process as movement. Requiring both means a counter has to change by an
// amount that is large in its own units *and* large relative to where it started.
type rule struct {
	// minPct is the relative change required, in percent, when a baseline exists.
	minPct float64
	// minAbs is the absolute change required, in the counter's own unit.
	minAbs int64
	// unit names that unit, so a note can say what number it is talking about.
	unit string
}

// rules holds the floor for each counter.
//
// The numbers come from what the counters mean, not from fitting a corpus:
//
//	threads  +2 threads is a new worker; +1 is a runtime detail
//	syscalls  a doubling is activity; a few hundred calls is background noise
//	rss      1MiB and 20% - below either, the process merely touched a page
var rules = map[model.CounterName]rule{
	model.CounterThreads:       {minPct: 50, minAbs: 2, unit: "threads"},
	model.CounterSyscallsRead:  {minPct: 50, minAbs: 50, unit: "calls"},
	model.CounterSyscallsWrite: {minPct: 50, minAbs: 50, unit: "calls"},
	model.CounterRSS:           {minPct: 20, minAbs: 1 << 20, unit: "bytes"},
}

// Correlation is one counter that moved with the onset of the growth.
type Correlation struct {
	// Counter names the reading.
	Counter model.CounterName `json:"counter"`
	// Baseline is the last reading before the rise began, and Latest the last
	// readable one inside the window. Both are reported so the reader can redo the
	// subtraction rather than trust it.
	Baseline int64 `json:"baseline"`
	Latest   int64 `json:"latest"`
	// Delta is Latest minus Baseline, and DeltaPct the same as a percentage of
	// Baseline. DeltaPct is absent when the baseline was zero: a percentage of
	// nothing is not a number, and printing 0% there would say "no change".
	Delta    int64    `json:"delta"`
	DeltaPct *float64 `json:"delta_pct,omitempty"`
	// Overlap is how many samples of the window had a readable reading, and
	// Window how many samples the window holds.
	Overlap int `json:"overlap_samples"`
	Window  int `json:"window_samples"`
	// Confidence describes the overlap, never the causation.
	Confidence Confidence `json:"confidence"`
	// Note is the sentence a reader takes away. It always says "correlation".
	Note string `json:"note"`
}

// Report is the L2 block: what moved, and why nothing did.
type Report struct {
	// Onset is the sample index where the growth began, or -1 when it could not
	// be located. Window is how many samples the comparison covers.
	Onset  int `json:"onset_index"`
	Window int `json:"window_samples"`
	// Correlations holds the counters that moved, confidence first.
	Correlations []Correlation `json:"correlations,omitempty"`
	// Notes explains the counters and windows that produced nothing. Empty is the
	// normal case for a clean run: there is no onset to correlate with and the
	// caller does not print the section at all.
	Notes []string `json:"notes,omitempty"`
}

// Compare relates the counters to the sample where the descriptors started to
// grow.
//
// onset is the index of the first sample that left the settled prefix - the same
// index the leak judgement uses to place its baseline, so the two layers agree
// about when the growth started instead of each computing its own answer.
//
// The baseline is the sample *before* the onset. When the onset is the first
// sample there is no such sample, and the report says so rather than treating the
// rise's own first value as a baseline: that would make every growth look like it
// began at zero change and silence L2 exactly where the growth is fastest.
func Compare(series []model.CounterSeries, samples, onset int) Report {
	rep := Report{Onset: onset}
	if samples < 2 {
		rep.Notes = append(rep.Notes, "a correlation needs at least two samples")
		return rep
	}
	if onset < 0 {
		rep.Notes = append(rep.Notes, "no onset was located, so there is nothing to correlate against")
		return rep
	}
	if onset == 0 {
		rep.Notes = append(rep.Notes, "the rise began at the first sample: it predates the window, "+
			"so there is no pre-window baseline to compare a counter against")
		return rep
	}
	if onset >= samples {
		rep.Notes = append(rep.Notes, "the growth predates the window: no sample in it shows a rise")
		return rep
	}
	// The baseline is the sample just before the rise. If it was not readable for
	// a counter, that counter is skipped: comparing against a later sample inside
	// the rise would understate the change, and comparing against zero would
	// overstate it.
	baseIdx := onset - 1
	rep.Window = samples - onset

	for _, cs := range series {
		// A series shorter than the window would make "overlap out of window"
		// describe a span it does not cover. It cannot happen through the timeline,
		// which builds every counter series at the sample count, so it is treated as
		// a caller error rather than reported as a finding.
		if len(cs.Values) < samples || len(cs.Known) < samples {
			continue
		}
		rep.consider(cs, baseIdx)
	}
	return rep
}

// consider adds one counter's verdict to the report, or explains why it has none.
func (rep *Report) consider(cs model.CounterSeries, baseIdx int) {
	r, known := rules[cs.Counter]
	if !known {
		// A counter this build does not have a floor for cannot be judged, and
		// judging it with someone else's floor would be inventing a threshold.
		return
	}
	if baseIdx < 0 || baseIdx >= len(cs.Values) || !cs.Known[baseIdx] {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%s could not be read before the window, so there is no baseline to compare against", cs.Counter))
		return
	}
	baseline := cs.Values[baseIdx]

	// The window's readable readings, and the last of them. The last readable one
	// rather than the literal last: a counter that stopped being readable at the
	// end of the window still has a truthful value at the last sample it answered.
	overlap, latest := 0, baseline
	for i := baseIdx + 1; i < len(cs.Values); i++ {
		if !cs.Known[i] {
			continue
		}
		overlap++
		latest = cs.Values[i]
	}
	if overlap < minOverlap {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%s had %d readable sample(s) in the window and needs %d", cs.Counter, overlap, minOverlap))
		return
	}

	delta := latest - baseline
	var pct *float64
	if baseline > 0 {
		v := float64(delta) / float64(baseline) * 100
		pct = &v
	}
	if !moved(r, delta, pct) {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%s did not move enough to correlate (%+d %s, needs %d %s or %.0f%%)",
			cs.Counter, delta, r.unit, r.minAbs, r.unit, r.minPct))
		return
	}

	rep.Correlations = append(rep.Correlations, Correlation{
		Counter:    cs.Counter,
		Baseline:   baseline,
		Latest:     latest,
		Delta:      delta,
		DeltaPct:   pct,
		Overlap:    overlap,
		Window:     rep.Window,
		Confidence: confidenceFor(overlap),
		Note:       noteFor(cs.Counter, delta, pct, overlap, rep.Window),
	})
}

// moved applies both floors.
func moved(r rule, delta int64, pct *float64) bool {
	abs := delta
	if abs < 0 {
		abs = -abs
	}
	if abs < r.minAbs {
		return false
	}
	if pct == nil {
		// No baseline to take a percentage of; the absolute floor is the only
		// test available, and it has been cleared.
		return true
	}
	return math.Abs(*pct) >= r.minPct
}

// confidenceFor rates a correlation by its overlap alone.
func confidenceFor(overlap int) Confidence {
	switch {
	case overlap >= highOverlap:
		return ConfidenceHigh
	case overlap >= mediumOverlap:
		return ConfidenceMedium
	}
	return ConfidenceLow
}

// noteFor writes the sentence attached to a correlation.
//
// The wording is load-bearing, not cosmetic. It states the direction, gives the
// numbers back, and says in the same breath what the observation is not; a report
// that let "syscw rose 4000" stand alone would be read as "writes opened the
// descriptors" by everyone who saw it.
func noteFor(name model.CounterName, delta int64, pct *float64, overlap, window int) string {
	verb := "rose"
	if delta < 0 {
		verb = "fell"
	}
	amount := fmt.Sprintf("%+d", delta)
	if pct != nil {
		amount = fmt.Sprintf("%+d (%+.0f%%)", delta, *pct)
	}
	return fmt.Sprintf(
		"correlation only: %s %s by %s across %d of %d samples since the rise began; "+
			"this is co-occurrence inside one window, not evidence of what opened the descriptors",
		name, verb, amount, overlap, window)
}
