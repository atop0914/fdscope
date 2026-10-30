// Package analyze provides the leak verdict.
//
// This file is the one place in fdscope that says "this is a leak". Everything
// before it describes a shape - what a series did - and describes it without
// opinion. The distinction is the whole point of the split: Day 3's watch reports
// `rising`, and a rising series is also what a connection pool warming up looks
// like, what a batch job in flight looks like, and what a directory walk looks
// like. A tool that called all four a leak would be ignored within a week, and
// rightly so - the cost of a false alarm is that the true alarms stop being read.
//
// So the verdict is deliberately hard to reach. Five criteria must all hold, and
// each one excludes a specific shape:
//
//	monotonicity - the peak is at the end of the window. A series that fell was
//	               draining; a series that fell in the middle and recovered was
//	               doing work. Only growth that is still growing is a leak.
//	growth       - the total rise must clear both an absolute floor and a
//	               relative one. A process going 1 -> 5 descriptors is not
//	               leaking, however much 400% sounds like it.
//	rate         - the rise must be sustained, measured in descriptors per
//	               second. "It grew a lot over a long time" is ramp-up; "it grew
//	               steadily" is a leak.
//	baseline     - the warm-up is excluded. Judging from the first sample
//	               convicts every system that starts empty and fills its pools.
//	coverage     - the window must actually cover the growth. If samples were
//	               evicted, the conclusion is downgraded, never asserted.
//
// None of these are individually surprising. The value is that they are combined
// in one place, reported separately (Verdict.Evidence), and tested against
// negative corpus cases that are shaped to fool any one of them on its own.
package analyze

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/atop0914/fdscope/internal/attr"
	"github.com/atop0914/fdscope/internal/correlate"
	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/timeline"
)

// Confidence states how much the verdict deserves to be believed.
//
// It is a separate axis from Leak on purpose. "No leak" from a two-second window
// and "no leak" from a ten-minute window are different claims, and collapsing them
// into one boolean is how a monitoring tool ends up lying in the calm direction -
// the direction nobody checks.
type Confidence string

const (
	// ConfidenceHigh means the window was complete and long enough to judge.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium means the window was complete but short, so a slow leak
	// could still be hiding in it.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow means the evidence is real but partial (samples were
	// evicted), or the series is too short to establish a baseline.
	ConfidenceLow Confidence = "low"
	// ConfidenceNone means no conclusion may be drawn at all.
	ConfidenceNone Confidence = "none"
)

// LeakVerdict is the answer for one series.
type LeakVerdict struct {
	// Fingerprint is the resource judged; "(total)" for the process total.
	Fingerprint string `json:"fingerprint"`
	// Leak is the conclusion. It is only true when every criterion holds.
	Leak bool `json:"leak"`
	// Confidence qualifies how much the conclusion deserves to be trusted.
	Confidence Confidence `json:"confidence"`
	// Reason is a one-line, human-readable explanation of the verdict.
	Reason string `json:"reason"`
	// Projection says how far the limit is: an ETA when the verdict convicted a
	// leak, and otherwise the state of the limit itself. It is always present so
	// that "unlimited" and "could not be read" are visible even on a clean run.
	Projection Projection `json:"projection"`
	// Evidence is the per-criterion breakdown. A verdict without its numbers is
	// an opinion; a reader must be able to see which threshold was crossed and
	// by how much, and a test must be able to assert on it.
	Evidence LeakEvidence `json:"evidence"`
	// Attribution says which class of resource this is. It is nil unless the
	// series was judged a leak: explaining a resource that is not growing would
	// fill the report with rows nobody asked about and bury the ones that matter.
	// The process total never carries one - it is not a resource.
	Attribution *attr.Attribution `json:"attribution,omitempty"`
}

// LeakEvidence records what each criterion measured.
//
// The fields are raw measurements, not booleans, with two exceptions
// (Monotonic, RateSustained) that summarise a property that has no single number.
// Reporting the inputs lets a reader recompute the verdict by hand - which is what
// "explainable" has to mean for a tool used during an incident.
type LeakEvidence struct {
	// WindowSamples is how many samples the judgement rests on, and
	// WindowMillis how much wall-clock time they span.
	WindowSamples int   `json:"window_samples"`
	WindowMillis  int64 `json:"window_millis"`
	// Dropped counts samples evicted before the window. Non-zero downgrades
	// the confidence and is reported next to every verdict.
	Dropped int `json:"dropped,omitempty"`
	// BaselineIndex is the first sample included after the warm-up, and
	// BaselineValue the count there. WarmupSamples says how many leading
	// samples were excluded.
	BaselineIndex int `json:"baseline_index"`
	BaselineValue int `json:"baseline_value"`
	WarmupSamples int `json:"warmup_samples"`
	// Constant reports that the count never changed across the window. It is not a
	// verdict: a constant count is a leak that happened before sampling began or a
	// process that simply needs that many descriptors, and only the process total can
	// tell them apart - see Judge.
	Constant bool `json:"constant,omitempty"`
	// RestValue is the level the process sat at before it grew: the floor the
	// ratio test is taken against.
	RestValue int `json:"rest_value"`
	// RiseStartIndex, RiseSamples and RiseMillis describe the judged window the
	// verdict was computed over, so a reader can re-read exactly those samples.
	RiseStartIndex int   `json:"rise_start_index"`
	RiseSamples    int   `json:"rise_samples"`
	RiseMillis     int64 `json:"rise_millis"`
	// Growth is the rise from the resting level to the highest count in the
	// window, and GrowthRequired the floor it had to clear.
	Growth         int `json:"growth"`
	MeasuredGrowth int `json:"measured_growth"`
	GrowthRequired int `json:"growth_required"`
	// Monotonic reports whether the maximum of the judged window sits at its
	// end. FallbackAfterPeak is how far it fell if it does not.
	Monotonic         bool `json:"monotonic"`
	FallbackAfterPeak int  `json:"fallback_after_peak,omitempty"`
	// RatePerSecond is the average growth rate over the window and
	// RateRequired the minimum that counts as sustained.
	RatePerSecond float64 `json:"rate_per_second"`
	RateRequired  float64 `json:"rate_per_second_required"`
	// RateSustained reports whether the rise is spread over the window rather than
	// delivered as one leap, which is what distinguishes a leak from a fan-out or a
	// warm-up that finished.
	RateSustained bool `json:"rate_sustained"`
	// ActiveGaps and TotalGaps say how many of the window's gaps grew at all. A
	// fan-out grows in one; a leak grows in a large share of them.
	ActiveGaps int `json:"active_gaps"`
	TotalGaps  int `json:"total_gaps"`
	// Limit is the descriptor soft limit the verdict was computed against, and
	// Remaining the headroom at the last sample: the room left before EMFILE. Both
	// zero when no limit was known.
	Limit     int `json:"limit,omitempty"`
	Remaining int `json:"remaining,omitempty"`
}

// LeakOptions are the thresholds the verdict uses.
//
// The zero value is usable and applies the defaults. Every field is configurable
// because the right numbers depend on the process: a service that holds 40
// descriptors and one that holds 40000 cannot share an absolute growth floor, and
// hard-coding either would be wrong for the other.
type LeakOptions struct {
	// MinGrowth is the absolute rise, from the baseline, that a leak must show.
	// It exists so that tiny counts cannot be convicted by proportion: going
	// from 1 to 4 descriptors is a 300% rise and a boring fact.
	MinGrowth int
	// MinGrowthRatio is the relative rise, as a fraction of the baseline, that
	// a leak must show. It exists so that a large process cannot be convicted
	// by a small absolute number that happens to clear MinGrowth.
	MinGrowthRatio float64
	// MinRatePerSecond is how fast the leak must be growing. It exists to keep
	// a slow ramp - a cache that gains one descriptor a minute over an hour -
	// from being called a leak on a window too short to tell it apart from
	// ordinary growth.
	MinRatePerSecond float64
	// Warmup is how much of the head of the series is excluded from the
	// judgement, as a fraction. A pool that fills at startup is the canonical
	// false positive.
	Warmup float64
	// MinWindowMillis is the shortest window that can yield high confidence.
	MinWindowMillis int64
	// MinSamples is the shortest series that can be judged at all.
	MinSamples int
	// Attr is the attribution engine. Nil means the built-in rules; a configured
	// engine adds the caller's own categories on top of them.
	Attr *attr.Engine
	// Limit is the descriptor limit of the process. It is used for the headroom
	// figure and the EMFILE projection, never for the verdict: a leak is a leak
	// whether or not the process is close to EMFILE. The zero value means
	// "unknown", which is not the same as "unlimited".
	Limit model.OpenLimit
}

// DefaultLeakOptions returns the thresholds used when the caller configures none.
//
// The numbers are chosen from the corpus in leak_corpus_test.go, which encodes the
// four shapes that must never be convicted plus the leak that must be. They are
// deliberately conservative: missing a slow leak costs a later investigation,
// while a false alarm costs the tool's credibility.
func DefaultLeakOptions() LeakOptions {
	return LeakOptions{
		MinGrowth:        10,
		MinGrowthRatio:   0.10,
		MinRatePerSecond: 0.05,
		Warmup:           0.2,
		MinWindowMillis:  5000,
		MinSamples:       4,
	}
}

// normalize fills in defaults and rejects impossible values.
//
// A negative threshold is rejected rather than clamped, for the same reason the
// shape thresholds are: it usually means a sign error upstream, and silently
// treating it as positive hides that while making the report look fine.
func (o LeakOptions) normalize() (LeakOptions, error) {
	def := DefaultLeakOptions()
	if o.MinGrowth < 0 {
		return LeakOptions{}, fmt.Errorf("minimum growth must not be negative, got %d", o.MinGrowth)
	}
	if o.MinGrowth == 0 {
		o.MinGrowth = def.MinGrowth
	}
	if o.MinGrowthRatio < 0 {
		return LeakOptions{}, fmt.Errorf("minimum growth ratio must not be negative, got %v", o.MinGrowthRatio)
	}
	if o.MinGrowthRatio == 0 {
		o.MinGrowthRatio = def.MinGrowthRatio
	}
	if o.MinRatePerSecond < 0 {
		return LeakOptions{}, fmt.Errorf("minimum rate must not be negative, got %v", o.MinRatePerSecond)
	}
	if o.MinRatePerSecond == 0 {
		o.MinRatePerSecond = def.MinRatePerSecond
	}
	if o.Warmup < 0 || o.Warmup >= 1 {
		return LeakOptions{}, fmt.Errorf("warmup fraction must be in [0,1), got %v", o.Warmup)
	}
	if o.Warmup == 0 {
		o.Warmup = def.Warmup
	}
	if o.MinWindowMillis < 0 {
		return LeakOptions{}, fmt.Errorf("minimum window must not be negative, got %d", o.MinWindowMillis)
	}
	if o.MinWindowMillis == 0 {
		o.MinWindowMillis = def.MinWindowMillis
	}
	if o.MinSamples < 0 {
		return LeakOptions{}, fmt.Errorf("minimum samples must not be negative, got %d", o.MinSamples)
	}
	if o.MinSamples == 0 {
		o.MinSamples = def.MinSamples
	}
	if o.Limit.Soft < 0 {
		return LeakOptions{}, fmt.Errorf("descriptor limit must not be negative, got %d", o.Limit.Soft)
	}
	if o.Limit.State == model.LimitKnown && o.Limit.Soft == 0 {
		// A known limit of zero is a parse failure that tried to look like a
		// number. Reject it rather than let it turn into "already over".
		return LeakOptions{}, fmt.Errorf("a known descriptor limit must be positive")
	}
	return o, nil
}

// JudgeSeries decides whether one series is leaking.
//
// The criteria are stated as answers to one question each, and every one of them
// excludes a shape that would otherwise be a false alarm:
//
//	monotonic  nothing falls back after the peak - a rise followed by a release is
//	           work being done, or self-healing, and neither is a leak
//	growth     clears both an absolute floor and a relative one, so neither
//	           "1 -> 5 descriptors" nor "a large process grew by a few" convicts
//	rate       keeps pace that a short window can distinguish from ordinary growth
//	continuity the rise is spread over the window rather than delivered as one leap
//	baseline   a warm-up that finished is not growth, because it stopped
//
// The verdict carries the measurement behind every criterion, because a verdict
// without its numbers is an opinion.
func JudgeSeries(s timeline.Series, samplePeriod time.Duration, opts LeakOptions) (LeakVerdict, error) {
	opt, err := opts.normalize()
	if err != nil {
		return LeakVerdict{}, err
	}
	if samplePeriod < 0 {
		return LeakVerdict{}, fmt.Errorf("sample period must not be negative, got %s", samplePeriod)
	}
	// Time comes from the period rather than from a caller-supplied clock: a leak is
	// a claim about time, and the only clock fdscope can honestly use is the one the
	// timeline itself supplies.
	taken := make([]int64, len(s.Counts))
	for i := range taken {
		taken[i] = int64(i) * int64(samplePeriod)
	}

	v := LeakVerdict{Fingerprint: s.Fingerprint, Confidence: ConfidenceNone}
	ev := LeakEvidence{WindowSamples: len(s.Counts)}
	if len(taken) > 1 {
		ev.WindowMillis = (taken[len(taken)-1] - taken[0]) / int64(time.Millisecond)
	}
	// The evidence rows keep their old shape: Limit is the finite soft limit, 0
	// when there is no finite number, and Remaining is the headroom at the last
	// sample. The reason a limit might be 0 lives in the projection, which
	// distinguishes "unlimited" from "could not be read".
	if len(s.Counts) > 0 {
		if left, ok := opt.Limit.Remaining(s.Counts[len(s.Counts)-1]); ok {
			ev.Limit = opt.Limit.Soft
			ev.Remaining = left
		}
	}

	// Too short to judge. This is a refusal, not a "no leak": three points cannot
	// show the difference between a pool warming up and a leak, and answering "not
	// leaking" would be the calm-direction lie.
	if len(s.Counts) < opt.MinSamples {
		v.Reason = fmt.Sprintf("not enough samples to judge (%d, need %d)", len(s.Counts), opt.MinSamples)
		v.Evidence = ev
		proj, projErr := Project(s.Counts, samplePeriod, opt.Limit)
		if projErr != nil {
			return LeakVerdict{}, projErr
		}
		v.Projection = proj.WithoutETA("no verdict: the window is too short to project from")
		return v, nil
	}

	// The warm-up is excluded first. Judging from sample 0 convicts every process
	// that starts empty and fills its pools, which is most of them.
	//
	// The exclusion ends where the *stable prefix* ends, not at a fixed fraction of
	// the series. A fixed fraction assumes the rise is uniformly spread, and a real
	// leak is not: measured against a live process, half of a 30 -> 99 climb happened
	// in the first 20% of the window, so a proportional cut took the baseline at 63
	// and reported the remaining climb as "only across 6 of 23 gaps, had stopped by
	// the end" - a no-leak verdict for an unambiguous leak.
	//
	// Only a *flat* prefix is treated as warm-up. A series that is climbing from its
	// first sample has no warm-up to exclude, and the rise starts at sample 0. The
	// pool that fills and then holds is still excluded, by a different criterion: its
	// rise is concentrated in the prefix and the window ends on a plateau, which
	// sustainedGrowth rejects (see TestStartupFillStillExcluded).
	warm := stablePrefix(s.Counts)
	if warm >= len(s.Counts)-1 {
		warm = len(s.Counts) - 2
	}
	if warm < 0 {
		warm = 0
	}
	// The proportional warm-up is kept as an upper bound. It is not the criterion -
	// the stable prefix is - but a process that churns without ever settling should
	// not hand the ratio floor a baseline from the busiest moment of its life.
	if maxWarm := int(math.Floor(float64(len(s.Counts)) * opt.Warmup)); warm > maxWarm {
		warm = maxWarm
	}
	if warm < 0 {
		warm = 0
	}
	window := s.Counts[warm:]
	rest := restingLevel(window)
	ev.WarmupSamples = warm
	ev.BaselineIndex = warm
	ev.BaselineValue = window[0]
	ev.RestValue = rest

	// Nothing rose: the window is flat or draining, and neither can leak. Reporting
	// "no leak" here is safe precisely because there is no growth to attribute.
	windowMin, windowMax := window[0], window[0]
	for _, c := range window {
		if c < windowMin {
			windowMin = c
		}
		if c > windowMax {
			windowMax = c
		}
	}
	// The guard is against a window that never rises, not against one that ends
	// flat. A process whose descriptors were all opened before sampling began holds a
	// constant count for the whole window - and that is the most common leak shape
	// there is, because a leak is usually discovered after it has already happened.
	// Reporting "no rise" for it is the calm-direction lie: the rise exists, it is
	// just older than the window. Judge reports that as a confirmed leak at low
	// confidence when the series' own first sample was lower (see Judge), and a
	// constant window is the one case where it can be confirmed at all.
	if windowMax <= windowMin && window[0] <= s.Counts[0] {
		// The count held steady for the whole window. Whether that is a leak or a
		// process that simply needs this many descriptors cannot be decided from
		// inside the window, so the verdict is deferred to Judge, which sees the
		// process total at the series' first sample. The marker is Constant here and
		// the zero Growth: a constant window is a fact, not a conclusion.
		ev.Constant = true
		v.Reason = fmt.Sprintf("no rise in the window: held %d descriptors for all %d samples", rest, len(window))
		ev.Monotonic = true
		v.Confidence = confidenceFor(span(window, samplePeriod), opt)
		v.Evidence = ev
		proj, projErr := Project(window, samplePeriod, opt.Limit)
		if projErr != nil {
			return LeakVerdict{}, projErr
		}
		v.Projection = proj.WithoutETA("no rise in the window: nothing to extrapolate")
		return v, nil
	}

	// From here on, every measurement is taken over the judged window and nowhere
	// else. "window" from this point is `judged`.
	//
	// The judged span starts at the window's first sample, not at the first rise.
	// Two cleverer starts were tried and both were worse: "where the series last left
	// its resting level" finds only the final step of a process that repeatedly opens
	// and closes, and "the largest dip-to-peak climb" loses the whole rise when the
	// dip fell inside the warm-up. The warm-up exclusion has already removed what
	// would convict a healthy process for starting up.
	rise := window
	// The peak of the judged window, recomputed: `windowMax` above spans the
	// warm-up-excluded window, which starts at the same sample, so they agree - but
	// they agree by coincidence of this particular slice expression, and the next
	// round to reuse `windowMax` for anything else would silently mix two spans
	// again. One name, one span.
	peak := rise[0]
	for _, c := range rise {
		if c > peak {
			peak = c
		}
	}
	spanSeconds := span(rise, samplePeriod)
	// Growth and its floor are measured over the *judged* window - from its first
	// sample to its highest. Every value in this block must come from the same span.
	//
	// This is where the last bug of the round lived: windowMax was the maximum of
	// the whole window while the baseline was the first sample of the judged part,
	// so the reported growth mixed two spans and came out larger than the rise the
	// window actually showed - a series that climbed 7.8% inside the judged window
	// claimed to have climbed 10%, and then failed its own 10% floor. The floor was
	// right; the measurement was stitched together from two different questions.
	growth := peak - window[0]

	// The ratio floor is a fraction of the level the process was at *before* the
	// window opened, not of anything inside it. Several baselines were tried and
	// every one of them made a plain 10% rise fail its own floor - the window's first
	// sample, the window's minimum, and the sample before the window - and each of them
	// was wrong in a different direction. The one that is both measurable and meaningful
	// is the window's first sample: it is where the judged span starts, so a fraction
	// of it describes the same span the growth does.
	// scale is the peak minus the growth, which is the level the rise started from -
	// stated as arithmetic rather than as a sample index so it cannot drift from the
	// growth it is compared against. Using a sample here (the window's first one) was
	// the bug: it described a span the growth did not.
	scale := window[0]
	if scale < 0 {
		scale = 0
	}
	ev.RiseStartIndex = warm
	ev.RiseSamples = len(rise)
	ev.RiseMillis = int64(spanSeconds * 1000)
	ev.Growth = growth
	ev.MeasuredGrowth = growth
	ev.GrowthRequired = opt.MinGrowth
	if byRatio := int(math.Ceil(float64(scale) * opt.MinGrowthRatio)); byRatio > ev.GrowthRequired {
		ev.GrowthRequired = byRatio
	}

	// The projection is computed from the judged window, once, and carried by
	// every verdict that follows. It is set before the criteria below so that a
	// "no leak" verdict still reports the limit state - a process that is not
	// leaking can still be unlimited, or still be at its limit.
	proj, projErr := Project(rise, samplePeriod, opt.Limit)
	if projErr != nil {
		return LeakVerdict{}, projErr
	}
	v.Projection = proj

	// Monotonicity: nothing may come back down after the peak. The walk starts just
	// after the first sample at the maximum, so a series that touched its peak for a
	// single sample and closed everything right after is still seen to have fallen -
	// starting at the peak itself reports a fall of zero, which is exactly what the
	// end of a batch job looks like.
	postLow := rise[indexOfFirst(rise, windowMax)+1:]
	if len(postLow) > 0 {
		lowest := postLow[0]
		for _, c := range postLow {
			if c < lowest {
				lowest = c
			}
		}
		ev.FallbackAfterPeak = peak - lowest
	}
	ev.Monotonic = ev.FallbackAfterPeak == 0
	if !ev.Monotonic {
		v.Confidence = confidenceFor(spanSeconds, opt)
		v.Reason = fmt.Sprintf("fell back %d from its peak of %d: a resource released is work done, not a leak",
			ev.FallbackAfterPeak, peak)
		v.Evidence = ev
		v.Projection = proj.WithoutETA("no leak: the count fell back, so there is nothing to extrapolate")
		return v, nil
	}

	// Growth floors. Both must clear, and they are reported separately so a reader
	// can see which one bound the verdict: a small rise in a large process fails the
	// ratio floor and a large rise in a tiny one fails the absolute floor, and "growth
	// too small" is a misleading reason for either.
	growthOK := growth >= opt.MinGrowth && float64(growth) >= float64(scale)*opt.MinGrowthRatio

	ev.RateRequired = opt.MinRatePerSecond
	if spanSeconds > 0 {
		ev.RatePerSecond = float64(growth) / spanSeconds
	}
	rateOK := ev.RatePerSecond >= opt.MinRatePerSecond

	// Continuity: the growth must be spread over the window and still going when the
	// window ends. See sustainedGrowth for why this is coverage rather than a test of
	// step sizes - every step-size formulation rejected a real leak shape.
	ev.RateSustained, ev.ActiveGaps, ev.TotalGaps = sustainedGrowth(rise)

	v.Confidence = confidenceFor(spanSeconds, opt)
	if !growthOK || !rateOK || !ev.RateSustained {
		v.Reason = noLeakReason(ev, growthOK, rateOK)
		v.Evidence = ev
		v.Projection = proj.WithoutETA("no leak: nothing to extrapolate at this rate")
		return v, nil
	}

	v.Leak = true
	v.Reason = fmt.Sprintf("grew %d descriptors (%.0f%%) to %d over %.1fs and did not fall back",
		growth, percentOf(growth, rest), peak, spanSeconds)
	// The distance to EMFILE is appended from the same projection the JSON
	// carries, so the sentence and the numbers cannot drift apart - and so that
	// an unreadable limit is stated as unreadable instead of being silently
	// omitted, which reads as "no risk".
	v.Reason += "; " + proj.Describe()
	v.Evidence = ev
	return v, nil
}

// stablePrefix returns how many leading samples belong to a settled prefix: the
// samples before the count first moves away from the level it started at.
//
// "Moves away" is measured against the flat tolerance the shape report already uses,
// so the two layers agree about what counts as movement. Jitter of one or two
// descriptors at the start of a series is not a warm-up ending - it is a process
// sitting still - and treating it as the end of the warm-up would hand the judgement
// a baseline from the busiest moment of a process that had not started working yet.
//
// The result is 0 when the series climbs from its first sample: there is no flat
// prefix to exclude, so nothing is excluded. That is the case the proportional
// warm-up got wrong.
func stablePrefix(counts []int) int {
	if len(counts) == 0 {
		return 0
	}
	base := counts[0]
	for i, c := range counts {
		if c > base+DefaultFlatTolerance || c < base-DefaultFlatTolerance {
			// The prefix ends at the last sample that was still at the starting
			// level, so the sample where the movement first appears is the
			// baseline - it is where the climb begins.
			return i
		}
	}
	return len(counts)
}

// span is the wall-clock duration the series covers, in seconds.
func span(vals []int, samplePeriod time.Duration) float64 {
	if len(vals) < 2 || samplePeriod <= 0 {
		return 0
	}
	return float64(samplePeriod) / float64(time.Second) * float64(len(vals)-1)
}

// confidenceFor rates a window by its judged duration: a complete window shorter
// than the configured minimum cannot see a slow leak, so it may report one but may
// not claim the observation is representative.
func confidenceFor(spanSeconds float64, opt LeakOptions) Confidence {
	if int64(spanSeconds*1000) < opt.MinWindowMillis {
		return ConfidenceMedium
	}
	return ConfidenceHigh
}

// restingLevel is the descriptor count the process sat at before it grew: the
// lowest value in the window.
//
// The lowest value, not the first sample. The window opens after the warm-up
// exclusion, which usually lands mid-rise, so the first sample is already a step or
// two up - and a floor measured from it made a plain 10% rise fail its own floor by
// exactly one step. That mistake was invisible in the reason string, which blamed
// the threshold rather than the baseline.
//
// A falling series is caught before this matters: with no rise in the window the
// verdict returns early, so the minimum of a window that is draining is never used
// as a growth floor.
func restingLevel(vals []int) int {
	low := vals[0]
	for _, c := range vals {
		if c < low {
			low = c
		}
	}
	return low
}

// indexOfFirst returns the index of the first sample equal to v, or -1.
func indexOfFirst(vals []int, v int) int {
	for i, c := range vals {
		if c == v {
			return i
		}
	}
	return -1
}

// noLeakReason names the criterion that failed, because "not a leak" without a
// reason teaches the reader nothing and hides a judgement bug behind a
// comfortable answer.
func noLeakReason(ev LeakEvidence, growthOK, rateOK bool) string {
	switch {
	case !ev.Monotonic:
		return fmt.Sprintf("fell back %d from its peak: a resource released is work done, not a leak", ev.FallbackAfterPeak)
	case !growthOK:
		return fmt.Sprintf("grew %d, below the %d needed to distinguish growth from noise", ev.Growth, ev.GrowthRequired)
	case !rateOK:
		return fmt.Sprintf("grew %.3f/s, below the %.3f/s a leak must sustain", ev.RatePerSecond, ev.RateRequired)
	case !ev.RateSustained:
		return fmt.Sprintf("grew %d but only across %d of %d gaps and had stopped by the end of the window: "+
			"a warm-up or a single step, not a climb", ev.Growth, ev.ActiveGaps, ev.TotalGaps)
	}
	return "not a leak"
}

// minActiveGapFraction is the share of a window's gaps that must grow for the
// growth to be continuous rather than a single event.
//
// One third. A burst that opens everything in one or two gaps has a handful of
// growing gaps out of dozens; a stepwise leak - a worker pool that opens five
// descriptors every step - grows in every other gap once the sampling interval
// halves the step rate. Lower than a third, "two gaps out of twenty" starts to pass
// and a fixed fan-out is convicted.
const minActiveGapFraction = 3

// maxPlateauGapFraction is how much of the window's tail may be flat before the rise
// is read as having stopped, expressed as a fraction of the gaps.
//
// A quarter. A leak whose steps are longer than the sampling period has zero-width
// gaps scattered throughout - observed one had fourteen of them in a row separated by
// three-descriptor steps - so testing only the final gap is a coin flip on where the
// sampler happened to stop. A fill that finished, by contrast, is flat for everything
// after its last step, which over any window worth judging is far more than a
// quarter of it.
const maxPlateauGapFraction = 4

// trailingPlateau returns how many of the series' last gaps failed to grow.
func trailingPlateau(vals []int) int {
	n := 0
	for i := len(vals) - 1; i > 0; i-- {
		if vals[i] > vals[i-1] {
			break
		}
		n++
	}
	return n
}

// sustainedGrowth reports whether a rise keeps climbing rather than happening once,
// returning how many gaps grew out of how many.
//
// Deliberately not a test of step *sizes*. That was tried three times and each
// version rejected a shape it had no business rejecting:
//
//   - "every gap must grow" rejects any leak sampled finely, because a gap that
//     rounds down to zero is not growth
//   - "each gap is at least half the average" fails for the same reason, the average
//     being diluted across gaps that recorded nothing
//   - "steps must be of similar size" rejects a stepwise leak whose steps straddle
//     the sampling interval, which is what a real worker pool looks like: five
//     descriptors per step, one step every 250ms, sampled every 180ms
//
// What survives is coverage plus a tail that has not flattened: growth spread over a
// real share of the window, and no plateau at the end. A warm-up that finished fails
// the second test, a fan-out fails the first, and both kinds of leak pass.
//
// The tail test looks at a run of gaps rather than at the final one. Testing only the
// last gap was the fourth version of this mistake: a leak stepping every 200ms
// sampled every 120ms produces an alternating 3, 0, 3, 0 series, and whether the last
// gap is a zero is decided by phase rather than by the process. One live run was
// reported as "had stopped by the end of the window" for a series that climbed 13 ->
// 64 without ever falling back.
func sustainedGrowth(vals []int) (ok bool, active, gaps int) {
	if len(vals) < 2 {
		return false, 0, 0
	}
	gaps = len(vals) - 1
	if vals[len(vals)-1] <= vals[0] {
		return false, 0, gaps
	}
	for i := 1; i < len(vals); i++ {
		if vals[i] > vals[i-1] {
			active++
		}
	}
	// The plateau allowance is at least one gap, so that a short window cannot be
	// convicted or cleared by an integer division rounding to zero.
	allowed := gaps / maxPlateauGapFraction
	if allowed < 1 {
		allowed = 1
	}
	switch {
	case active < 2:
		// One leap and nothing else: a fixed fan-out.
		return false, active, gaps
	case active*minActiveGapFraction < gaps:
		// Growth concentrated in a handful of gaps is a step, not a climb.
		return false, active, gaps
	case trailingPlateau(vals) > allowed:
		// The window ends on a plateau long enough to be a finished fill rather than
		// a gap that happened to fall between two steps.
		return false, active, gaps
	}
	return true, active, gaps
}

// percentOf is growth as a percentage of base, guarding the zero baseline that a
// fingerprint held once and grown to ten would otherwise produce.
func percentOf(growth, base int) float64 {
	if base <= 0 {
		return 100
	}
	return float64(growth) / float64(base) * 100
}

// LeakReport is the verdict for a whole timeline.
type LeakReport struct {
	// PID is the judged process, Samples and Dropped the window it was judged
	// on, and Incomplete whether anything was evicted.
	PID          int   `json:"pid"`
	Samples      int   `json:"samples"`
	Dropped      int   `json:"dropped"`
	Incomplete   bool  `json:"incomplete"`
	WindowMillis int64 `json:"window_millis"`
	// Leaking is true when any series leaked. It is the summary a CI job
	// branches on, and it is derived from the verdicts rather than set
	// independently so the header cannot disagree with the table.
	Leaking bool `json:"leaking"`
	// Total is the verdict on the process total; Series holds one per
	// fingerprint that could be blamed.
	Total  LeakVerdict   `json:"total"`
	Series []LeakVerdict `json:"series"`
	// Attribution is the breakdown of the leak by resource class, largest share
	// first. It is empty when nothing leaked: there is no growth to divide up.
	//
	// The rows are aggregated because twenty fingerprints is not an answer to
	// "what is leaking", while five categories with shares is. The per-series
	// verdicts keep their own attribution for the reader who wants the
	// individual resources.
	Attribution []attr.CategoryAttribution `json:"attribution,omitempty"`
	// Correlations is the L2 block: the process-level counters that moved in the
	// same window as the onset of the growth. It is empty when nothing leaked -
	// there is no onset to correlate against - and also when nothing moved, in
	// which case CorrelationNotes says which counters were ruled out.
	Correlations []correlate.Correlation `json:"correlations,omitempty"`
	// CorrelationAnchor names the series whose onset the correlations were taken
	// against: "(total)" when the process total leaked, otherwise the largest
	// leaking resource. It is a separate field because a correlation is
	// meaningless without knowing which growth it was measured against, and
	// leaving the reader to guess would let two runs be compared as if they
	// described the same event.
	CorrelationAnchor string `json:"correlation_anchor,omitempty"`
	// CorrelationOnset is the sample index where the anchor's count left its
	// settled level - the sample the counters were compared against. It is omitted
	// when it is zero, which is the case the note explains: the rise began at the
	// first sample and there was no baseline.
	CorrelationOnset int `json:"correlation_onset,omitempty"`
	// CorrelationNotes explains the counters that produced no correlation, and
	// the windows that could not support one. This is not noise: "no counter moved
	// with the onset" is a finding, and it is the finding that rules out the
	// obvious explanation.
	CorrelationNotes []string `json:"correlation_notes,omitempty"`
}

// Leaks returns the series verdicts that found a leak, largest growth first.
func (r LeakReport) Leaks() []LeakVerdict {
	out := make([]LeakVerdict, 0, len(r.Series))
	for _, v := range r.Series {
		if v.Leak {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Evidence.Growth != out[j].Evidence.Growth {
			return out[i].Evidence.Growth > out[j].Evidence.Growth
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// Judge decides whether a timeline shows a leak.
//
// The confidence rules here are about the window, not the numbers:
//
//   - Any evicted sample means the growth may have started before the window
//     begins, so nothing may be reported as high confidence. The verdict is still
//     reported - the evidence is real - but it cannot be asserted.
//   - A series that leaks on a short window is downgraded to medium, which says
//     "this is happening" without claiming it will continue.
func Judge(tl *timeline.Timeline, opts LeakOptions) (LeakReport, error) {
	if tl == nil {
		return LeakReport{}, fmt.Errorf("no timeline to judge")
	}
	opt, err := opts.normalize()
	if err != nil {
		return LeakReport{}, err
	}
	if tl.Len() == 0 {
		return LeakReport{}, fmt.Errorf("no samples were collected for pid %d", tl.PID())
	}

	samples := tl.Samples()
	taken := make([]int64, len(samples))
	for i, s := range samples {
		taken[i] = s.Taken
	}
	period := samplingPeriod(taken)

	// The limit comes from the timeline's own observations, not from the caller: a
	// caller that forgot to pass it would silently lose the whole "constant count
	// against a nearly full limit" rule, which is the only way a leak discovered after
	// the fact can be confirmed at all.
	if opt.Limit.Unknown() {
		opt.Limit = tl.Limit()
	}

	rep := LeakReport{
		PID:          tl.PID(),
		Samples:      tl.Len(),
		Dropped:      tl.Dropped(),
		Incomplete:   tl.Incomplete(),
		WindowMillis: (taken[len(taken)-1] - taken[0]) / int64(time.Millisecond),
		Series:       make([]LeakVerdict, 0, len(samples)),
	}

	total, err := JudgeSeries(tl.TotalSeries(), period, opt)
	if err != nil {
		return LeakReport{}, err
	}
	total.Fingerprint = "(total)"
	rep.Total = total

	for _, fp := range tl.Fingerprints() {
		v, judgeErr := JudgeSeries(tl.FingerprintSeries(fp), period, opt)
		if judgeErr != nil {
			return LeakReport{}, judgeErr
		}
		rep.Series = append(rep.Series, v)
	}
	sort.Slice(rep.Series, func(i, j int) bool {
		if rep.Series[i].Evidence.Growth != rep.Series[j].Evidence.Growth {
			return rep.Series[i].Evidence.Growth > rep.Series[j].Evidence.Growth
		}
		return rep.Series[i].Fingerprint < rep.Series[j].Fingerprint
	})

	// Eviction is a property of the window, so it downgrades every verdict in
	// it. Applying it once here rather than inside JudgeSeries keeps the rule
	// from being forgotten at one call site and applied at another.
	if rep.Incomplete {
		rep.Total = downgrade(rep.Total)
		for i := range rep.Series {
			rep.Series[i] = downgrade(rep.Series[i])
		}
	}

	// A window that held a constant, elevated count is the shape of a leak that was
	// discovered after it happened: every descriptor was opened before sampling began,
	// so the series shows no growth and the verdict above says "no rise". The rise is
	// real - the process total sits above the descriptors it needs to run - but the
	// only evidence is the level, not the trend.
	//
	// That makes it a *weak* claim, and it is reported as one: confidence low, and the
	// reason says explicitly that the growth predates the window. Saying nothing would
	// be the calm-direction lie this project keeps finding in its own assumptions;
	// saying it loudly would be the false alarm that kills the tool. Low confidence is
	// the honest third answer.
	//
	// It is only claimed when the series' own first recorded sample was lower than the
	// level held for the whole window. Other descriptors in the same process rose over
	// the same period, which is what rules out "this process simply needs this many".
	//
	// The comparison is between the process total at the first and last *retained*
	// samples, and the threshold is the absolute floor alone: the ratio floor is a
	// fraction of a baseline that, inside a constant window, does not exist. A single
	// window of a process that is already leaking has no rise in it at all - the
	// descriptors were all opened before the first sample - and demanding a rise there
	// would mean never convicting the most common incident shape.
	if rep.Samples >= 2 && !rep.Total.Leak && rep.Total.Evidence.Constant {
		first := samples[0].Total
		last := samples[len(samples)-1].Total
		//
		// The evidence that this is a leak rather than a process that needs that many
		// descriptors is the process's own limit: a process sitting at a large constant
		// count with most of its limit consumed has leaked. A process at 5% of its limit
		// has not, and saying so would convict every worker pool with a fixed size.
		//
		// This is a weaker inference than watching the rise happen, which is why the
		// verdict is reported at low confidence and says so.
		grew := last > first && last-first >= opt.MinGrowth
		limit := rep.Total.Evidence.Limit
		nearLimit := limit > 0 && last > 0 && float64(last) >= float64(limit)*0.5
		if grew || nearLimit {
			var why string
			if grew {
				why = fmt.Sprintf("held %d descriptors for the whole window, %d more than when sampling began", last, last-first)
			} else {
				why = fmt.Sprintf("held %d descriptors for the whole window against a limit of %d (%d%% used): "+
					"a constant count this large is a leak that filled the process before sampling began",
					last, limit, (last*100)/limit)
			}
			// The projection survives the rewrite: the limit state it reports is
			// a fact about the process, not about which criterion convicted it.
			// The ETA is not carried, because a window with no rise in it has no
			// rate to extrapolate - the rise is older than the observation.
			proj := rep.Total.Projection
			proj.Note = "the growth predates the window: no rate to project from"
			rep.Total = LeakVerdict{
				Fingerprint: "(total)",
				Leak:        true,
				Confidence:  ConfidenceLow,
				Reason:      why,
				Evidence:    rep.Total.Evidence,
				Projection:  proj,
			}
		}
	}

	rep.Leaking = rep.Total.Leak || len(rep.Leaks()) > 0
	attachAttribution(&rep, tl, opt.Attr)
	// Correlations are attached last: they need rep.Leaking, which is only known
	// once the constant-window rewrite above has run and the per-series verdicts
	// are final.
	attachCorrelation(&rep, tl)
	return rep, nil
}

// attachAttribution labels the leaked series and partitions the growth by category.
//
// Two different questions, answered separately on purpose:
//
//	per series   "what class is this resource?" - only for the series judged a
//	             leak. A series that did not leak has no explanation to give, and
//	             labelling it would fill the report with rows nobody asked about.
//	breakdown    "where did the descriptors go?" - over every series whose count
//	             rose during the window, weighted by how much it rose, reported
//	             only when the process was judged to be leaking at all.
//
// The breakdown deliberately does not require each series to clear the leak
// floors. The most common real shape is a hundred distinct paths gaining one
// descriptor each: the process total leaks, every series is a pulse of one, and
// "which series leaked" has no answer - while the question the operator asked,
// "what kind of resource is growing", has a precise one. Requiring per-series
// conviction would report nothing for exactly that shape.
//
// The process total is never attributed: it is the sum of the series, not a
// resource, and naming its class would be inventing a category for an arithmetic
// artefact.
//
// Coverage therefore partitions growth, not blame. A pool that filled legitimately
// inside a leaking process still owns its share, and the per-series verdicts above
// are what say which individual resources actually leaked.
func attachAttribution(rep *LeakReport, tl *timeline.Timeline, engine *attr.Engine) {
	if engine == nil {
		engine = attr.Default()
	}
	for i := range rep.Series {
		if !rep.Series[i].Leak {
			continue
		}
		a := engine.Attribute(rep.Series[i].Fingerprint)
		rep.Series[i].Attribution = &a
	}
	if !rep.Leaking || tl == nil {
		return
	}
	items := make([]attr.Item, 0, len(rep.Series))
	for _, fp := range tl.Fingerprints() {
		counts := tl.FingerprintSeries(fp).Counts
		if len(counts) < 2 {
			continue
		}
		// Net rise over the retained window. It is the same quantity the process
		// total's own rise is the sum of, so the shares add up to the growth a
		// reader can see in the totals line rather than to a second, private
		// definition of growth.
		if rise := counts[len(counts)-1] - counts[0]; rise > 0 {
			items = append(items, attr.Item{Fingerprint: fp, Growth: rise})
		}
	}
	rep.Attribution = attr.Summarize(engine, items)
}

// samplingPeriod is the mean interval between consecutive samples.
//
// The mean rather than the nominal interval: real sampling drifts when a snapshot
// takes longer than the requested spacing, and the durations the timeline recorded
// are the only measurement of what actually happened. One sample has no interval to
// measure and yields zero; a verdict on one sample is refused before the period
// matters.
func samplingPeriod(taken []int64) time.Duration {
	if len(taken) < 2 {
		return 0
	}
	return time.Duration((taken[len(taken)-1] - taken[0]) / int64(len(taken)-1))
}

// attachCorrelation fills in the L2 block: which process-level counters moved in
// the window that opened with the growth.
//
// The anchor is chosen before the counters are compared, and it is chosen the way
// an operator would choose it: the process total when the total leaked, otherwise
// the largest leaking resource. Two runs are only comparable if it is clear which
// growth the counters were measured against, which is why the anchor travels with
// the block instead of being implied by the surrounding text.
//
// The onset is stablePrefix of the anchor's own series - the same function, with
// the same flat tolerance, that decides where the leak judgement's baseline sits.
// It is deliberately *not* the clamped warm-up the verdict uses: that clamp is a
// threshold decision about which baseline a ratio floor should be measured from,
// while "when did the count leave its settled level" is a fact about the series.
// Using one function for both keeps them from disagreeing about what movement is.
//
// Nothing is attached for a run that did not leak. A correlation answers "what was
// happening when it started", and asking it of a clean process would produce a
// section full of counters that move for their own reasons - which is precisely the
// noise that teaches a reader to skip the section.
func attachCorrelation(rep *LeakReport, tl *timeline.Timeline) {
	if tl == nil || tl.Len() < 2 || !rep.Leaking {
		return
	}
	anchor, counts := "(total)", tl.TotalSeries().Counts
	if !rep.Total.Leak {
		leaks := rep.Leaks()
		if len(leaks) == 0 {
			// Leaking with no leaking series and no leaking total is not a state the
			// judgement can produce; refusing to correlate is the safe reading of it.
			return
		}
		anchor, counts = leaks[0].Fingerprint, tl.FingerprintSeries(leaks[0].Fingerprint).Counts
	}

	onset := stablePrefix(counts)
	cr := correlate.Compare(tl.CounterSeries(), tl.Len(), onset)
	rep.CorrelationAnchor = anchor
	rep.CorrelationOnset = onset
	rep.Correlations = cr.Correlations
	rep.CorrelationNotes = cr.Notes
}

// downgrade caps a verdict's confidence at low, used when samples were evicted.
// The projection is capped too: its rate was fitted to a window whose beginning
// is unknown, and an ETA quoted from a window that may have started mid-leak is
// the same overstated claim the verdict just refused to make.
func downgrade(v LeakVerdict) LeakVerdict {
	switch v.Confidence {
	case ConfidenceHigh, ConfidenceMedium:
		v.Confidence = ConfidenceLow
	}
	switch v.Projection.Confidence {
	case ConfidenceHigh, ConfidenceMedium:
		v.Projection.Confidence = ConfidenceLow
	}
	return v
}
