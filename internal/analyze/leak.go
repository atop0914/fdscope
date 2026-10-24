// Package analyze: the leak verdict.
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
	// Evidence is the per-criterion breakdown. A verdict without its numbers is
	// an opinion; a reader must be able to see which threshold was crossed and
	// by how much, and a test must be able to assert on it.
	Evidence LeakEvidence `json:"evidence"`
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
	// Growth is the rise from the baseline: Last - Baseline, and
	// GrowthRequired the floor it had to clear.
	Growth         int `json:"growth"`
	GrowthRequired int `json:"growth_required"`
	// Monotonic reports whether the maximum of the judged window sits at its
	// end. FallbackAfterPeak is how far it fell if it does not.
	Monotonic         bool `json:"monotonic"`
	FallbackAfterPeak int  `json:"fallback_after_peak,omitempty"`
	// RatePerSecond is the average growth rate over the window and
	// RateRequired the minimum that counts as sustained.
	RatePerSecond float64 `json:"rate_per_second"`
	RateRequired  float64 `json:"rate_per_second_required"`
	// RateSustained reports whether each gap between consecutive samples grew
	// on average, which is what distinguishes a steady climb from one cliff.
	RateSustained bool `json:"rate_sustained"`
	// Remaining is the descriptor headroom at the last sample, when a limit is
	// known: the room left before EMFILE. Zero means unknown.
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
	// Limit is the descriptor limit of the process, when known. It is used only
	// for the headroom figure, never for the verdict: a leak is a leak whether
	// or not the process is close to EMFILE.
	Limit int
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
	if o.Limit < 0 {
		return LeakOptions{}, fmt.Errorf("descriptor limit must not be negative, got %d", o.Limit)
	}
	return o, nil
}

// JudgeSeries decides whether one series is leaking.
//
// The series' own counts drive every criterion, and the timeline supplies the
// timestamps: a leak is a claim about time as well as magnitude, and judging
// counts alone would report the same verdict for a series sampled once a second
// and one sampled once an hour.
func JudgeSeries(s timeline.Series, taken []int64, opts LeakOptions) (LeakVerdict, error) {
	opt, err := opts.normalize()
	if err != nil {
		return LeakVerdict{}, err
	}
	if len(s.Counts) != len(taken) {
		return LeakVerdict{}, fmt.Errorf("series %q has %d counts but %d timestamps; a series cannot be judged against a clock it was not sampled with",
			s.Fingerprint, len(s.Counts), len(taken))
	}

	v := LeakVerdict{Fingerprint: s.Fingerprint, Confidence: ConfidenceNone}
	ev := LeakEvidence{WindowSamples: len(s.Counts)}
	span := int64(0)
	if len(taken) > 1 {
		span = (taken[len(taken)-1] - taken[0]) / int64(time.Millisecond)
	}
	ev.WindowMillis = span
	if opt.Limit > 0 && len(s.Counts) > 0 {
		ev.Remaining = opt.Limit - s.Counts[len(s.Counts)-1]
	}

	// Too short to judge. This is a refusal, not a "no leak": a three-point
	// series cannot show the difference between a pool warming up and a leak,
	// and answering "not leaking" would be the calm-direction lie.
	if len(s.Counts) < opt.MinSamples {
		v.Reason = fmt.Sprintf("not enough samples to judge (%d, need %d)", len(s.Counts), opt.MinSamples)
		v.Evidence = ev
		return v, nil
	}

	// The warm-up is excluded before anything else is measured. Judging from
	// sample 0 convicts every process that starts empty and fills its pools -
	// which is most of them, and would make the tool useless on the first
	// minute of every deployment.
	warm := int(math.Floor(float64(len(s.Counts)) * opt.Warmup))
	if warm >= len(s.Counts)-1 {
		warm = len(s.Counts) - 2
	}
	if warm < 0 {
		warm = 0
	}
	judged := s.Counts[warm:]
	judgedTaken := taken[warm:]
	ev.WarmupSamples = warm
	ev.BaselineIndex = warm
	ev.BaselineValue = judged[0]
	ev.WindowSamples = len(judged)

	// Rate is computed over the judged window, not the whole series: time spent
	// warming up would otherwise dilute the rate and hide a real leak.
	judgedSpan := (judgedTaken[len(judgedTaken)-1] - judgedTaken[0]) / int64(time.Millisecond)
	ev.WindowMillis = judgedSpan
	growth := judged[len(judged)-1] - judged[0]
	ev.Growth = growth

	if growth < 0 {
		// A series that ended below its baseline is releasing descriptors. No
		// other criterion can rescue it, and saying so plainly is better than
		// reporting four failed thresholds.
		v.Reason = fmt.Sprintf("descriptors were released: %d -> %d after warm-up", judged[0], judged[len(judged)-1])
		v.Evidence = ev
		return v, nil
	}

	// Monotonicity. The maximum must be the last judged sample. Two shapes are
	// excluded here, and they are different problems: a series that peaked in
	// the middle and fell back is doing work (a batch job), and one that peaked
	// in the middle and recovered is self-healing. Neither is leaking.
	peakIdx, peak := 0, judged[0]
	for i, c := range judged {
		if c > peak {
			peak, peakIdx = c, i
		}
	}
	ev.Monotonic = peakIdx == len(judged)-1
	if !ev.Monotonic {
		// Report the deepest fall after the peak, not the gap from the peak
		// to the end: the deepest fall is what proves the resource was really
		// released, and the end value can be misleading if it climbed back.
		lowest := judged[peakIdx]
		for _, c := range judged[peakIdx+1:] {
			if c < lowest {
				lowest = c
			}
		}
		ev.FallbackAfterPeak = peak - lowest
	}

	// Growth floors. Both must be cleared, and they are reported separately so a
	// reader can see which one was the binding constraint.
	ev.GrowthRequired = opt.MinGrowth
	byRatio := int(math.Ceil(float64(judged[0]) * opt.MinGrowthRatio))
	if byRatio > ev.GrowthRequired {
		ev.GrowthRequired = byRatio
	}
	growthOK := growth >= ev.GrowthRequired

	// Rate. The average rate answers "how fast", the sustained check answers
	// "does the growth keep happening". A single cliff - 100 descriptors opened
	// in one gap and then flat - has a high average rate but is not sustained,
	// and is much more likely to be a fixed fan-out than a leak.
	ev.RateRequired = opt.MinRatePerSecond
	if judgedSpan > 0 {
		ev.RatePerSecond = float64(growth) / (float64(judgedSpan) / 1000)
	}
	rateOK := ev.RatePerSecond >= opt.MinRatePerSecond
	ev.RateSustained = sustainedGrowth(judged)

	confidence := ConfidenceHigh
	if span < opt.MinWindowMillis {
		confidence = ConfidenceMedium
	}

	if !ev.Monotonic || !growthOK || !rateOK || !ev.RateSustained {
		v.Confidence = confidence
		v.Reason = noLeakReason(ev, growthOK, rateOK)
		v.Evidence = ev
		return v, nil
	}

	v.Leak = true
	v.Confidence = confidence
	v.Reason = fmt.Sprintf("grew %d descriptors (%.0f%%) over %.1fs and did not fall back; limit crossed at %.0fs if the rate holds",
		growth, percentOf(growth, judged[0]), float64(judgedSpan)/1000, timeToLimit(s, opt))
	v.Evidence = ev
	return v, nil
}

// noLeakReason names the criterion that failed, because "not a leak" without a
// reason teaches the reader nothing and hides a judgement bug behind a
// comfortable answer.
func noLeakReason(ev LeakEvidence, growthOK, rateOK bool) string {
	switch {
	case !ev.Monotonic:
		return fmt.Sprintf("fell back %d after its peak: a resource released is work done, not a leak", ev.FallbackAfterPeak)
	case !growthOK:
		return fmt.Sprintf("grew %d, below the %d needed to distinguish growth from noise", ev.Growth, ev.GrowthRequired)
	case !rateOK:
		return fmt.Sprintf("grew %.3f/s, below the %.3f/s a leak must sustain", ev.RatePerSecond, ev.RateRequired)
	case !ev.RateSustained:
		return fmt.Sprintf("grew %d in one step rather than steadily: a fixed fan-out, not a leak", ev.Growth)
	}
	return "not a leak"
}

// sustainedGrowth reports whether the growth is spread over the window rather
// than concentrated in one leap.
//
// The test is that the average per-gap increase is positive: a series that gains
// 100 descriptors in one gap and nothing afterwards averages 100/n per gap, which
// stays positive - so the average alone cannot separate them. What does separate
// them is how many gaps actually grew: a fan-out grows in one gap out of many,
// while a leak grows in most of them. At least half the gaps must show growth.
func sustainedGrowth(vals []int) bool {
	if len(vals) < 2 {
		return false
	}
	grew := 0
	for i := 1; i < len(vals); i++ {
		if vals[i] > vals[i-1] {
			grew++
		}
	}
	gaps := len(vals) - 1
	return grew*2 > gaps
}

// percentOf is growth as a percentage of base, guarding the zero baseline that a
// fingerprint held once and grown to ten would otherwise produce.
func percentOf(growth, base int) float64 {
	if base <= 0 {
		return 100
	}
	return float64(growth) / float64(base) * 100
}

// timeToLimit estimates how long until the descriptor limit is reached if the
// observed rate holds. It returns 0 when no limit or no rate is known.
//
// This figure is a projection, not a prediction, and the caller must label it as
// such: the rate is an average over a short window, and the only honest claim is
// "at this rate, not at this date".
func timeToLimit(s timeline.Series, opt LeakOptions) float64 {
	if opt.Limit <= 0 || len(s.Counts) == 0 {
		return 0
	}
	remaining := opt.Limit - s.Counts[len(s.Counts)-1]
	if remaining <= 0 {
		return 0
	}
	growth := s.Counts[len(s.Counts)-1] - s.Counts[0]
	span := len(s.Counts) - 1
	if growth <= 0 || span <= 0 {
		return 0
	}
	ratePerSample := float64(growth) / float64(span)
	if ratePerSample <= 0 {
		return 0
	}
	return float64(remaining) / ratePerSample
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

	rep := LeakReport{
		PID:          tl.PID(),
		Samples:      tl.Len(),
		Dropped:      tl.Dropped(),
		Incomplete:   tl.Incomplete(),
		WindowMillis: (taken[len(taken)-1] - taken[0]) / int64(time.Millisecond),
		Series:       make([]LeakVerdict, 0, len(samples)),
	}

	total, err := JudgeSeries(tl.TotalSeries(), taken, opt)
	if err != nil {
		return LeakReport{}, err
	}
	total.Fingerprint = "(total)"
	rep.Total = total

	for _, fp := range tl.Fingerprints() {
		v, judgeErr := JudgeSeries(tl.FingerprintSeries(fp), taken, opt)
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

	rep.Leaking = rep.Total.Leak || len(rep.Leaks()) > 0
	return rep, nil
}

// downgrade caps a verdict's confidence at low, used when samples were evicted.
func downgrade(v LeakVerdict) LeakVerdict {
	switch v.Confidence {
	case ConfidenceHigh, ConfidenceMedium:
		v.Confidence = ConfidenceLow
	}
	return v
}
