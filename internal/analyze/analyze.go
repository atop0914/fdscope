// Package analyze turns a series of descriptor counts into a judgement.
//
// Everything here is a pure function of numbers. That is deliberate: the leak
// criteria are the part of fdscope most likely to be wrong in a way nobody
// notices, because a wrong verdict looks exactly like a right one. Keeping them
// free of /proc, clocks and processes means they can be tested against the
// awkward shapes - a pool warming up, a batch job, a periodic spike - with
// hand-built sequences and no flakiness.
//
// The first judgement implemented is the rebound (回落). It exists to answer a
// question two snapshots structurally cannot: "did the count go up and come back
// down?" A count that rises and falls is doing work; a count that rises and stays
// is what leaks. Without this, every batch job would be reported as a leak and
// the tool would be ignored within a week.
package analyze

import (
	"fmt"
	"sort"

	"github.com/atop0914/fdscope/internal/timeline"
)

// Trend is the coarse direction of a series.
type Trend string

const (
	// TrendRising means the series ended above where it started, by more than
	// the flat tolerance.
	TrendRising Trend = "rising"
	// TrendFalling means the series ended below where it started, by more than
	// the flat tolerance.
	TrendFalling Trend = "falling"
	// TrendFlat means the series ended close enough to where it started that
	// calling it a direction would be noise.
	TrendFlat Trend = "flat"
)

// DefaultFlatTolerance is how much net movement a series may show and still be
// reported as flat.
//
// It is not zero because descriptor counts jitter by one or two even in a
// perfectly stable process: a helper goroutine opens a file, a transient
// connection closes. Reporting "rising by 1" for that trains the reader to ignore
// the trend column entirely, so the column becomes worthless exactly when a real
// trend appears. A tolerance turns the column into a statement the reader can act
// on.
const DefaultFlatTolerance = 2

// Summary describes one series over the retained window.
//
// Every field is derived from the counts alone, so a summary can be recomputed
// from a JSON dump of the series and must agree with the original.
type Summary struct {
	// Fingerprint identifies the series; "(total)" for the process total.
	Fingerprint string `json:"fingerprint"`
	// Samples is the number of points in the series.
	Samples int `json:"samples"`
	// First and Last are the endpoint values.
	First int `json:"first"`
	Last  int `json:"last"`
	// Min and Max are the extremes over the window. Peak is where Max was
	// first reached, as an index into the series.
	Min      int   `json:"min"`
	Max      int   `json:"max"`
	Peak     int   `json:"-"`
	PeakAt   int   `json:"peak_at"`
	PeakTime int64 `json:"peak_time,omitempty"`
	// Trend is the coarse direction, decided with FlatTolerance.
	Trend Trend `json:"trend"`
	// Rebound reports whether the series fell by at least ReboundThreshold
	// from a peak it had reached after rising. See DetectRebound for why the
	// "after rising" part matters.
	Rebound bool `json:"rebound"`
	// ReboundFrom and ReboundTo are the peak value and the lowest value after
	// it, meaningful only when Rebound is set.
	ReboundFrom int `json:"rebound_from,omitempty"`
	ReboundTo   int `json:"rebound_to,omitempty"`
}

// Drop is how far the series fell after its peak. It is zero when the series
// never rebounded.
func (s Summary) Drop() int {
	if !s.Rebound {
		return 0
	}
	return s.ReboundFrom - s.ReboundTo
}

// Options controls the thresholds a caller judges by.
//
// The zero value is usable and applies the defaults, so the common call site does
// not have to know the numbers. Thresholds are configurable because what counts
// as a rebound depends on the process: a service holding 5 descriptors and one
// holding 50000 need different absolute thresholds, and hard-coding either would
// be wrong for the other.
type Options struct {
	// FlatTolerance is the net movement still called flat.
	FlatTolerance int
	// ReboundThreshold is the drop from a peak that counts as a rebound.
	ReboundThreshold int
}

// DefaultOptions returns the thresholds fdscope uses when none are configured.
func DefaultOptions() Options {
	return Options{FlatTolerance: DefaultFlatTolerance, ReboundThreshold: 3}
}

// normalize fills in the defaults and rejects impossible values.
//
// A negative threshold is rejected rather than clamped: "-3" most likely means
// the caller intended "3" but has a sign error somewhere upstream, and silently
// treating it as 3 would hide that while making the report look fine.
func (o Options) normalize() (Options, error) {
	if o.FlatTolerance < 0 {
		return Options{}, fmt.Errorf("flat tolerance must not be negative, got %d", o.FlatTolerance)
	}
	if o.ReboundThreshold < 1 {
		if o.ReboundThreshold == 0 {
			// Zero is the documented "use the default" value.
			o.ReboundThreshold = DefaultOptions().ReboundThreshold
		} else {
			return Options{}, fmt.Errorf("rebound threshold must be at least 1, got %d", o.ReboundThreshold)
		}
	}
	return o, nil
}

// SummarizeSeries describes a single series.
func SummarizeSeries(s timeline.Series, opts Options) (Summary, error) {
	opt, err := opts.normalize()
	if err != nil {
		return Summary{}, err
	}
	if len(s.Counts) == 0 {
		return Summary{}, fmt.Errorf("series %q has no samples to summarise", s.Fingerprint)
	}

	out := Summary{
		Fingerprint: s.Fingerprint,
		Samples:     len(s.Counts),
		First:       s.Counts[0],
		Last:        s.Counts[len(s.Counts)-1],
		Min:         s.Counts[0],
		Max:         s.Counts[0],
	}
	for i, c := range s.Counts {
		if c < out.Min {
			out.Min = c
		}
		// Strictly greater: the *first* time the peak is reached is the
		// meaningful one. A series that touches its maximum twice and then
		// falls will otherwise attribute the drop to the second, later visit
		// and report a cleaner-looking series than actually happened.
		if c > out.Max {
			out.Max = c
			out.PeakAt = i
		}
	}
	out.Peak = out.Max

	out.Trend = trendOf(s.Counts, opt.FlatTolerance)

	from, to, rebounded := DetectRebound(s.Counts, opt.ReboundThreshold)
	if rebounded {
		out.Rebound = true
		out.ReboundFrom = from
		out.ReboundTo = to
	}
	return out, nil
}

// trendOf classifies the net movement of vals.
//
// It compares endpoints, not a fitted slope, on purpose. A least-squares slope
// over a short window amplifies single-sample jitter into a fractional number
// that reads as precision the data does not have: three samples of 100, 101, 100
// produce a nonzero slope and would be reported as a trend. The endpoint
// difference with a tolerance answers the question a reader actually asks - "is
// it higher than when I started watching?" - and stays quiet when the answer is
// "about the same".
func trendOf(vals []int, flatTolerance int) Trend {
	if len(vals) < 2 {
		return TrendFlat
	}
	delta := vals[len(vals)-1] - vals[0]
	switch {
	case delta > flatTolerance:
		return TrendRising
	case delta < -flatTolerance:
		return TrendFalling
	default:
		return TrendFlat
	}
}

// DetectRebound reports whether vals rose to a peak and then fell at least
// threshold from it, returning the peak value and the lowest value reached after
// the peak.
//
// The definition has three parts, and each one excludes a shape that would
// otherwise be a false alarm:
//
//   - The peak must be preceded by a rise. A series that only falls - 100, 90,
//     80 - is draining, which is the opposite of a problem. Without this clause
//     every shutdown would be reported as a rebound.
//   - The fall must be measured from the peak, not from the first value. A
//     process that starts at 10, rises to 100 and settles at 40 has recovered a
//     real resource, even though it ends above where it started.
//   - The fall must reach the threshold. Descriptor counts wobble; a drop of one
//     is churn, and reporting it would bury the real rebounds.
//
// The "lowest value after the peak" is reported rather than the last value so
// that a series which partially recovered - peak 100, drop to 40, back up to 80 -
// does not get credit for a rebound it did not finish. The tool should report the
// deepest release it can prove.
func DetectRebound(vals []int, threshold int) (from, to int, ok bool) {
	if threshold < 1 || len(vals) < 2 {
		return 0, 0, false
	}

	// Find the first index at which the running maximum was set. A peak that
	// equals the previous maximum is not a new peak: using the last one would
	// move the peak later in the series and hide an earlier, deeper drop.
	peakIdx, peak := 0, vals[0]
	for i := 1; i < len(vals); i++ {
		if vals[i] > peak {
			peak, peakIdx = vals[i], i
		}
	}

	rose := false
	for i := 0; i < peakIdx; i++ {
		if vals[i] < peak {
			rose = true
			break
		}
	}
	if !rose {
		return 0, 0, false
	}
	if peakIdx == len(vals)-1 {
		// Still at the peak: nothing has fallen yet.
		return 0, 0, false
	}

	lowest := vals[peakIdx]
	for i := peakIdx + 1; i < len(vals); i++ {
		if vals[i] < lowest {
			lowest = vals[i]
		}
	}
	if peak-lowest < threshold {
		return 0, 0, false
	}
	return peak, lowest, true
}

// Report summarises a whole timeline.
type Report struct {
	// PID is the observed process.
	PID int `json:"pid"`
	// Samples is the number of retained samples, and Dropped how many were
	// evicted by the capacity bound.
	Samples int `json:"samples"`
	Dropped int `json:"dropped"`
	// Incomplete reports whether Dropped > 0, meaning the window does not cover
	// the whole observation. It is a separate field from Dropped so a reader
	// cannot miss it.
	Incomplete bool `json:"incomplete"`
	// Requested is how many samples the caller asked for. The analyser does not
	// sample, so it is set by the caller; it exists because "samples: 4" alone is
	// ambiguous - four out of four is a finished run, four out of forty is an
	// interrupted one, and a reader cannot tell them apart without this number.
	Requested int `json:"requested_samples,omitempty"`
	// Span is the wall-clock distance between the first and last retained
	// sample, in milliseconds. Milliseconds rather than a Duration string so
	// the JSON stays parseable without a second parser.
	SpanMillis int64 `json:"span_millis"`
	// Total is the summary of the process descriptor total.
	Total Summary `json:"total"`
	// Series holds one summary per fingerprint, ordered by peak descending then
	// by name, so the resources that reached the largest counts come first.
	Series []Summary `json:"series"`
}

// Rising returns the fingerprints whose trend is rising.
//
// It is computed from the summaries rather than passed through from the trend
// field so that a caller filtering on direction gets the same rows a reader sees
// in the table; deriving it twice would eventually disagree.
func (r Report) Rising() []Summary {
	out := make([]Summary, 0, len(r.Series))
	for _, s := range r.Series {
		if s.Trend == TrendRising {
			out = append(out, s)
		}
	}
	return out
}

// Rebounded returns the fingerprints that rose and then fell back.
func (r Report) Rebounded() []Summary {
	out := make([]Summary, 0, len(r.Series))
	for _, s := range r.Series {
		if s.Rebound {
			out = append(out, s)
		}
	}
	return out
}

// Analyze summarizes every fingerprint in a timeline.
//
// An empty timeline is an error rather than an empty report: a caller that
// renders "no descriptor changed" for a run that collected nothing has been told
// something false.
func Analyze(tl *timeline.Timeline, opts Options) (Report, error) {
	if tl == nil {
		return Report{}, fmt.Errorf("no timeline to analyze")
	}
	opt, err := opts.normalize()
	if err != nil {
		return Report{}, err
	}
	if tl.Len() == 0 {
		return Report{}, fmt.Errorf("no samples were collected for pid %d", tl.PID())
	}

	total, err := SummarizeSeries(tl.TotalSeries(), opt)
	if err != nil {
		return Report{}, err
	}
	total.Fingerprint = "(total)"

	samples := tl.Samples()
	rep := Report{
		PID:        tl.PID(),
		Samples:    tl.Len(),
		Dropped:    tl.Dropped(),
		Incomplete: tl.Incomplete(),
		SpanMillis: (samples[len(samples)-1].Taken - samples[0].Taken) / 1_000_000,
		Total:      total,
		Series:     make([]Summary, 0, len(samples)),
	}

	for _, fp := range tl.Fingerprints() {
		s, summarizeErr := SummarizeSeries(tl.FingerprintSeries(fp), opt)
		if summarizeErr != nil {
			return Report{}, summarizeErr
		}
		if s.Samples > 0 && tl.Len() > 0 {
			// PeakTime must agree with the sample the peak was found in; taking
			// it from the timeline keeps series and time from drifting apart.
			s.PeakTime = samples[s.PeakAt].Taken
		}
		rep.Series = append(rep.Series, s)
	}

	sort.Slice(rep.Series, func(i, j int) bool {
		if rep.Series[i].Max != rep.Series[j].Max {
			return rep.Series[i].Max > rep.Series[j].Max
		}
		return rep.Series[i].Fingerprint < rep.Series[j].Fingerprint
	})
	return rep, nil
}
