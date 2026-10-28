package fdscope

// This file is the verdict as a library call, for code that wants the answer
// without a command line: a CI job written in Go, an agent, a wrapper that adds
// its own reporting. The judgement itself is not reimplemented here - CheckPID
// drives the same sampler and the same analyse.Judge that `fdscope check` uses,
// so a verdict obtained from the library and one obtained from the binary cannot
// drift apart.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/atop0914/fdscope/internal/analyze"
	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/probe"
)

// The verdict types are re-exported so an embedder can name them without
// importing an internal package.
type (
	// LeakOptions are the thresholds the verdict uses. The zero value is usable
	// and applies the defaults.
	LeakOptions = analyze.LeakOptions
	// LeakReport is the verdict for a whole window.
	LeakReport = analyze.LeakReport
	// LeakVerdict is the verdict for one series.
	LeakVerdict = analyze.LeakVerdict
	// LeakEvidence is the per-criterion breakdown behind a verdict.
	LeakEvidence = analyze.LeakEvidence
	// Confidence states how much a verdict deserves to be believed.
	Confidence = analyze.Confidence
)

// Confidence levels reported by fdscope.
const (
	ConfidenceHigh   = analyze.ConfidenceHigh
	ConfidenceMedium = analyze.ConfidenceMedium
	ConfidenceLow    = analyze.ConfidenceLow
	ConfidenceNone   = analyze.ConfidenceNone
)

// DefaultLeakOptions returns the thresholds used when the caller configures none.
func DefaultLeakOptions() LeakOptions { return analyze.DefaultLeakOptions() }

// supported is the platform gate, held in a variable so that the refusal on
// non-Linux platforms can be exercised from a test running on Linux. Without
// that, the most safety-critical branch in this package - "do not pretend to
// have measured" - would be the one branch no test could reach.
var supported = probe.IsSupported

// Sampling defaults for CheckPID.
//
// 25 samples 200ms apart is a five second window, which is the shortest one the
// leak thresholds grant high confidence to. Longer windows find slower leaks;
// shorter ones are still usable but the verdict says "medium" and means it.
const (
	// DefaultCheckInterval is the delay between samples.
	DefaultCheckInterval = 200 * time.Millisecond
	// DefaultCheckSamples is how many samples a check takes by default.
	DefaultCheckSamples = 25
)

// CheckOptions configures CheckPID.
type CheckOptions struct {
	// Interval is the delay between samples. Zero means DefaultCheckInterval.
	Interval time.Duration
	// Samples is how many samples to take. Zero means DefaultCheckSamples; the
	// minimum is two, but a window shorter than LeakOptions.MinSamples yields a
	// refusal (an error) rather than a verdict, because three points cannot tell
	// a pool warming up from a leak.
	Samples int
	// Leak carries the thresholds. The zero value applies the defaults.
	Leak LeakOptions
	// Normalizer overrides the fingerprint rules. Nil means the default rules,
	// with the current user's home directory anonymised.
	Normalizer *Normalizer
}

// DefaultCheckOptions returns the options a check uses when none are given.
func DefaultCheckOptions() CheckOptions {
	return CheckOptions{
		Interval: DefaultCheckInterval,
		Samples:  DefaultCheckSamples,
		Leak:     analyze.DefaultLeakOptions(),
	}
}

// normalize fills in defaults and rejects impossible values.
func (o CheckOptions) normalize() (CheckOptions, error) {
	def := DefaultCheckOptions()
	if o.Interval == 0 {
		o.Interval = def.Interval
	}
	if o.Interval < 0 {
		return CheckOptions{}, fmt.Errorf("check interval must not be negative, got %s", o.Interval)
	}
	if o.Samples == 0 {
		o.Samples = def.Samples
	}
	if o.Samples < 2 {
		// Two samples are the minimum a series can exist at; one sample is not a
		// series and would produce a report of pure zeros that reads as "stable".
		return CheckOptions{}, fmt.Errorf("check needs at least 2 samples, got %d", o.Samples)
	}
	return o, nil
}

// CheckResult is the outcome of a check.
type CheckResult struct {
	// PID is the process that was checked, Interval the requested spacing and
	// Snapshots how many samples were captured.
	PID       int
	Interval  time.Duration
	Snapshots int
	// Incomplete counts snapshots that could not be read fully and were skipped.
	// A partial read looks exactly like a release, so it is never appended.
	Incomplete int
	// Totals is the process descriptor total at each sample, oldest first. It is
	// the series the verdict was computed on: a verdict that cannot be reproduced
	// from its own input is an opinion.
	Totals []int
	// Headroom is the distance to the soft limit at the last sample. It is
	// reported even when nothing is leaking, because "unlimited" and "could not
	// be read" are facts a reader needs on a clean run too.
	Headroom model.Headroom
	// Report is the verdict.
	Report LeakReport
}

// Leaking reports whether the check found a leak.
func (r CheckResult) Leaking() bool { return r.Report.Leaking }

// Summarize renders a report as one line: what leaked, if anything.
//
// It is derived from the report rather than set next to it, so the sentence and
// the exit code a caller derives from the same report cannot disagree - a run that
// prints LEAK and exits 0 is the one combination that must be impossible. It lives
// here rather than in the command so that an embedder's log line and the binary's
// say the same thing.
func Summarize(r LeakReport) string {
	if !r.Leaking {
		return "no leak"
	}
	parts := make([]string, 0, len(r.Series)+1)
	if r.Total.Leak {
		parts = append(parts, "process total")
	}
	for _, v := range r.Leaks() {
		parts = append(parts, v.Fingerprint)
	}
	return "leak in " + strings.Join(parts, ", ")
}

// CheckPID samples pid and returns the verdict.
//
// It is the non-asserting form of `fdscope check`: same sampler, same thresholds,
// same refusal rules, no exit code. A caller that wants a gate turns Leaking into
// one.
//
// Every failure is an error, never a verdict. That direction is deliberate: a
// check is a gate, and the failure modes of a gate are not symmetric. Reporting
// "no leak" when the process died halfway through the window would let a CI job
// pass on evidence that was never collected - the calm-direction lie this project
// keeps finding in its own assumptions - while reporting "could not check" costs
// one retry.
func CheckPID(pid int, opts CheckOptions) (CheckResult, error) {
	if !supported() {
		return CheckResult{}, ErrNotLinux
	}
	opt, err := opts.normalize()
	if err != nil {
		return CheckResult{}, err
	}

	p := probe.NewProbe()
	if opt.Normalizer != nil {
		p.Normalizer = *opt.Normalizer
	} else if home, homeErr := os.UserHomeDir(); homeErr == nil {
		// Anonymise the home directory by default: fingerprints end up in CI logs
		// and issue reports, and a username does not help anyone read them.
		p.Normalizer.HomeDir = home
	}

	// Capacity equals the sample count: check decides inside a fixed window, so
	// there is nothing to retain beyond it.
	res, err := p.Watch(pid, opt.Samples, probe.WatchConfig{Interval: opt.Interval, Capacity: opt.Samples})
	if err != nil {
		return CheckResult{}, err
	}
	if res.Err != nil {
		// A run that stopped early is not a short verdict, it is no verdict.
		return CheckResult{}, fmt.Errorf("checking pid %d stopped after %d of %d samples: %w",
			pid, res.Snapshots, opt.Samples, res.Err)
	}
	if res.Timeline.Len() == 0 {
		return CheckResult{}, fmt.Errorf("no samples could be collected from pid %d", pid)
	}

	rep, err := analyze.Judge(res.Timeline, opt.Leak)
	if err != nil {
		return CheckResult{}, err
	}
	// The judge refuses to conclude when the window is too short to separate the
	// shapes. That refusal must not read as a pass: ConfidenceNone is the one
	// value that means "I did not answer the question".
	if rep.Total.Confidence == analyze.ConfidenceNone {
		return CheckResult{}, fmt.Errorf("no verdict for pid %d: %s", pid, rep.Total.Reason)
	}

	totals := res.Timeline.TotalSeries().Counts
	last := 0
	if len(totals) > 0 {
		last = totals[len(totals)-1]
	}

	return CheckResult{
		PID:        pid,
		Interval:   opt.Interval,
		Snapshots:  res.Snapshots,
		Incomplete: res.Incomplete,
		Totals:     totals,
		Headroom:   model.NewHeadroom(pid, last, res.Timeline.Limit()),
		Report:     rep,
	}, nil
}
