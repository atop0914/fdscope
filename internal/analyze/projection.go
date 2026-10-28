package analyze

import (
	"fmt"
	"math"
	"time"

	"github.com/atop0914/fdscope/internal/model"
)

// ProjectionState says what can honestly be said about the distance to EMFILE.
//
// The states are separate because they answer different questions and only one
// of them is a number. A run against an unlimited limit has no ETA and no risk;
// a run whose limit could not be read has no ETA either but for the opposite
// reason, and a process already at its limit does not need an ETA - it needs a
// warning. Collapsing those into "eta = 0" would make the most urgent state and
// the most harmless one print the same thing.
type ProjectionState string

const (
	// Projected means a finite limit is known and the observed rate reaches it:
	// ETASeconds is meaningful.
	Projected ProjectionState = "projected"
	// ProjectionAtLimit means the process is already at or past its soft limit,
	// so the next allocation fails. No extrapolation is involved.
	ProjectionAtLimit ProjectionState = "at-limit"
	// ProjectionUnlimited means the kernel reported "unlimited": no amount of
	// descriptor growth reaches EMFILE.
	ProjectionUnlimited ProjectionState = "unlimited"
	// ProjectionLimitUnknown means no finite limit could be read, so no EMFILE
	// estimate is possible. It is not a zero, and it is not unlimited.
	ProjectionLimitUnknown ProjectionState = "limit-unknown"
	// ProjectionNoGrowth means a finite limit is known but there is no rise to
	// extrapolate, so no ETA is produced.
	ProjectionNoGrowth ProjectionState = "no-growth"
)

// projectionMinSamples is how many samples a rate needs before it deserves
// medium confidence.
//
// Four samples are the minimum the verdict itself accepts, but a rate fitted to
// four points and then applied over hours is a much longer stride than the
// verdict ever takes. Below this the ETA is still reported - it is the honest
// order of magnitude - and labelled low.
const projectionMinSamples = 5

// projectionMinWindow is the span below which a rate is reported at medium
// confidence rather than high. It matches DefaultLeakOptions.MinWindowMillis:
// the verdict and the projection must not disagree about when an observation is
// long enough to be representative.
const projectionMinWindow = 5 * time.Second

// Projection is the answer to "how long until EMFILE", with its basis attached.
//
// Every field is an input the reader could recompute the ETA from: the rate, how
// many samples and how much time it was fitted over, and what is left. An ETA
// without those is a guess wearing a number's clothes.
type Projection struct {
	// State says which question this projection answered.
	State ProjectionState `json:"state"`
	// Limit is the finite soft limit, 0 when there is no finite number to report.
	Limit int `json:"limit,omitempty"`
	// Remaining is limit minus the last observed count, negative when the
	// process is already over a lowered limit.
	Remaining int `json:"remaining,omitempty"`
	// RatePerSecond is the mean growth over the fitted window, RateSamples how
	// many samples it was fitted to and RateSeconds how much time they span.
	RatePerSecond float64 `json:"rate_per_second,omitempty"`
	RateSamples   int     `json:"rate_samples,omitempty"`
	RateSeconds   float64 `json:"rate_seconds,omitempty"`
	// ETASeconds is how long the remaining descriptors last at RatePerSecond.
	// Zero means "no ETA was produced", which the state explains.
	ETASeconds float64 `json:"eta_seconds,omitempty"`
	// Confidence rates the extrapolation, not the leak verdict.
	Confidence Confidence `json:"confidence,omitempty"`
	// Note states the basis in words, including why there is no ETA.
	Note string `json:"note"`
}

// Project computes the distance to EMFILE from an observed series.
//
// It is an extrapolation of a measured rate over a measured window, nothing
// more: the rate is an average, the limit may be raised, and a leak can stop.
// The wording it produces therefore says "at this rate", and the caller chooses
// whether the verdict justifies quoting it at all.
//
// No ETA is produced when the limit is not a finite number, when nothing is
// growing, or when the process is already at its limit. Each of those returns a
// state that explains itself rather than a zero that would be read as "now".
func Project(counts []int, period time.Duration, limit model.OpenLimit) (Projection, error) {
	if period < 0 {
		return Projection{}, fmt.Errorf("sample period must not be negative, got %s", period)
	}
	if len(counts) == 0 {
		return Projection{State: ProjectionNoGrowth, Note: "no samples to project from"}, nil
	}

	last := counts[len(counts)-1]

	switch {
	case limit.Unlimited():
		return Projection{
			State: ProjectionUnlimited,
			Note:  "the limit is unlimited: descriptor growth cannot reach EMFILE",
		}, nil
	case !limit.Known():
		return Projection{
			State: ProjectionLimitUnknown,
			Note:  "the process limit could not be read: no EMFILE estimate is possible",
		}, nil
	}

	p := Projection{State: ProjectionNoGrowth, Limit: limit.Soft, Remaining: limit.Soft - last}
	if p.Remaining <= 0 {
		p.State = ProjectionAtLimit
		p.Note = fmt.Sprintf("already at the limit of %d with %d open: the next allocation fails", limit.Soft, last)
		return p, nil
	}

	if len(counts) < 2 || period == 0 {
		p.Note = fmt.Sprintf("a single sample: no interval to measure a rate over, %d descriptors left", p.Remaining)
		return p, nil
	}

	spanSeconds := (period * time.Duration(len(counts)-1)).Seconds()
	growth := last - counts[0]
	if growth <= 0 {
		p.Note = fmt.Sprintf("no growth across %d samples over %s: nothing to extrapolate, %d descriptors left",
			len(counts), shortDuration(time.Duration(spanSeconds*float64(time.Second))), p.Remaining)
		return p, nil
	}

	p.RatePerSecond = float64(growth) / spanSeconds
	p.RateSamples = len(counts)
	p.RateSeconds = spanSeconds
	p.ETASeconds = float64(p.Remaining) / p.RatePerSecond
	p.State = Projected
	p.Confidence = projectionConfidence(len(counts), spanSeconds)
	p.Note = fmt.Sprintf("rate from %d samples over %s at %s/s",
		len(counts), shortDuration(time.Duration(spanSeconds*float64(time.Second))), formatRate(p.RatePerSecond))
	return p, nil
}

// projectionConfidence rates how far the extrapolation is allowed to be trusted.
//
// Two things shorten the stride: too few samples to fit a rate, and a window
// shorter than the one the leak thresholds already call representative.
func projectionConfidence(samples int, spanSeconds float64) Confidence {
	switch {
	case samples < projectionMinSamples:
		return ConfidenceLow
	case spanSeconds < projectionMinWindow.Seconds():
		return ConfidenceMedium
	}
	return ConfidenceHigh
}

// WithoutETA drops the extrapolation but keeps everything the limit itself
// says, for verdicts that established no leak.
//
// The distinction matters: "no leak" is not a reason to stop reporting that the
// process is already at its limit, and it is not a reason to hide that the limit
// is unlimited. It is only a reason not to predict a time of death.
func (p Projection) WithoutETA(note string) Projection {
	if p.State != Projected {
		return p
	}
	p.State = ProjectionNoGrowth
	p.ETASeconds = 0
	p.Note = note
	return p
}

// HumanETA renders ETASeconds in the coarsest unit that stays precise enough to
// act on. It never returns seconds in the six-digit range.
//
// The rule exists because the previous output said "crossed in about 524278s",
// which is arithmetically right and practically unreadable - a number nobody can
// convert is a number nobody acts on. Anything a month out is not a countdown,
// it is a statement that the limit is far away.
func (p Projection) HumanETA() string {
	return humanETA(p.ETASeconds)
}

// RateText renders the fitted rate for display, with no more precision than the
// window supports.
func (p Projection) RateText() string { return formatRate(p.RatePerSecond) }

func humanETA(seconds float64) string {
	switch d := time.Duration(seconds * float64(time.Second)); {
	case d < time.Minute:
		s := math.Round(d.Seconds())
		if s < 1 {
			s = 1
		}
		return fmt.Sprintf("%.0fs", s)
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", math.Round(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
	return "over a month"
}

// shortDuration renders a span the projection was fitted over.
func shortDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// formatRate renders a rate without pretending to more precision than a short
// window can support.
func formatRate(rate float64) string {
	switch {
	case rate >= 10:
		return fmt.Sprintf("%.0f", rate)
	case rate >= 1:
		return fmt.Sprintf("%.1f", rate)
	}
	return fmt.Sprintf("%.3f", rate)
}

// Describe renders the projection as one clause that can follow a verdict.
func (p Projection) Describe() string {
	switch p.State {
	case Projected:
		return fmt.Sprintf("%d descriptors below the limit of %d: crossed in about %s at %s/s",
			p.Remaining, p.Limit, p.HumanETA(), formatRate(p.RatePerSecond))
	case ProjectionAtLimit:
		return fmt.Sprintf("at or past the limit of %d: EMFILE is imminent", p.Limit)
	case ProjectionUnlimited:
		return "the limit is unlimited: EMFILE is not reachable by descriptor count"
	case ProjectionLimitUnknown:
		return "the process limit could not be read, so no EMFILE estimate is possible"
	}
	if p.Limit > 0 {
		return fmt.Sprintf("%d descriptors below the limit of %d, but the count is not rising", p.Remaining, p.Limit)
	}
	return p.Note
}
