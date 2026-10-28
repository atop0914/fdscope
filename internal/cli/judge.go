package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/atop0914/fdscope/internal/analyze"
	"github.com/atop0914/fdscope/internal/probe"
	fdscope "github.com/atop0914/fdscope/pkg/fdscope"
)

// judgedReport is the JSON shape of `watch --judge --json`.
//
// The shape report is embedded and the verdict nested inside it, so the document
// keeps the field names of both existing wire formats. A caller that already parses
// `watch --json` sees the same fields plus one more object; a caller that wants only
// the verdict reads `verdict`.
type judgedReport struct {
	watchReport
	Verdict analyze.LeakReport `json:"verdict"`
	Summary string             `json:"summary"`
}

// writeJudgedJSON writes the shape report and the verdict as a single document.
func writeJudgedJSON(w io.Writer, rep analyze.Report, res probe.WatchResult, top int, lr analyze.LeakReport, series []int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	out := buildWatchReport(rep, res, top)
	out.Totals = series
	return enc.Encode(judgedReport{
		watchReport: out,
		Verdict:     lr,
		Summary:     fdscope.Summarize(lr),
	})
}

// renderJudgeTable renders the leak verdict and the numbers behind it.
//
// The table exists because a verdict without its evidence is an opinion. An
// operator told "leak: yes" asks "how do you know", and the answer has to be on
// the same screen: which floor was cleared, by how much, over how long a window,
// and how much headroom is left before EMFILE.
//
// The verdict is printed before the evidence, because on a terminal the reader
// sees the top of the output first - and the reverse order means scrolling past
// twenty numbers to find out whether anything is wrong.
func renderJudgeTable(w io.Writer, rep analyze.LeakReport) error {
	// Every write is checked. A renderer that ignores write errors prints half a
	// verdict and exits 0, and a truncated verdict on a CI log reads as a clean
	// run - which for this particular report is the worst possible misreading.
	if _, err := fmt.Fprintf(w, "verdict: %s\n", verdictWord(rep.Leaking)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "window: %d samples over %dms\n",
		rep.Samples, rep.WindowMillis); err != nil {
		return err
	}
	if rep.Incomplete {
		// Saying this is not optional: dropping samples is the one condition that
		// makes a "no leak" verdict weak in the direction nobody checks.
		if _, err := fmt.Fprintf(w, "warning: %d earlier samples were discarded; the verdict rests on the most recent %d only "+
			"and its confidence is capped at low\n", rep.Dropped, rep.Samples); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if err := renderVerdict(w, rep.Total, true); err != nil {
		return err
	}

	leaks := rep.Leaks()
	if len(leaks) == 0 {
		if _, err := fmt.Fprintln(w, "no single resource was judged a leak on its own"); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "\n%d resource(s) judged a leak:\n", len(leaks)); err != nil {
		return err
	}
	for _, v := range leaks {
		if err := renderVerdict(w, v, false); err != nil {
			return err
		}
	}
	return nil
}

// renderVerdict prints one verdict and its evidence.
func renderVerdict(w io.Writer, v analyze.LeakVerdict, total bool) error {
	label := v.Fingerprint
	if total {
		label = "process total"
	}
	head := fmt.Sprintf("%s: %s", label, verdictWord(v.Leak))
	if v.Confidence != "" {
		head += fmt.Sprintf(" (confidence %s)", v.Confidence)
	}
	if _, err := fmt.Fprintln(w, head); err != nil {
		return err
	}
	if v.Reason != "" {
		if _, err := fmt.Fprintf(w, "  reason: %s\n", v.Reason); err != nil {
			return err
		}
	}

	// The evidence table is what makes the verdict auditable: every row is a
	// measurement and the threshold it was compared against, so a reader can
	// disagree with the conclusion using the tool's own numbers.
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	ev := v.Evidence
	if _, err := fmt.Fprintf(tw, "  WINDOW\t%d samples / %dms\t(warmup excluded: %d)\n",
		ev.WindowSamples, ev.WindowMillis, ev.WarmupSamples); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "  BASELINE\t%d\trise measured from here\n",
		ev.BaselineValue); err != nil {
		return err
	}
	if ev.Constant {
		// A constant window is reported as what it is - a fact about the series -
		// rather than folded into the growth row, where "grew 0" would read as
		// "nothing happened".
		if _, err := fmt.Fprintf(tw, "  SHAPE\tconstant\tno change across the window\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(tw, "  GROWTH	%d	(floor %d, reached %.0f%% of it)\n",
			ev.Growth, ev.GrowthRequired, growthRatioPercent(ev)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(tw, "  RATE\t%.3f/s\t(floor %.3f/s)\n",
			ev.RatePerSecond, ev.RateRequired); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(tw, "  COVERAGE\t%d/%d gaps grew\tstill climbing at window end: %t\n",
			ev.ActiveGaps, ev.TotalGaps, ev.RateSustained); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(tw, "  MONOTONIC\t%t\t", ev.Monotonic); err != nil {
			return err
		}
		if ev.Monotonic {
			if _, err := fmt.Fprintln(tw, "peak is at the end of the window"); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(tw, "fell %d after its peak\n", ev.FallbackAfterPeak); err != nil {
			return err
		}
	}
	// The headroom and the projection are printed from the projection object
	// rather than from the evidence, because they are the only place that knows
	// whether an absent number means "unlimited" or "could not be read". Printing
	// nothing for either case would read as "no risk" in both.
	if p := v.Projection; p.State != "" {
		switch p.State {
		case analyze.ProjectionUnlimited:
			if _, err := fmt.Fprintf(tw, "  HEADROOM\tunlimited\tEMFILE is not reachable by descriptor count\n"); err != nil {
				return err
			}
		case analyze.ProjectionLimitUnknown:
			if _, err := fmt.Fprintf(tw, "  HEADROOM\tunknown\tthe process limit could not be read\n"); err != nil {
				return err
			}
		case analyze.ProjectionAtLimit:
			if _, err := fmt.Fprintf(tw, "  HEADROOM\t%d left of %d\tat or past the soft limit: EMFILE is imminent\n",
				p.Remaining, p.Limit); err != nil {
				return err
			}
		case analyze.Projected:
			if _, err := fmt.Fprintf(tw, "  HEADROOM\t%d left of %d\tEMFILE in about %s at %s/s\n",
				p.Remaining, p.Limit, p.HumanETA(), p.RateText()); err != nil {
				return err
			}
			// The ETA is an extrapolation, so its basis is printed next to it:
			// how many samples the rate came from, over how long, and how much
			// the number deserves to be trusted.
			if _, err := fmt.Fprintf(tw, "  PROJECTION\t%s\tconfidence %s\n", p.Note, p.Confidence); err != nil {
				return err
			}
		default:
			if p.Limit > 0 {
				if _, err := fmt.Fprintf(tw, "  HEADROOM\t%d left of %d\t%d%% consumed, no ETA\n",
					p.Remaining, p.Limit, (p.Limit-p.Remaining)*100/p.Limit); err != nil {
					return err
				}
			}
		}
	}
	return tw.Flush()
}

// verdictWord renders the boolean as the words a reader acts on.
func verdictWord(leak bool) string {
	if leak {
		return "LEAK"
	}
	return "no leak"
}

// growthRatioPercent is how much of the required growth was actually reached,
// as a percentage.
//
// It is derived here rather than carried in the evidence because the floor is a
// max() of an absolute and a relative criterion computed inside the judgement, and
// re-deriving that max at the render site would eventually disagree with it. What
// the reader needs is the one comparison that decided the verdict.
func growthRatioPercent(ev analyze.LeakEvidence) float64 {
	if ev.GrowthRequired <= 0 {
		return 0
	}
	return float64(ev.Growth) / float64(ev.GrowthRequired) * 100
}
