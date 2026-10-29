package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/atop0914/fdscope/internal/analyze"
	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/probe"
	fdscope "github.com/atop0914/fdscope/pkg/fdscope"
)

// runWatch samples a process repeatedly and reports the shape of each series.
//
// The distinction it exists to make is "rising and staying" versus "rising and
// coming back". `snapshot` answers "how many now" and `diff` answers "what changed
// between two points"; neither can tell a batch job from a leak, because both
// would report the same numbers for either.
func runWatch(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	interval := fs.Duration("interval", time.Second, "delay between samples")
	samples := fs.Int("samples", 30, "how many samples to take")
	keep := fs.Int("keep", 0, "samples retained in the timeline (0 = keep all requested samples)")
	rebound := fs.Int("rebound", 0, "drop from a peak that counts as a rebound (0 = default)")
	flat := fs.Int("flat-tolerance", -1, "net movement still reported as flat (-1 = default)")
	top := fs.Int("top", 0, "limit output to the N largest series (0 = all)")
	keepDir := fs.Bool("keep-dir", true, "keep directory components in fingerprints")
	stripRotation := fs.Bool("strip-rotation", true, "merge rotated log files into one fingerprint")
	judge := fs.Bool("judge", false, "also decide whether the series is a leak, and exit 2 if it is")
	withSeries := fs.Bool("series", false, "include the per-sample descriptor totals in the JSON output")
	attrRules := fs.String("attr-rules", "", "JSON file of attribution rules to add to the built-in ones")

	args, positionals := splitFlags(args, fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	positionals = append(positionals, fs.Args()...)
	if len(positionals) != 1 {
		return fmt.Errorf("watch requires exactly one pid, got %d", len(positionals))
	}
	pid, err := strconv.Atoi(positionals[0])
	if err != nil {
		return fmt.Errorf("invalid pid %q: %w", positionals[0], err)
	}
	// Two samples are enough to state a difference but not a shape: a rise and a
	// fall need at least three points. Refusing one sample matters most, because
	// it would otherwise produce a report of pure zeros that reads as "stable".
	if *samples < 2 {
		return fmt.Errorf("--samples must be at least 2 to describe a series, got %d", *samples)
	}
	if *interval < 0 {
		return errors.New("--interval must not be negative")
	}
	if *top < 0 {
		return errors.New("--top must be >= 0")
	}
	if *flat < -1 {
		return errors.New("--flat-tolerance must be >= 0")
	}

	capacity := *keep
	if capacity == 0 {
		capacity = *samples
	}
	if capacity > *samples {
		// A timeline that can hold more than the run will ever collect is not
		// wrong, but it hides a typo (--keep 300 with --samples 30) that the
		// caller probably wants to know about.
		return fmt.Errorf("--keep %d exceeds --samples %d: the run cannot retain more samples than it takes", capacity, *samples)
	}

	opts := analyze.DefaultOptions()
	if *rebound != 0 {
		opts.ReboundThreshold = *rebound
	}
	if *flat >= 0 {
		opts.FlatTolerance = *flat
	}

	p := probe.NewProbe()
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		p.Normalizer.HomeDir = home
	}
	p.Normalizer.KeepDir = *keepDir
	p.Normalizer.StripRotation = *stripRotation

	res, err := p.Watch(pid, *samples, probe.WatchConfig{Interval: *interval, Capacity: capacity})
	if err != nil {
		return err
	}

	// A watch that stopped early still collected evidence. Rendering the report
	// first and then failing keeps that evidence in front of the reader: a
	// series that ends abruptly is usually the interesting part, and throwing it
	// away because the last read failed would discard the answer along with the
	// error.
	if res.Timeline.Len() == 0 {
		if res.Err != nil {
			return fmt.Errorf("no samples could be collected from pid %d: %w", pid, res.Err)
		}
		return fmt.Errorf("no samples could be collected from pid %d", pid)
	}

	rep, analyzeErr := analyze.Analyze(res.Timeline, opts)
	if analyzeErr != nil {
		return analyzeErr
	}
	// The analyser only sees the timeline, so it cannot know how many samples were
	// asked for. Without this, an interrupted run is indistinguishable from a
	// finished one in the JSON.
	rep.Requested = *samples

	// The per-sample totals are opt-in and JSON-only: they are what makes a verdict
	// reproducible offline, and they are the first thing anyone needs when a verdict
	// looks wrong. Omitted by default because a long window makes a very large array.
	if *withSeries && !*asJSON {
		return errors.New("--series requires --json")
	}
	var renderErr error
	switch {
	case *asJSON && *judge:
		// Handled below, together with the verdict, so that stdout carries exactly
		// one JSON document. Writing the shape report here and the verdict after it
		// produces two top-level values, which is not valid JSON - and that defect
		// was caught by a test asserting the output parses, not by reading it.
	case *asJSON:
		renderErr = writeWatchJSON(stdout, rep, res, *top, seriesOf(res, *withSeries))
	default:
		renderErr = writeWatchTable(stdout, rep, res, *top)
	}
	if renderErr != nil {
		return renderErr
	}

	// The verdict is computed after the shape report and rendered after it too:
	// the shape is what the reader needs in order to disagree with the verdict,
	// and printing the conclusion first would invite acting on it without looking.
	//
	// The verdict is only reached when asked for. `watch` deliberately does not
	// convict on its own - a rising series is also a pool warming up - and a
	// tool that volunteered a verdict on every run would train its reader to
	// ignore the word.
	leaking := false
	if *judge {
		// The rules are loaded before the judgement and a broken file ends the run
		// with an error: judging under rules the operator did not choose, without
		// saying so, is the failure this flag exists to avoid.
		engine, engineErr := fdscope.LoadAttrEngine(*attrRules)
		if engineErr != nil {
			return engineErr
		}
		judgeOpts := analyze.DefaultLeakOptions()
		judgeOpts.Attr = engine
		lr, judgeErr := analyze.Judge(res.Timeline, judgeOpts)
		if judgeErr != nil {
			return judgeErr
		}
		leaking = lr.Leaking
		if *asJSON {
			// One document, not two: a second JSON object on stdout is not valid for
			// the parsers this flag exists for. The shape report is therefore held
			// back and the verdict nested inside it.
			if err := writeJudgedJSON(stdout, rep, res, *top, lr, seriesOf(res, *withSeries)); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
			if err := renderJudgeTable(stdout, lr); err != nil {
				return err
			}
		}
	}

	if res.Err != nil {
		// The report is complete and the run is not. Say both: the exit code is
		// non-zero so a CI job notices, and the message names how much evidence
		// was salvaged.
		//
		// A zombie is called out separately because its /proc entry still exists:
		// reporting it as "process not found" would send the reader looking for a
		// pid-reuse bug that is not there, and would hide the fact that the
		// process is gone but unreaped.
		if errors.Is(res.Err, probe.ErrProcessExited) {
			return fmt.Errorf("sampling stopped after %d of %d samples: pid %d has exited but has not been reaped "+
				"(a zombie keeps its /proc entry with an empty fd directory, which would otherwise read as "+
				"'every descriptor was released'); report above covers the %d collected",
				res.Snapshots, *samples, pid, rep.Samples)
		}
		return fmt.Errorf("sampling stopped after %d of %d samples: %w (report above covers the %d collected)",
			res.Snapshots, *samples, res.Err, rep.Samples)
	}
	// A leak outranks a clean run but not a failed one: the sampling error above
	// already returned, because an interrupted window is not a verdict at all.
	// ExitLeakFound is what a CI job branches on, so it must come from the same
	// report the reader saw.
	if leaking {
		return errLeakFound
	}
	return nil
}

// watchReport is the JSON shape of a watch run.
//
// The analyze.Report is embedded rather than flattened so the wire format follows
// the analyser's own field names; a translation layer here would drift from the
// library API that embedders use.
type watchReport struct {
	analyze.Report
	Snapshots  int  `json:"snapshots"`
	Incomplete int  `json:"incomplete_snapshots"`
	Truncated  bool `json:"truncated,omitempty"`
	// Totals is the process descriptor total at each retained sample, oldest
	// first, present only when --series asked for it. A verdict that cannot be
	// reproduced from the numbers it was computed on is an opinion, and before this
	// existed a suspicious verdict could only be investigated by re-running the
	// sampler and hoping the shape recurred.
	Totals []int `json:"totals,omitempty"`
}

func buildWatchReport(rep analyze.Report, res probe.WatchResult, top int) watchReport {
	out := watchReport{
		Report:     rep,
		Snapshots:  res.Snapshots,
		Incomplete: res.Incomplete,
	}
	if top > 0 && len(out.Series) > top {
		out.Series = out.Series[:top]
		out.Truncated = true
	}
	return out
}

func writeWatchJSON(w io.Writer, rep analyze.Report, res probe.WatchResult, top int, series []int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	out := buildWatchReport(rep, res, top)
	out.Totals = series
	return enc.Encode(out)
}

// seriesOf returns the per-sample descriptor totals when asked for, or nil.
//
// Nil rather than an empty slice: the field is omitempty, and an empty array would
// say "the run collected no samples" for a run that simply did not ask.
func seriesOf(res probe.WatchResult, want bool) []int {
	if !want {
		return nil
	}
	return res.Timeline.TotalSeries().Counts
}

func writeWatchTable(w io.Writer, rep analyze.Report, res probe.WatchResult, top int) error {
	buf := &errBuffer{}
	if err := renderWatchTable(buf, rep, res, top); err != nil {
		return err
	}
	return buf.flushTo(w)
}

func renderWatchTable(w io.Writer, rep analyze.Report, res probe.WatchResult, top int) error {
	// Every write is checked, and the whole report is rendered into a buffer
	// before the caller sees it: a renderer that ignores write errors prints a
	// truncated series table and exits 0, and a reader then draws conclusions
	// from a table whose bottom rows are missing.
	if _, err := fmt.Fprintf(w, "pid %d  %d samples over %s  total %s\n",
		rep.PID, rep.Samples, time.Duration(rep.SpanMillis)*time.Millisecond, trendWord(rep.Total)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "total descriptors: %d -> %d (min %d, max %d)\n",
		rep.Total.First, rep.Total.Last, rep.Total.Min, rep.Total.Max); err != nil {
		return err
	}
	if rep.Incomplete {
		// The window does not cover the run. Saying so is not optional: "rose
		// from 100 to 140" reads as the whole story, and the earliest change is
		// usually the one that matters.
		if _, err := fmt.Fprintf(w, "warning: %d earlier samples were discarded; the series below cover the most recent %d only\n",
			rep.Dropped, rep.Samples); err != nil {
			return err
		}
	}
	if res.Incomplete > 0 {
		// A partial snapshot is skipped rather than turned into a phantom drop.
		// The gap is disclosed so nobody reads a flat stretch as proof of calm.
		if _, err := fmt.Fprintf(w, "warning: %d of %d snapshots were incomplete and were skipped (a partial read looks like a release)\n",
			res.Incomplete, res.Snapshots); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if len(rep.Series) == 0 {
		if _, err := fmt.Fprintln(w, "no fingerprint was observed in any sample"); err != nil {
			return err
		}
		return nil
	}

	rows := rep.Series
	truncated := false
	if top > 0 && len(rows) > top {
		rows = rows[:top]
		truncated = true
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "TREND\tFIRST\tLAST\tMIN\tMAX\tREBOUND\tKIND\tRESOURCE"); err != nil {
		return err
	}
	for _, row := range rows {
		label := row.Fingerprint
		if kind := fingerprintKindLabel(row.Fingerprint); kind == model.KindDeleted {
			label += "  [deleted, space not freed]"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
			row.Trend, row.First, row.Last, row.Min, row.Max, reboundWord(row), fingerprintKindLabel(row.Fingerprint), label); err != nil {
			return err
		}
	}
	if truncated {
		if _, err := fmt.Fprintf(tw, "\n(limited to top %d of %d series)\n", top, len(rep.Series)); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	// The rebound summary is printed separately because it is the one line that
	// answers the question the user came with. Burying it in a column of numbers
	// leaves the reader to compare min and max across dozens of rows.
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	rebounded := rep.Rebounded()
	if len(rebounded) == 0 {
		if _, err := fmt.Fprintln(w, "no resource rose and then fell back within the window"); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "%d resource(s) rose and then fell back (self-healing, not a leak):\n", len(rebounded)); err != nil {
		return err
	}
	rtw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(rtw, "PEAK\tLOW\tDROP\tRESOURCE"); err != nil {
		return err
	}
	for _, row := range rebounded {
		if _, err := fmt.Fprintf(rtw, "%d\t%d\t%d\t%s\n", row.ReboundFrom, row.ReboundTo, row.Drop(), row.Fingerprint); err != nil {
			return err
		}
	}
	return rtw.Flush()
}

// trendWord renders the total trend with the numbers inline so the header line
// does not need the reader to cross-reference the table.
func trendWord(s analyze.Summary) string {
	return fmt.Sprintf("%s %d -> %d", s.Trend, s.First, s.Last)
}

// reboundWord renders the rebound column.
//
// The column shows the drop, not just a boolean: "yes" invites "how much?", and
// the drop is the number that decides whether the release was meaningful.
func reboundWord(s analyze.Summary) string {
	if !s.Rebound {
		return "-"
	}
	return fmt.Sprintf("-%d (%d->%d)", s.Drop(), s.ReboundFrom, s.ReboundTo)
}

// fingerprintKindLabel derives the kind from the fingerprint prefix.
//
// The normaliser's prefix is the authoritative statement of what a fingerprint
// means (it survives round-tripping, which the payload does not), so the label is
// read from it rather than re-derived from the payload. A mislabelled kind would
// put "deleted" beside a live path, which is the self-contradicting output this
// project has already had to fix once.
func fingerprintKindLabel(fp string) model.FDKind {
	// Delegated to the model rather than re-derived here, because the hand-rolled
	// version disagreed with it: devices keep their raw path as a fingerprint, so
	// "/dev/null" fell through every prefix case and the table printed "unknown"
	// for a descriptor whose kind was never in doubt. Two parsers of one format is
	// how the report and the verdict start describing different things.
	if info, ok := model.DecomposeFingerprint(fp); ok {
		return info.Kind
	}
	return model.KindUnknown
}
