package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	fdscope "github.com/atop0914/fdscope/pkg/fdscope"
)

// runCheck is the gate: one window, one verdict, three exit codes.
//
// It is deliberately the smallest of the subcommands, because everything it needs
// already exists - the sampler, the thresholds and the judgement are the ones
// `watch --judge` uses, reached through the library so there is exactly one
// implementation of the verdict. What `check` adds is the contract a CI job needs:
//
//	0  judged, no leak
//	2  judged, leak found
//	1  not judged at all - no such process, the process died mid-window, or a
//	   window too short to separate a warming pool from a leak
//
// The third code is the point of the command. A gate that answered "no leak" when
// it could not measure anything would pass every job that happened to break its
// target, which is the failure mode nobody notices until the incident.
func runCheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	interval := fs.Duration("interval", fdscope.DefaultCheckInterval, "delay between samples")
	samples := fs.Int("samples", fdscope.DefaultCheckSamples, "how many samples to take")

	// Thresholds start from the library defaults and are only replaced when the
	// caller asks: the defaults are the tested ones, and a flag whose default is
	// "0 means something else" is how a report starts printing numbers that were
	// never used.
	leak := fdscope.DefaultLeakOptions()
	minGrowth := fs.Int("min-growth", 0, "absolute descriptor rise a leak must show (0 = default)")
	minRatio := fs.Float64("min-growth-ratio", 0, "relative rise as a fraction of the baseline (0 = default)")
	minRate := fs.Float64("min-rate", 0, "sustained rise in descriptors per second (0 = default)")
	minWindow := fs.Duration("min-window", 0, "shortest window that can yield high confidence (0 = default)")

	keepDir := fs.Bool("keep-dir", true, "keep directory components in fingerprints")
	stripRotation := fs.Bool("strip-rotation", true, "merge rotated log files into one fingerprint")
	attrRules := fs.String("attr-rules", "", "JSON file of attribution rules to add to the built-in ones")

	args, positionals := splitFlags(args, fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	positionals = append(positionals, fs.Args()...)
	if len(positionals) != 1 {
		return fmt.Errorf("check requires exactly one pid, got %d", len(positionals))
	}
	pid, err := strconv.Atoi(positionals[0])
	if err != nil {
		return fmt.Errorf("invalid pid %q: %w", positionals[0], err)
	}
	if *interval <= 0 {
		return fmt.Errorf("--interval must be positive, got %s", *interval)
	}
	if *samples < 2 {
		// Not the judgement's minimum - that is higher, and the analyser refuses
		// below it. This is the floor where a series exists at all.
		return fmt.Errorf("--samples must be at least 2 to form a series, got %d", *samples)
	}
	if *minGrowth < 0 {
		return errors.New("--min-growth must not be negative")
	}
	if *minRatio < 0 {
		return errors.New("--min-growth-ratio must not be negative")
	}
	if *minRate < 0 {
		return errors.New("--min-rate must not be negative")
	}
	if *minWindow < 0 {
		return errors.New("--min-window must not be negative")
	}
	if *minGrowth > 0 {
		leak.MinGrowth = *minGrowth
	}
	if *minRatio > 0 {
		leak.MinGrowthRatio = *minRatio
	}
	if *minRate > 0 {
		leak.MinRatePerSecond = *minRate
	}
	if *minWindow > 0 {
		leak.MinWindowMillis = int64(*minWindow / time.Millisecond)
	}

	// The rule file is read before sampling starts, and a bad one ends the run
	// here. Reading it later would mean spending a five second window and then
	// failing - or, worse, reporting with rules the operator thinks are in effect
	// but are not.
	engine, err := fdscope.LoadAttrEngine(*attrRules)
	if err != nil {
		return err
	}

	n := fdscope.NewNormalizer()
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		n.HomeDir = home
	}
	n.KeepDir = *keepDir
	n.StripRotation = *stripRotation

	opts := fdscope.DefaultCheckOptions()
	opts.Interval = *interval
	opts.Samples = *samples
	opts.Leak = leak
	opts.Leak.Attr = engine
	opts.Normalizer = &n

	res, err := fdscope.CheckPID(pid, opts)
	if err != nil {
		// Every one of these is exit 1 and never exit 2: "could not measure" and
		// "measured a leak" are different answers, and a CI job that treated them
		// as the same would either fail on a typo or pass on a broken target.
		return err
	}

	var renderErr error
	if *asJSON {
		renderErr = writeCheckJSON(stdout, res, leak)
	} else {
		renderErr = writeCheckTable(stdout, res, leak)
	}
	if renderErr != nil {
		return renderErr
	}
	if res.Leaking() {
		// The exit code comes from the same report the reader saw, so the word on
		// screen and the status a CI job branches on cannot disagree.
		return errLeakFound
	}
	return nil
}

// checkThresholds is the resolved threshold set as it appears on the wire.
//
// It is a separate type from fdscope.LeakOptions so the JSON keeps the snake_case
// names the rest of the format uses; the values are the ones actually applied,
// not the flags as typed, because "0 means default" is only meaningful to the
// code that fills the defaults in.
type checkThresholds struct {
	MinGrowth        int     `json:"min_growth"`
	MinGrowthRatio   float64 `json:"min_growth_ratio"`
	MinRatePerSecond float64 `json:"min_rate_per_second"`
	MinWindowMillis  int64   `json:"min_window_millis"`
	MinSamples       int     `json:"min_samples"`
	Warmup           float64 `json:"warmup"`
}

// checkReport is the JSON shape of `check`.
//
// The verdict is nested rather than flattened so it keeps the field names
// `watch --judge --json` already uses; a caller that parses one can parse the
// other with a different top-level key.
type checkReport struct {
	PID            int             `json:"pid"`
	IntervalMillis int64           `json:"interval_millis"`
	Snapshots      int             `json:"snapshots"`
	Incomplete     int             `json:"incomplete_snapshots"`
	WindowMillis   int64           `json:"window_millis"`
	Thresholds     checkThresholds `json:"thresholds"`
	// Totals is the process descriptor total at each sample. It is always
	// present, unlike on `watch`: a check is the document a CI job keeps, and a
	// verdict nobody can reproduce from its own input is an opinion.
	Totals []int `json:"totals"`
	// Headroom is the distance to the soft limit at the end of the window, and
	// Projection is the same series' extrapolation. Both are hoisted from the
	// verdict so a CI job does not have to know which series the process total
	// was called; they are copies of verdict.total's values, not a second
	// computation that could disagree with it.
	Headroom   fdscope.Headroom   `json:"headroom"`
	Projection fdscope.Projection `json:"projection"`
	// Attribution is the leak breakdown, hoisted from verdict.attribution for the
	// same reason as Headroom and Projection: a CI job reading one field should
	// not have to know that the process total is not a resource. It is a copy of
	// the verdict's rows, not a second computation that could disagree with them.
	Attribution []fdscope.CategoryAttribution `json:"attribution,omitempty"`
	// Correlations is the L2 block, hoisted from verdict.correlations for the same
	// reason as Attribution: a CI job reading one field should not have to know where
	// inside the verdict it lives. The rows are the verdict's own, not a second
	// computation that could disagree with them.
	Correlations      []fdscope.Correlation `json:"correlations,omitempty"`
	CorrelationAnchor string                `json:"correlation_anchor,omitempty"`
	CorrelationOnset  int                   `json:"correlation_onset,omitempty"`
	CorrelationNotes  []string              `json:"correlation_notes,omitempty"`
	Verdict           fdscope.LeakReport    `json:"verdict"`
	Summary           string                `json:"summary"`
}

func buildCheckReport(res fdscope.CheckResult, leak fdscope.LeakOptions) checkReport {
	return checkReport{
		PID:            res.PID,
		IntervalMillis: res.Interval.Milliseconds(),
		Snapshots:      res.Snapshots,
		Incomplete:     res.Incomplete,
		WindowMillis:   res.Report.WindowMillis,
		Thresholds: checkThresholds{
			MinGrowth:        leak.MinGrowth,
			MinGrowthRatio:   leak.MinGrowthRatio,
			MinRatePerSecond: leak.MinRatePerSecond,
			MinWindowMillis:  leak.MinWindowMillis,
			MinSamples:       leak.MinSamples,
			Warmup:           leak.Warmup,
		},
		Totals:            res.Totals,
		Headroom:          res.Headroom,
		Projection:        res.Report.Total.Projection,
		Attribution:       res.Report.Attribution,
		Correlations:      res.Report.Correlations,
		CorrelationAnchor: res.Report.CorrelationAnchor,
		CorrelationOnset:  res.Report.CorrelationOnset,
		CorrelationNotes:  res.Report.CorrelationNotes,
		Verdict:           res.Report,
		Summary:           fdscope.Summarize(res.Report),
	}
}

func writeCheckJSON(w io.Writer, res fdscope.CheckResult, leak fdscope.LeakOptions) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(buildCheckReport(res, leak))
}

func writeCheckTable(w io.Writer, res fdscope.CheckResult, leak fdscope.LeakOptions) error {
	buf := &errBuffer{}
	if err := renderCheckTable(buf, res, leak); err != nil {
		return err
	}
	return buf.flushTo(w)
}

func renderCheckTable(w io.Writer, res fdscope.CheckResult, leak fdscope.LeakOptions) error {
	// Every write is checked and the whole report is buffered: a renderer that
	// ignores write errors prints half a verdict and exits 0, and a truncated
	// verdict on a CI log reads as a clean run.
	if _, err := fmt.Fprintf(w, "pid %d  check  interval %s\n", res.PID, res.Interval); err != nil {
		return err
	}
	// The window length is not repeated here: the verdict block below prints it
	// with the span actually measured, and two nearly equal numbers invite the
	// reader to compare them instead of reading either.
	if _, err := fmt.Fprintf(w, "thresholds: rise >= %d and >= %.0f%% of baseline, rate >= %.3f/s, high confidence from %dms\n",
		leak.MinGrowth, leak.MinGrowthRatio*100, leak.MinRatePerSecond, leak.MinWindowMillis); err != nil {
		return err
	}
	if res.Incomplete > 0 {
		// A partial read looks exactly like a release, so it is skipped rather
		// than counted - and the gap is disclosed, because a flat stretch next to
		// an undisclosed gap is not evidence of calm.
		if _, err := fmt.Fprintf(w, "warning: %d of %d snapshots were incomplete and were skipped\n",
			res.Incomplete, res.Snapshots); err != nil {
			return err
		}
	}
	// The series is printed next to the verdict on purpose. Every wrong verdict
	// this project has found was found by seeing the shape and the conclusion side
	// by side; a conclusion on its own cannot be disagreed with.
	if _, err := fmt.Fprintf(w, "totals: %s\n\n", seriesLine(res.Totals)); err != nil {
		return err
	}
	return renderJudgeTable(w, res.Report)
}

// seriesLine renders the per-sample totals on one line, truncating the middle of a
// long run.
//
// The truncation is stated with both the count of omitted samples and where to
// find them: a silently shortened series would read as the whole window.
func seriesLine(vals []int) string {
	const limit = 40
	if len(vals) <= limit {
		return joinInts(vals)
	}
	half := limit / 2
	return fmt.Sprintf("%s ... (%d samples omitted; --json has all) ... %s",
		joinInts(vals[:half]), len(vals)-limit, joinInts(vals[len(vals)-half:]))
}

func joinInts(vals []int) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, " ")
}
