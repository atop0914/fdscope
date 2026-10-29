package analyze

import (
	"math"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/attr"
)

// attrInterval is the sample spacing of every fixture here: 25 samples 200ms apart
// is exactly the window `check` takes by default.
const attrInterval = 200 * time.Millisecond

// verdictFor returns the series verdict for fp.
func verdictFor(t *testing.T, rep LeakReport, fp string) LeakVerdict {
	t.Helper()
	for _, v := range rep.Series {
		if v.Fingerprint == fp {
			return v
		}
	}
	t.Fatalf("no verdict for %q in %+v", fp, rep.Series)
	return LeakVerdict{}
}

// TestJudgeAttributesLeakedSeries is the attribution wiring assertion.
//
// It covers both directions in one run: a leaked series must carry a category, and
// a series that did not leak must carry nothing. The second half is the one that
// keeps the report readable - attributing a flat resource produces a row that
// answers a question nobody asked.
func TestJudgeAttributesLeakedSeries(t *testing.T) {
	const logFP = "file:/var/log/app.log"
	const sockFP = "socket"
	const flatFP = "file:/srv/app/state.db"

	tl := seriesOf(t, map[string][]int{
		logFP:  ramp(0, 40, 25),
		sockFP: ramp(0, 20, 25),
		flatFP: fill(6, 25),
	}, attrInterval)

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if !rep.Leaking {
		t.Fatalf("the fixture did not leak: total = %+v", rep.Total.Reason)
	}

	logV := verdictFor(t, rep, logFP)
	if !logV.Leak {
		t.Fatalf("%s was not judged a leak: %s", logFP, logV.Reason)
	}
	if logV.Attribution == nil {
		t.Fatalf("%s leaked but carries no attribution", logFP)
	}
	if logV.Attribution.Category != "log file" || logV.Attribution.Rule != "log-file" {
		t.Errorf("%s attribution = %q / %q, want log file / log-file",
			logFP, logV.Attribution.Category, logV.Attribution.Rule)
	}
	if logV.Attribution.Confidence != attr.ConfidenceHigh {
		t.Errorf("%s attribution confidence = %q, want high", logFP, logV.Attribution.Confidence)
	}

	sockV := verdictFor(t, rep, sockFP)
	if !sockV.Leak || sockV.Attribution == nil {
		t.Fatalf("%s: leak %t, attribution %v", sockFP, sockV.Leak, sockV.Attribution)
	}
	if sockV.Attribution.Category != "socket" {
		t.Errorf("%s attribution = %q, want socket", sockFP, sockV.Attribution.Category)
	}

	// Reverse assertion: no growth, no explanation.
	flatV := verdictFor(t, rep, flatFP)
	if flatV.Leak {
		t.Fatalf("%s was judged a leak: %s", flatFP, flatV.Reason)
	}
	if flatV.Attribution != nil {
		t.Errorf("%s did not leak but was attributed %q: explaining a flat resource is noise",
			flatFP, flatV.Attribution.Category)
	}

	// The process total is a sum, not a resource, so it is never attributed.
	if rep.Total.Attribution != nil {
		t.Errorf("the process total was attributed %q", rep.Total.Attribution.Category)
	}

	if len(rep.Attribution) != 2 {
		t.Fatalf("got %d breakdown rows, want 2: %+v", len(rep.Attribution), rep.Attribution)
	}
	// The shares are recomputed from the verdicts' own growth numbers, so a
	// breakdown computed over a different quantity fails here instead of looking
	// plausible.
	total := float64(logV.Evidence.Growth + sockV.Evidence.Growth)
	for _, row := range rep.Attribution {
		switch row.Category {
		case "log file":
			if want := float64(logV.Evidence.Growth) / total; math.Abs(row.Coverage-want) > 1e-9 {
				t.Errorf("log coverage = %v, want %v (growth %d of %v)", row.Coverage, want, logV.Evidence.Growth, total)
			}
		case "socket":
			if want := float64(sockV.Evidence.Growth) / total; math.Abs(row.Coverage-want) > 1e-9 {
				t.Errorf("socket coverage = %v, want %v", row.Coverage, want)
			}
		default:
			t.Errorf("unexpected category %q in the breakdown", row.Category)
		}
	}
	var sum float64
	for _, row := range rep.Attribution {
		sum += row.Coverage
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("shares sum to %v, want 1", sum)
	}
}

// TestJudgeAttributesTheUnattributedShare covers the honest half of the breakdown:
// a leak whose resource no rule knows is reported as unattributed, with its share
// of the growth, rather than silently dropped.
func TestJudgeAttributesTheUnattributedShare(t *testing.T) {
	const unknownFP = "file:/srv/app/state.db"
	tl := seriesOf(t, map[string][]int{unknownFP: ramp(0, 40, 25)}, attrInterval)

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	v := verdictFor(t, rep, unknownFP)
	if !v.Leak {
		t.Fatalf("%s was not judged a leak: %s", unknownFP, v.Reason)
	}
	if v.Attribution == nil {
		t.Fatal("a leaked series carries no attribution at all; the boundary must be stated")
	}
	if v.Attribution.Matched {
		t.Errorf("attribution claimed a match: %q", v.Attribution.Category)
	}
	if v.Attribution.Category != attr.NoMatchCategory {
		t.Errorf("category = %q, want %q", v.Attribution.Category, attr.NoMatchCategory)
	}
	if len(rep.Attribution) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rep.Attribution), rep.Attribution)
	}
	if rep.Attribution[0].Matched || rep.Attribution[0].Coverage != 1 {
		t.Errorf("row = %+v, want an unmatched row covering the whole leak", rep.Attribution[0])
	}
}

// TestJudgeReportsNoAttributionWithoutALeak is the reverse assertion at the report
// level: a clean run carries no attribution key at all, so "attribution: []" can
// never be read as "attributed nothing, must be fine".
func TestJudgeReportsNoAttributionWithoutALeak(t *testing.T) {
	tl := seriesOf(t, map[string][]int{
		"file:/var/log/app.log": fill(10, 25),
		"socket":                fill(4, 25),
	}, attrInterval)

	rep, err := Judge(tl, DefaultLeakOptions())
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if rep.Leaking {
		t.Fatalf("the flat fixture was judged a leak: %s", rep.Total.Reason)
	}
	if rep.Attribution != nil {
		t.Errorf("a clean run produced an attribution breakdown: %+v", rep.Attribution)
	}
	for _, v := range rep.Series {
		if v.Attribution != nil {
			t.Errorf("%s carries an attribution on a clean run", v.Fingerprint)
		}
	}
}

// TestJudgeUsesTheConfiguredEngine proves the option is wired, not merely stored:
// the same fixture produces a different category once a rule file is in effect.
func TestJudgeUsesTheConfiguredEngine(t *testing.T) {
	const fp = "file:/srv/app/shards/0001.db"
	tl := seriesOf(t, map[string][]int{fp: ramp(0, 40, 25)}, attrInterval)
	opts := DefaultLeakOptions()

	// Baseline: the built-in rules do not know this path.
	rep, err := Judge(tl, opts)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if got := verdictFor(t, rep, fp).Attribution.Category; got != attr.NoMatchCategory {
		t.Fatalf("baseline category = %q, want %q", got, attr.NoMatchCategory)
	}

	rules, err := attr.Parse([]byte(`{"version": 1, "rules": [{
	  "name": "shard-open",
	  "category": "shard file",
	  "why": "one of this deployment's shard files, held open per query",
	  "path_prefix": ["/srv/app/shards/"]
	}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	engine, err := attr.New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	opts.Attr = engine

	rep, err = Judge(tl, opts)
	if err != nil {
		t.Fatalf("Judge with engine: %v", err)
	}
	v := verdictFor(t, rep, fp)
	if v.Attribution == nil || v.Attribution.Category != "shard file" {
		t.Errorf("configured category = %v, want shard file", v.Attribution)
	}
	if len(rep.Attribution) != 1 || rep.Attribution[0].Rule != "shard-open" {
		t.Errorf("breakdown = %+v, want one row from shard-open", rep.Attribution)
	}
}
