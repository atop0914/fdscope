package attr

import (
	"math"
	"testing"
)

// TestSummarizeSharesAddUp is the coverage assertion.
//
// Coverage is what keeps a partial explanation from reading as a complete one, so
// it has to be close to the truth: the shares of a breakdown must sum to 1 when
// every item carried growth, and each row's share must match its own growth over
// the total.
func TestSummarizeSharesAddUp(t *testing.T) {
	items := []Item{
		{Fingerprint: "file:/var/log/app.log", Growth: 20},
		{Fingerprint: "file:/var/log/access.log", Growth: 10},
		{Fingerprint: "socket", Growth: 10},
		{Fingerprint: "file:/srv/app/state.db", Growth: 10},
	}
	rows := Summarize(Default(), items)
	if len(rows) != 3 {
		t.Fatalf("got %d categories, want 3: %+v", len(rows), rows)
	}
	var sum float64
	for _, r := range rows {
		sum += r.Coverage
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("shares sum to %v, want 1", sum)
	}

	// Largest share first, and the two log files merged into one row.
	if rows[0].Category != "log file" {
		t.Fatalf("first row = %q, want %q", rows[0].Category, "log file")
	}
	if rows[0].Growth != 30 || rows[0].Fingerprints != 2 {
		t.Errorf("log row = growth %d / %d fingerprints, want 30 / 2", rows[0].Growth, rows[0].Fingerprints)
	}
	if math.Abs(rows[0].Coverage-0.6) > 1e-9 {
		t.Errorf("log coverage = %v, want 0.6", rows[0].Coverage)
	}
	if !rows[0].Matched || rows[0].Rule != "log-file" {
		t.Errorf("log row = matched %t rule %q, want true / log-file", rows[0].Matched, rows[0].Rule)
	}

	// The unmatched share is reported as its own row rather than dropped: 20% of
	// this leak has no explanation, and a report that omitted it would suggest the
	// named categories cover everything.
	var unmatched *CategoryAttribution
	for i := range rows {
		if rows[i].Category == NoMatchCategory {
			unmatched = &rows[i]
		}
	}
	if unmatched == nil {
		t.Fatalf("no %q row in %+v", NoMatchCategory, rows)
	}
	last := *unmatched
	if math.Abs(last.Coverage-0.2) > 1e-9 {
		t.Errorf("unmatched coverage = %v, want 0.2", last.Coverage)
	}
	if last.Matched {
		t.Error("the unmatched row claims to be matched")
	}
}

// TestSummarizeIgnoresNonGrowth keeps zero and negative series out of the
// breakdown. A row with a 0% share is a category that is not in the leak, and
// showing it invites the reader to go and look at it.
func TestSummarizeIgnoresNonGrowth(t *testing.T) {
	items := []Item{
		{Fingerprint: "file:/var/log/app.log", Growth: 5},
		{Fingerprint: "socket", Growth: 0},
		{Fingerprint: "pipe", Growth: -3},
	}
	rows := Summarize(Default(), items)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Category != "log file" || rows[0].Coverage != 1 {
		t.Errorf("row = %+v, want log file at 100%%", rows[0])
	}

	if got := Summarize(Default(), nil); got != nil {
		t.Errorf("Summarize(nil) = %+v, want nil", got)
	}
}

// TestSummarizeIsDeterministic pins the ordering. The buckets live in a map, so
// without an explicit sort the JSON row order would change between runs and every
// diff of two reports would be noise.
func TestSummarizeIsDeterministic(t *testing.T) {
	items := []Item{
		{Fingerprint: "socket", Growth: 10},
		{Fingerprint: "pipe", Growth: 10},
		{Fingerprint: "file:/tmp/x", Growth: 10},
	}
	first := Summarize(Default(), items)
	for i := 0; i < 20; i++ {
		again := Summarize(Default(), items)
		for j := range first {
			if first[j] != again[j] {
				t.Fatalf("run %d row %d = %+v, first run = %+v", i, j, again[j], first[j])
			}
		}
	}
	// Equal growth breaks ties by category name, so the order is stated and not
	// left to map iteration.
	if first[0].Category != "pipe" || first[1].Category != "socket" || first[2].Category != "temporary file" {
		t.Errorf("order = %q, %q, %q; want pipe, socket, temporary file",
			first[0].Category, first[1].Category, first[2].Category)
	}
}

// TestSummarizePrefersTheMoreSpecificRuleForACategory covers a category reached by
// several fingerprints of different specificity. The evidence sentence must be the
// narrow one, so that it is true for every member of the bucket.
func TestSummarizePrefersTheMoreSpecificRuleForACategory(t *testing.T) {
	custom, err := New([]Rule{{
		Name:     "app-log",
		Category: "log file",
		Why:      "a .log file under /srv/app, which this deployment uses for its audit trail",
		Priority: UserRulePriority,
		Match:    func(v View) bool { return v.Path == "/srv/app/audit.log" },
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rows := Summarize(custom, []Item{
		{Fingerprint: "file:/var/log/app.log", Growth: 10},
		{Fingerprint: "file:/srv/app/audit.log", Growth: 10},
	})
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Rule != "app-log" {
		t.Errorf("rule = %q, want app-log: the more specific rule names the bucket", rows[0].Rule)
	}
	if rows[0].Fingerprints != 2 {
		t.Errorf("fingerprints = %d, want 2", rows[0].Fingerprints)
	}
}
