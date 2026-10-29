package attr

import "sort"

// Item is one judged series: what grew, and by how much.
//
// Growth rather than the descriptor count is what the breakdown is weighted by.
// A process holding 900 sockets and 100 log files that leaks 10 sockets has a
// leak that is ten parts socket by count and nothing but socket by growth, and
// only the second number tells a reader where to look.
type Item struct {
	// Fingerprint is the leaked resource.
	Fingerprint string
	// Growth is how many descriptors it added. Negative or zero items are
	// accepted and ignored by the shares, because a caller summing a verdict
	// should not have to filter first.
	Growth int
}

// CategoryAttribution is one row of the leak breakdown: how much of a leak one
// class of resource accounts for.
type CategoryAttribution struct {
	// Category is the class, and NoMatchCategory when nothing covered it.
	Category string `json:"category"`
	// Rule is the rule that named this category; empty when nothing matched.
	Rule string `json:"rule,omitempty"`
	// Why is the evidence sentence, taken from the rule.
	Why string `json:"why"`
	// Confidence is "high" for a matched L1 category and "none" otherwise.
	Confidence Confidence `json:"confidence"`
	// Matched is false for the unattributed bucket.
	Matched bool `json:"matched"`
	// Growth is the descriptors this category added, and Fingerprints how many
	// distinct resources contributed to it.
	Growth       int `json:"growth"`
	Fingerprints int `json:"fingerprints"`
	// Coverage is Growth as a share of the whole leak, in [0,1].
	//
	// It is the number that keeps a partial explanation from reading as a
	// complete one: "log file, 60%" tells the reader that 40% of the leak is
	// something else, while a bare list of categories invites them to assume the
	// list is the whole story.
	Coverage float64 `json:"coverage"`
}

// Summarize groups leaked series into categories, largest share first.
//
// Aggregating is not cosmetic. The verdict already names up to twenty
// fingerprints, and twenty rows of "file:..." is not an answer to "what is
// leaking" - five categories with shares is. The per-series attribution is still
// reported next to each verdict for the reader who wants to see the individual
// resources.
//
// The result is sorted by growth, then category name, so two runs over the same
// input produce byte-identical output. Map iteration order would otherwise leak
// into the JSON and make a report diff useless.
func Summarize(e *Engine, items []Item) []CategoryAttribution {
	if e == nil {
		e = Default()
	}
	type bucket struct {
		row          CategoryAttribution
		bestPriority int
	}
	buckets := make(map[string]*bucket, len(items))
	total := 0

	for _, it := range items {
		if it.Growth <= 0 {
			// Nothing added, nothing to attribute: a zero-growth series would
			// contribute a row with a 0% share, which reads as a category that
			// exists in the leak when it does not.
			continue
		}
		a := e.Attribute(it.Fingerprint)
		total += it.Growth
		b, ok := buckets[a.Category]
		if !ok {
			b = &bucket{row: CategoryAttribution{
				Category:   a.Category,
				Rule:       a.Rule,
				Why:        a.Why,
				Confidence: a.Confidence,
				Matched:    a.Matched,
			}}
			buckets[a.Category] = b
			// A category reached by several rules reports the most specific one,
			// so the evidence sentence stays true for every member: two rules
			// share a category only when they describe the same class, and the
			// higher-priority one is the narrower statement.
			if r, ok := e.Match(mustView(it.Fingerprint)); ok {
				b.bestPriority = r.Priority
			}
			b.row.Growth += it.Growth
			b.row.Fingerprints++
			continue
		}
		b.row.Growth += it.Growth
		b.row.Fingerprints++
		if r, matched := e.Match(mustView(it.Fingerprint)); matched && r.Priority > b.bestPriority {
			b.row.Rule = r.Name
			b.row.Why = r.Why
			b.bestPriority = r.Priority
		}
	}

	out := make([]CategoryAttribution, 0, len(buckets))
	for _, b := range buckets {
		if total > 0 {
			b.row.Coverage = float64(b.row.Growth) / float64(total)
		}
		out = append(out, b.row)
	}
	if len(out) == 0 {
		// nil rather than an empty slice, so that "nothing to attribute" has one
		// representation on the wire and a caller has one thing to check.
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Growth != out[j].Growth {
			return out[i].Growth > out[j].Growth
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// mustView is ViewOf with the failure folded into an empty view.
//
// Summarize has already attributed the fingerprint, so a value that does not
// decompose has already been reported as unattributable; asking again only to
// decide which rule won cannot fail in a new way, and threading a second error
// through the aggregation would give callers two error paths for one input.
func mustView(fp string) View {
	v, _ := ViewOf(fp)
	return v
}
