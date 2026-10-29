// Package attr answers "which class of resource is this?", using nothing but the
// fingerprint.
//
// # What this package is allowed to say
//
// /proc does not record who opened a descriptor. That single fact decides the
// whole design of attribution in fdscope: it is split into three levels of
// decreasing strength, and each level is labelled with what it can prove.
//
//	L1  kind and path   - provable. "These descriptors are sockets." The
//	                      fingerprint says so; no inference is involved.
//	L2  timing          - correlation, not causation. "The count started rising
//	                      when the request rate tripled." Something else could
//	                      have done it.
//	L3  test-time pairs - a sampled snapshot. "In this test run, this goroutine
//	                      was blocked in Read on that descriptor." True for the
//	                      instant it was sampled, and no more.
//
// This package implements L1 only. Everything it reports is a restatement of the
// fingerprint with the vocabulary a reader needs, which is why an L1 attribution
// can be checked by hand with `readlink` and is never wrong in the way an
// inference is wrong.
//
// # What it must not say
//
// No L1 attribution may contain "opened by", "probably", "because of", or any
// other claim about origin. Naming the opener is L2's job at best and L3's at
// worst, and both must carry their weakness into the output. A tool that says
// "the logger is leaking" when it only knows "log files are growing" has traded
// its credibility for one sentence that reads better.
//
// # Rules are data
//
// A rule is a name, a category, a reason, a priority and a predicate over the
// fingerprint. Built-in rules cover the shapes that mean the same thing in every
// process; callers add their own because the interesting categories are
// application-specific ("postgres WAL segment", "shard file for tenant 42") and
// hard-coding those here would be wrong for everyone else.
package attr

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/atop0914/fdscope/internal/model"
)

// Confidence qualifies an attribution.
//
// It is a string rather than an enum so that the value lands in JSON unchanged,
// and it exists even though L1 always reports "high": the field is what a reader
// uses to decide how much weight to give the sentence, and it must already be
// there when L2 starts emitting "medium" for a correlation.
type Confidence string

const (
	// ConfidenceHigh is used by L1, whose claims are restatements of the
	// fingerprint. There is no inference to be wrong about.
	ConfidenceHigh Confidence = "high"
	// ConfidenceNone is used when nothing was attributed. It says there is no
	// claim to qualify, which is different from a weak claim.
	ConfidenceNone Confidence = "none"
)

// NoMatchCategory is the category reported when no rule covers a fingerprint.
//
// It is a value, not an empty string, because an empty string in a report reads
// as "there is nothing to say here" and gets skimmed - while an unattributed
// share of a leak is exactly the part a reader needs to know about. The share is
// reported alongside the named categories so that "60% of the growth is log
// files" cannot be mistaken for "all of it".
const NoMatchCategory = "no rule matched"

// NoMatchWhy explains an unattributed fingerprint. It names the boundary instead
// of apologising for it: the rules are fingerprints-only by construction, so an
// unusual path is simply not covered.
const NoMatchWhy = "no built-in or configured rule covers this fingerprint; " +
	"L1 only sees kind and path, so nothing is inferred"

// View is what a rule may look at: the parts of a fingerprint, and nothing else.
//
// The restriction is the implementation of the L1 boundary. A rule cannot reach
// the filesystem, the clock or the process through this struct, so it cannot
// accidentally turn a restatement into an inference.
type View struct {
	// Fingerprint is the value being attributed, for error messages and so a
	// rule can match on the exact string when a caller needs that.
	Fingerprint string
	// Scheme is the fingerprint namespace: "file", "deleted", "socket", "pipe",
	// "anon_inode", or "" for a device, which keeps its raw path.
	Scheme string
	// Kind is the descriptor kind the fingerprint asserts.
	Kind model.FDKind
	// Path is the normalised filesystem path, empty for sockets, pipes and
	// anonymous inodes. It is not stat-ed and may no longer exist.
	Path string
	// Name is the anonymous-inode payload ("eventpoll", "inotify"), empty
	// otherwise.
	Name string
	// Deleted reports that the file was unlinked while still held open.
	Deleted bool
}

// ViewOf builds the view a rule sees from a fingerprint.
//
// The second result is false when the value is not a fingerprint at all. Callers
// must report that as "not attributable" rather than picking a kind: a guessed
// kind is what a false attribution is made of.
func ViewOf(fp string) (View, bool) {
	info, ok := model.DecomposeFingerprint(fp)
	if !ok {
		return View{}, false
	}
	v := View{
		Fingerprint: fp,
		Scheme:      info.Scheme,
		Kind:        info.Kind,
		Deleted:     info.Deleted,
	}
	switch info.Scheme {
	case "anon_inode":
		v.Name = info.Payload
	default:
		// "file", "deleted" and the scheme-less device form all carry a path.
		v.Path = info.Path()
	}
	return v, true
}

// Rule is one classification.
//
// Match is a predicate rather than a pattern list because the built-in rules need
// real logic (does any path segment name a log directory?) and a pattern engine
// general enough to express that would be a language nobody asked for. Configured
// rules are compiled from their declarative form into a Rule, so both kinds end
// up as the same value and the engine has one code path.
type Rule struct {
	// Name identifies the rule in output and in error messages. It must be
	// unique among a rule set, because "which rule said this" is the first
	// question asked about a surprising attribution.
	Name string
	// Category is the human-facing class, e.g. "log file". Two rules may share
	// a category: the report aggregates by category, so a built-in and a user
	// rule that both describe log files land in one row.
	Category string
	// Why explains what the fingerprint showed that made this rule match. It is
	// printed next to the category, so it must stand alone.
	Why string
	// Priority orders rules from specific to general. Higher wins when several
	// rules match one fingerprint, and the winner is reported - never silently
	// dropped, and never merged with the others.
	Priority int
	// Match reports whether v belongs to this rule.
	Match func(View) bool
}

// Attribution is the answer for one fingerprint.
type Attribution struct {
	// Fingerprint is the attributed resource.
	Fingerprint string `json:"fingerprint"`
	// Matched is false when no rule covered the fingerprint. It is stated
	// separately from Category so a reader (or a jq filter) can branch without
	// string-matching the category.
	Matched bool `json:"matched"`
	// Rule is the name of the rule that matched, empty when none did.
	Rule string `json:"rule,omitempty"`
	// Category is never empty: NoMatchCategory when nothing matched.
	Category string `json:"category"`
	// Why is the evidence sentence behind the category.
	Why string `json:"why"`
	// Confidence is "high" for L1 and "none" when nothing was attributed.
	Confidence Confidence `json:"confidence"`
}

// Describe renders an attribution as one line for humans.
//
// Unmatched fingerprints get a sentence rather than a blank column. A blank
// column in a table of leaks reads as "fine", which is the one reading that is
// certainly wrong: an unattributed share of a leak is the part nobody has
// explained yet.
func (a Attribution) Describe() string {
	if !a.Matched {
		return NoMatchCategory + " (" + a.Fingerprint + ")"
	}
	return a.Category + " - " + a.Why
}

// Engine matches fingerprints against a rule set.
//
// The rules are sorted once at construction and never mutated, so an Engine is
// safe to share between goroutines and cheap to reuse across samples. That
// matters for `watch`, which attributes on every report but must not pay for
// sorting each time.
type Engine struct {
	rules []Rule
}

// Default returns the engine with the built-in rules only.
//
// Built-in rules are constructed from code that cannot fail, so the signature
// returns no error: a caller that has to handle an impossible error ends up
// ignoring it, and an ignored error at construction is how a tool starts with an
// empty rule set and reports "no rule matched" for everything.
func Default() *Engine { return &Engine{rules: sortedRules(builtinRules)} }

// New builds an engine from the built-in rules plus extra, with extra winning
// ties.
//
// A user rule that matches must beat a built-in one, otherwise configuring it
// appears to do nothing - which is the exact "I added a rule and it did not take
// effect" mystery the loader refuses to create. Extra rules are therefore placed
// ahead of the built-ins at equal priority; their own priorities (all at or above
// UserRulePriority) already make them win outright in practice.
func New(extra []Rule) (*Engine, error) {
	all := make([]Rule, 0, len(extra)+len(builtinRules))
	for i, r := range extra {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		all = append(all, r)
	}
	for _, r := range builtinRules {
		all = append(all, r)
	}
	// Duplicate names are rejected rather than tolerated: two rules with one
	// name make "rule: x matched" ambiguous in the report, and the reader has no
	// way to tell which of them ran.
	names := make(map[string]bool, len(all))
	for _, r := range all {
		if names[r.Name] {
			return nil, fmt.Errorf("duplicate rule name %q", r.Name)
		}
		names[r.Name] = true
	}
	return &Engine{rules: sortedRules(all)}, nil
}

// Rules returns the rule set in the order it is consulted.
//
// The slice is a copy: an exported field would let a caller reorder the rules
// after construction and silently change every later attribution.
func (e *Engine) Rules() []Rule {
	if e == nil {
		return Default().Rules()
	}
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Match returns the highest-priority rule covering v.
//
// Only one rule is reported even when several match, and which one wins is
// decided by Priority alone (declaration order breaks ties). Reporting all of
// them would put three rows in the output for one resource and make the reader
// do the ranking; picking the first match in declaration order would make the
// answer depend on how the rule file was sorted.
func (e *Engine) Match(v View) (Rule, bool) {
	if e == nil {
		e = Default()
	}
	for _, r := range e.rules {
		if r.Match(v) {
			return r, true
		}
	}
	return Rule{}, false
}

// Attribute classifies one fingerprint.
func (e *Engine) Attribute(fp string) Attribution {
	v, ok := ViewOf(fp)
	if !ok {
		// Not a fingerprint at all. Saying "no rule matched" would blame the
		// rule set for a malformed input, so the reason names the input.
		return Attribution{
			Fingerprint: fp,
			Category:    NoMatchCategory,
			Why:         "not a fingerprint fdscope can decompose, so nothing may be claimed about it",
			Confidence:  ConfidenceNone,
		}
	}
	r, ok := e.Match(v)
	if !ok {
		return Attribution{
			Fingerprint: fp,
			Category:    NoMatchCategory,
			Why:         NoMatchWhy,
			Confidence:  ConfidenceNone,
		}
	}
	return Attribution{
		Fingerprint: fp,
		Matched:     true,
		Rule:        r.Name,
		Category:    r.Category,
		Why:         r.Why,
		Confidence:  ConfidenceHigh,
	}
}

// validate rejects a rule that would misbehave silently.
//
// Every check here guards a failure that would not raise an error at run time: an
// empty predicate matches everything, an empty category prints a blank column, an
// empty name makes the report unactionable, and a non-positive priority makes the
// ordering depend on the sort implementation.
func (r Rule) validate() error {
	switch {
	case strings.TrimSpace(r.Name) == "":
		return errors.New("rule has no name")
	case strings.TrimSpace(r.Category) == "":
		return fmt.Errorf("rule %q has no category", r.Name)
	case strings.TrimSpace(r.Why) == "":
		return fmt.Errorf("rule %q has no reason; an attribution without its evidence is an opinion", r.Name)
	case r.Match == nil:
		return fmt.Errorf("rule %q has no predicate; it would match nothing", r.Name)
	case r.Priority <= 0:
		return fmt.Errorf("rule %q has priority %d; priorities must be positive so the order is defined", r.Name, r.Priority)
	}
	return nil
}

// sortedRules orders rules from specific to general.
//
// The sort is stable so that two rules of equal priority keep the order they were
// declared in: a rule file is a document a human wrote, and its order is the only
// tie-break the author controls.
func sortedRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })
	return out
}
