package attr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/atop0914/fdscope/internal/model"
)

// The configuration file is JSON because the project has no third-party
// dependencies and will not grow one for a config parser: encoding/json is in the
// standard library, and the declarative rules below are simple enough that a
// richer format would buy nothing.
//
// The format is deliberately strict. Every failure mode that could otherwise be
// silent - a misspelled field, a predicate that matches everything, an empty rule
// list - is rejected with the line it is on. A permissive loader turns "I added a
// rule and nothing changed" into a mystery with no error message, and that
// mystery is what makes people stop using the flag.

// ruleFile is the document shape.
type ruleFile struct {
	// Version is the format version. It exists so a future change can refuse an
	// old file instead of reinterpreting it, which is the only way a config
	// format ages without silently changing meaning.
	Version int `json:"version"`
	// Rules are the rules to add. They are consulted before the built-in ones.
	Rules []ruleSpec `json:"rules"`
}

// ruleSpec is one declarative rule.
//
// Every predicate is optional; a rule must specify at least one, and all the ones
// it does specify must hold. Within one predicate the values are alternatives -
// path_prefix ["/var/log", "/logs"] means either - because that is the only
// reading that makes a list useful, and because "all of these prefixes" would be
// unsatisfiable for a single path.
type ruleSpec struct {
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	Why          string   `json:"why"`
	Priority     int      `json:"priority"`
	Kind         []string `json:"kind"`
	Scheme       []string `json:"scheme"`
	PathPrefix   []string `json:"path_prefix"`
	PathSuffix   []string `json:"path_suffix"`
	PathContains []string `json:"path_contains"`
	// Deleted is a pointer so that "not configured" and "configured false" are
	// distinguishable: with a plain bool, a rule that requires a live file would
	// also match every unlinked one, which is the opposite of what its author
	// wrote.
	Deleted *bool `json:"deleted"`
}

// emitKinds are the kinds a fingerprint can actually carry.
//
// dir and unknown are valid model values but no fingerprint is ever emitted with
// them, so a rule restricting on either would never fire. Accepting them would
// produce exactly the silent no-op this loader exists to prevent.
var emitKinds = map[string]model.FDKind{
	"file":       model.KindFile,
	"deleted":    model.KindDeleted,
	"device":     model.KindDevice,
	"socket":     model.KindSocket,
	"pipe":       model.KindPipe,
	"anon_inode": model.KindAnonInode,
}

// LoadEngine builds an engine, reading user rules from path when one is given.
//
// One entry point for both callers, because the two steps have to happen in one
// order: load, then merge over the built-ins. A caller that did the second without
// the first would run with the built-ins only while believing its file was in use.
func LoadEngine(path string) (*Engine, error) {
	if path == "" {
		return Default(), nil
	}
	rules, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	return New(rules)
}

// LoadFile reads and compiles a rule file.
func LoadFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading attribution rules: %w", err)
	}
	rules, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rules, nil
}

// Parse compiles a rule file from bytes.
//
// Every error names the line it was found on. That is not a nicety: a rule file is
// edited by hand, often over ssh, and "invalid character '}' looking for beginning
// of object" without a position sends the reader to read the whole file while a
// line number sends them to the typo.
func Parse(data []byte) ([]Rule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	// Unknown fields are an error, not a warning. "path_prefx" would otherwise
	// parse into a rule with no path predicate - which either matches nothing or,
	// worse, matches everything - and the user would conclude the feature is
	// broken rather than that the key is misspelled.
	dec.DisallowUnknownFields()

	var doc ruleFile
	if err := dec.Decode(&doc); err != nil {
		return nil, atLine(data, err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version %d: this build understands version 1", doc.Version)
	}
	if len(doc.Rules) == 0 {
		return nil, errors.New(`the file defines no rules: an empty "rules" list would change nothing, so it is reported rather than ignored`)
	}

	out := make([]Rule, 0, len(doc.Rules))
	for i, spec := range doc.Rules {
		r, err := spec.compile()
		if err != nil {
			return nil, fmt.Errorf("rule %d (%q): %w", i+1, spec.Name, err)
		}
		// The shared validation runs here too, not only in New: a file whose rules
		// have no reason or no name would otherwise load cleanly and only fail
		// when the engine is constructed, which is a worse place to learn about it.
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// compile turns one declarative rule into a predicate.
func (s ruleSpec) compile() (Rule, error) {
	if s.Priority < 0 {
		return Rule{}, fmt.Errorf("priority must not be negative, got %d", s.Priority)
	}

	var predicates []func(View) bool

	if len(s.Kind) > 0 {
		want := make(map[model.FDKind]bool, len(s.Kind))
		for _, name := range s.Kind {
			k, ok := emitKinds[name]
			if !ok {
				return Rule{}, fmt.Errorf("unknown kind %q: a fingerprint is one of %s", name, kindNames())
			}
			want[k] = true
		}
		predicates = append(predicates, func(v View) bool { return want[v.Kind] })
	}
	if len(s.Scheme) > 0 {
		want := make(map[string]bool, len(s.Scheme))
		for _, name := range s.Scheme {
			want[name] = true
		}
		predicates = append(predicates, func(v View) bool { return want[v.Scheme] })
	}
	if len(s.PathPrefix) > 0 {
		prefixes := append([]string(nil), s.PathPrefix...)
		predicates = append(predicates, func(v View) bool {
			for _, p := range prefixes {
				if p != "" && strings.HasPrefix(v.Path, p) {
					return true
				}
			}
			return false
		})
	}
	if len(s.PathSuffix) > 0 {
		suffixes := append([]string(nil), s.PathSuffix...)
		predicates = append(predicates, func(v View) bool {
			for _, p := range suffixes {
				if p != "" && strings.HasSuffix(v.Path, p) {
					return true
				}
			}
			return false
		})
	}
	if len(s.PathContains) > 0 {
		needles := append([]string(nil), s.PathContains...)
		predicates = append(predicates, func(v View) bool {
			for _, p := range needles {
				if p != "" && strings.Contains(v.Path, p) {
					return true
				}
			}
			return false
		})
	}
	if s.Deleted != nil {
		want := *s.Deleted
		predicates = append(predicates, func(v View) bool { return v.Deleted == want })
	}

	if len(predicates) == 0 {
		// A rule with no predicate matches every fingerprint, which would
		// silently swallow the whole report into one category. Refusing it is the
		// only way the failure stays visible.
		return Rule{}, errors.New("no predicate given: a rule without one matches every fingerprint and would " +
			"swallow the whole report into one category; add at least one of kind, scheme, " +
			"path_prefix, path_suffix, path_contains, deleted")
	}

	match := func(v View) bool {
		for _, p := range predicates {
			if !p(v) {
				return false
			}
		}
		return true
	}

	return Rule{
		Name:     s.Name,
		Category: s.Category,
		Why:      s.Why,
		// Configured rules sit above every built-in one: the reason to write a
		// rule is that the built-in answer was not the one wanted for this
		// process, so losing to a built-in would make the file pointless.
		Priority: UserRulePriority + s.Priority,
		Match:    match,
	}, nil
}

// kindNames lists the accepted kind values for an error message, derived from the
// same map the check uses and sorted so the message does not shuffle between runs.
// A hand-written list here would drift from emitKinds, and the drift would show up
// as an error message that names a value the parser rejects.
func kindNames() string {
	names := make([]string, 0, len(emitKinds))
	for name := range emitKinds {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// atLine attaches the position of a decode error to the message.
//
// encoding/json reports a byte offset for syntax and type errors but not for
// unknown fields, so the field name is looked up in the raw bytes to find its
// line - the message has to point somewhere useful, and "unknown field
// path_prefx" on a 40-line file leaves the reader searching.
func atLine(data []byte, err error) error {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return fmt.Errorf("line %d: %w", lineAt(data, syn.Offset), err)
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) {
		return fmt.Errorf("line %d: %w", lineAt(data, typ.Offset), err)
	}
	if i := strings.Index(err.Error(), `unknown field "`); i >= 0 {
		rest := err.Error()[i+len(`unknown field "`):]
		if j := strings.IndexByte(rest, '"'); j >= 0 {
			token := []byte(`"` + rest[:j] + `"`)
			if at := bytes.Index(data, token); at >= 0 {
				return fmt.Errorf("line %d: %w", lineAt(data, int64(at+1)), err)
			}
		}
	}
	return err
}

// lineAt converts a 1-based byte offset to a 1-based line number.
func lineAt(data []byte, offset int64) int {
	if offset < 1 {
		return 1
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	return bytes.Count(data[:offset-1], []byte{'\n'}) + 1
}
