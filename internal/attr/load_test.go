package attr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validRules = `{
  "version": 1,
  "rules": [
    {
      "name": "wal-segment",
      "category": "postgres WAL segment",
      "why": "a file under pg_wal: one per write-ahead segment, and a count that only rises means segments are not being recycled",
      "path_contains": ["pg_wal"],
      "path_suffix": [".wal"]
    },
    {
      "name": "shard-open",
      "category": "shard file",
      "why": "one of this deployment's shard files",
      "path_prefix": ["/srv/app/shards/"],
      "priority": 5
    }
  ]
}`

// TestParseRules is the happy path, including that a configured rule actually
// wins over the built-in answer for the same fingerprint. Proving it changed the
// answer is the whole point: a rule that parses and never takes effect is the
// failure this loader is written to make impossible.
func TestParseRules(t *testing.T) {
	rules, err := Parse([]byte(validRules))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	for _, r := range rules {
		if r.Priority < UserRulePriority {
			t.Errorf("rule %q priority %d is below UserRulePriority %d: a configured rule that loses to a built-in makes the file pointless",
				r.Name, r.Priority, UserRulePriority)
		}
	}

	// Before: the built-in rules answer "temporary file" for anything under /tmp.
	builtin := Default().Attribute("file:/tmp/x")
	if builtin.Category != "temporary file" {
		t.Fatalf("baseline: category = %q, want temporary file", builtin.Category)
	}

	engine, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// After: a user rule naming /srv/app/shards takes over that prefix without
	// disturbing /tmp.
	got := engine.Attribute("file:/srv/app/shards/0001.db")
	if got.Rule != "shard-open" || got.Category != "shard file" {
		t.Errorf("Attribute(shard) = %q / %q, want shard-open / shard file", got.Rule, got.Category)
	}
	if got := engine.Attribute("file:/tmp/x"); got.Category != "temporary file" {
		t.Errorf("Attribute(/tmp/x) = %q, want the built-in answer to survive", got.Category)
	}
	// A rule whose predicates must all hold: a pg_wal path that is not a .wal.
	if got := engine.Attribute("file:/var/lib/postgresql/pg_wal/archive_status"); got.Rule == "wal-segment" {
		t.Errorf("wal-segment matched %q, but path_suffix .wal was not satisfied", got.Fingerprint)
	}
	if got := engine.Attribute("file:/var/lib/postgresql/pg_wal/000000010000000000000001.wal"); got.Rule != "wal-segment" {
		t.Errorf("Attribute(wal) = %q, want wal-segment", got.Rule)
	}
}

// TestParseRulesRejectsUnusableFiles enumerates the ways a rule file fails to mean
// what its author thought, each with the position that makes it findable.
//
// The line number is asserted, not just the message: a loader that says "invalid
// JSON" on a forty-line file has told the reader nothing they did not already
// know.
func TestParseRulesRejectsUnusableFiles(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "syntax error names the line",
			input: `{
  "version": 1,
  "rules": [
    {"name": "x" "category": "c"}
  ]
}`,
			want: []string{"line 4"},
		},
		{
			name: "misspelled field names the line",
			input: `{
  "version": 1,
  "rules": [
    {
      "name": "x",
      "category": "c",
      "why": "w",
      "path_prefx": ["/tmp"]
    }
  ]
}`,
			want: []string{"line 8", "unknown field"},
		},
		{
			name:  "no predicate",
			input: `{"version": 1, "rules": [{"name": "x", "category": "c", "why": "w"}]}`,
			want:  []string{"no predicate", "matches every fingerprint"},
		},
		{
			name:  "unknown kind",
			input: `{"version": 1, "rules": [{"name": "x", "category": "c", "why": "w", "kind": ["directory"]}]}`,
			want:  []string{`unknown kind "directory"`, "anon_inode"},
		},
		{
			name:  "empty rule list",
			input: `{"version": 1, "rules": []}`,
			want:  []string{"defines no rules"},
		},
		{
			name:  "missing version",
			input: `{"rules": [{"name": "x", "category": "c", "why": "w", "kind": ["file"]}]}`,
			want:  []string{"unsupported rules version 0"},
		},
		{
			name:  "negative priority",
			input: `{"version": 1, "rules": [{"name": "x", "category": "c", "why": "w", "kind": ["file"], "priority": -5}]}`,
			want:  []string{"priority must not be negative"},
		},
		{
			name:  "no reason",
			input: `{"version": 1, "rules": [{"name": "x", "category": "c", "kind": ["file"]}]}`,
			want:  []string{"no reason"},
		},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.input))
		if err == nil {
			t.Errorf("%s: Parse accepted the file", tc.name)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error = %q, want it to contain %q", tc.name, err, want)
			}
		}
	}
}

// TestDeletedPredicateIsThreeState covers the pointer field: "not configured" must
// not behave like "configured false", or a rule written for live files would also
// claim every unlinked one.
func TestDeletedPredicateIsThreeState(t *testing.T) {
	live := `{"version": 1, "rules": [
	  {"name": "live-only", "category": "live app file", "why": "w", "path_prefix": ["/srv/app/"], "deleted": false}
	]}`
	rules, err := Parse([]byte(live))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	engine, err := New(rules)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := engine.Attribute("deleted:/srv/app/state.db"); got.Rule == "live-only" {
		t.Errorf("live-only matched a deleted file: a false predicate is not the same as an absent one")
	}
	if got := engine.Attribute("file:/srv/app/state.db"); got.Rule != "live-only" {
		t.Errorf("live-only did not match a live file, got %q", got.Rule)
	}
}

// TestLoadFile covers the file path, including that a missing file is an error
// rather than an empty rule set: silently continuing with no user rules would run
// the check with rules the operator did not ask for and cannot see.
func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(path, []byte(validRules), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}

	_, err = LoadFile(filepath.Join(dir, "absent.json"))
	if err == nil {
		t.Fatal("LoadFile accepted a missing file")
	}
	if !strings.Contains(err.Error(), "attribution rules") {
		t.Errorf("error = %q, want it to say what could not be read", err)
	}

	bad := filepath.Join(dir, "bad.json")
	if writeErr := os.WriteFile(bad, []byte(`{"version": 1, "rules": `), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	_, err = LoadFile(bad)
	if err == nil {
		t.Fatal("LoadFile accepted a truncated file")
	}
	if !strings.Contains(err.Error(), bad) {
		t.Errorf("error = %q, want it to name the file", err)
	}
}

// TestLoadEngine covers the single entry point. An empty path must mean "built-in
// rules", not "no rules": the distinction matters because a nil engine silently
// degrades to the same thing, and a caller that passed an empty path by accident
// should get working behaviour rather than a report where nothing is attributed.
func TestLoadEngine(t *testing.T) {
	engine, err := LoadEngine("")
	if err != nil {
		t.Fatalf("LoadEngine(\"\"): %v", err)
	}
	if got := engine.Attribute("socket").Category; got != "socket" {
		t.Errorf("built-in engine category = %q, want socket", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	if writeErr := os.WriteFile(path, []byte(validRules), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	engine, err = LoadEngine(path)
	if err != nil {
		t.Fatalf("LoadEngine(%q): %v", path, err)
	}
	if got := engine.Attribute("file:/srv/app/shards/0002.db").Category; got != "shard file" {
		t.Errorf("category = %q, want shard file", got)
	}
	// The built-ins survive the merge: a rule file adds categories, it does not
	// replace the set. Otherwise loading one rule would silently blind the tool to
	// sockets.
	if got := engine.Attribute("socket").Category; got != "socket" {
		t.Errorf("after merging a rule file, socket = %q; the built-ins must still apply", got)
	}
}
