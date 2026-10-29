package attr

import (
	"sort"
	"strings"
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// builtinCases maps a fingerprint to the one rule that must win.
//
// It is a table rather than a pile of assertions so that
// TestEveryBuiltinRuleIsCovered can prove every rule appears here: a rule with no
// case is a rule whose behaviour nobody has ever seen, and the compiler will not
// tell anyone about it.
var builtinCases = []struct {
	fp       string
	rule     string
	category string
}{
	{"deleted:/tmp/ghost", "deleted-file", "unlinked file still held"},
	{"socket", "socket", "socket"},
	{"pipe", "pipe", "pipe"},
	{"/dev/pts/0", "terminal", "terminal"},
	{"/dev/tty1", "terminal", "terminal"},
	{"/dev/null", "null-device", "discard device"},
	{"/dev/sda", "device", "device node"},
	{"file:/var/log/app.log", "log-file", "log file"},
	{"file:/var/log/syslog/current", "log-file", "log file"},
	{"file:/dev/shm/metrics", "shared-memory", "shared memory file"},
	{"file:/tmp/worker", "temp-file", "temporary file"},
	{"file:/var/tmp/upload", "temp-file", "temporary file"},
	{"anon_inode:eventpoll", "anon-inode/eventpoll", "epoll instance"},
	{"anon_inode:inotify", "anon-inode/inotify", "inotify watch"},
	{"anon_inode:timerfd", "anon-inode/timerfd", "timer"},
	{"anon_inode:eventfd", "anon-inode/eventfd", "event counter"},
	{"anon_inode:signalfd", "anon-inode/signalfd", "signal queue"},
	{"anon_inode:io_uring", "anon-inode/io_uring", "io_uring ring"},
	// An anonymous inode the built-ins do not name: it must still be attributed,
	// and to the generic category, rather than falling through to "no rule
	// matched" - the kernel did name it, we just do not have a better word.
	{"anon_inode:fanotify", "anon-inode", "anonymous inode (other)"},
}

func TestBuiltinRules(t *testing.T) {
	e := Default()
	for _, tc := range builtinCases {
		got := e.Attribute(tc.fp)
		if !got.Matched {
			t.Errorf("Attribute(%q) matched nothing, want %q", tc.fp, tc.rule)
			continue
		}
		if got.Rule != tc.rule {
			// Name the winner and the expectation: "wrong rule" alone sends the
			// reader to the priority table without knowing which side moved.
			t.Errorf("Attribute(%q) rule = %q, want %q", tc.fp, got.Rule, tc.rule)
		}
		if got.Category != tc.category {
			t.Errorf("Attribute(%q) category = %q, want %q", tc.fp, got.Category, tc.category)
		}
		if got.Confidence != ConfidenceHigh {
			t.Errorf("Attribute(%q) confidence = %q, want %q: L1 restates the fingerprint",
				tc.fp, got.Confidence, ConfidenceHigh)
		}
	}
}

// TestEveryBuiltinRuleIsCovered fails when a rule has no case above.
//
// Without it, adding a rule is free: nothing asserts it ever matches, so a
// predicate that can never be true - a typo in a path prefix, a kind the
// normaliser does not emit - ships looking exactly like a working rule.
func TestEveryBuiltinRuleIsCovered(t *testing.T) {
	covered := make(map[string]bool, len(builtinCases))
	for _, tc := range builtinCases {
		covered[tc.rule] = true
	}
	var missing []string
	for _, r := range Default().Rules() {
		if !covered[r.Name] {
			missing = append(missing, r.Name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("built-in rules with no test case: %s", strings.Join(missing, ", "))
	}
}

// TestBuiltinRulesAreOrderedFromSpecificToGeneral holds the ladder down.
//
// The ladder is the answer to "which category wins when two apply", and it is the
// one part of attribution that cannot be derived from anything else - so it is
// asserted rather than left to the order the slice happens to be written in.
func TestBuiltinRulesAreOrderedFromSpecificToGeneral(t *testing.T) {
	rules := Default().Rules()
	for i := 1; i < len(rules); i++ {
		if rules[i-1].Priority < rules[i].Priority {
			t.Fatalf("rule %q (priority %d) sorts before %q (priority %d); the engine consults the first match",
				rules[i-1].Name, rules[i-1].Priority, rules[i].Name, rules[i].Priority)
		}
	}
	// The named anonymous-inode rules must outrank the generic one, otherwise a
	// growing epoll set would be reported as "anonymous inode (other)" and the
	// reader would lose the one word that explains it.
	priorities := make(map[string]int, len(rules))
	for _, r := range rules {
		priorities[r.Name] = r.Priority
	}
	if priorities["anon-inode/eventpoll"] <= priorities["anon-inode"] {
		t.Errorf("anon-inode/eventpoll priority %d must exceed the generic anon-inode %d",
			priorities["anon-inode/eventpoll"], priorities["anon-inode"])
	}
	// The consequence of an unlinked file outranks what the path was for: the
	// disk is pinned, and that is the actionable half of the sentence.
	if priorities["deleted-file"] <= priorities["log-file"] {
		t.Errorf("deleted-file priority %d must exceed log-file %d: consequence outranks role",
			priorities["deleted-file"], priorities["log-file"])
	}
}

// TestOneFingerprintYieldsOneCategory is the dedup assertion.
//
// A fingerprint usually satisfies more than one predicate - a deleted file in
// /tmp whose name ends in .log satisfies three - and the report must show one
// row, the most specific one. Showing all three would rank nothing and tell the
// reader to read the priority table; showing the general one would bury the
// action.
func TestOneFingerprintYieldsOneCategory(t *testing.T) {
	cases := []struct {
		fp   string
		want string
		why  string
	}{
		{
			fp:   "deleted:/tmp/app.log",
			want: "unlinked file still held",
			why:  "an unlinked log in /tmp matches deleted, log and temp; the pinned disk is the finding",
		},
		{
			fp:   "file:/tmp/worker.log",
			want: "log file",
			why:  "a .log file in /tmp matches log and temp; the role is the more specific statement",
		},
		{
			fp:   "file:/dev/shm/app.log",
			want: "log file",
			why:  "log outranks the tmpfs location, because the suffix constrains the name and the directory does not",
		},
	}
	for _, tc := range cases {
		got := Default().Attribute(tc.fp)
		if got.Category != tc.want {
			t.Errorf("Attribute(%q) category = %q, want %q (%s)", tc.fp, got.Category, tc.want, tc.why)
		}
	}
}

// TestNoMatchIsStatedNotBlanked is the honesty assertion.
//
// A fingerprint nothing covers must produce the words "no rule matched" and the
// reason why. An empty category would render as a blank column, and a blank
// column next to a real leak reads as "nothing to see here" - the one reading
// that is certainly wrong.
func TestNoMatchIsStatedNotBlanked(t *testing.T) {
	cases := []struct {
		fp   string
		note string
	}{
		{"file:/var/lib/catalog/index", "catalog is not a log, however the substring reads"},
		{"file:/home/u/data.bin", "an ordinary data file is not any of the built-in classes"},
		{"file:/tmpfoo/scratch", "/tmpfoo is not under /tmp"},
		{"file:/srv/app/state.db", "an application file the rules do not know"},
	}
	for _, tc := range cases {
		got := Default().Attribute(tc.fp)
		if got.Matched {
			t.Errorf("Attribute(%q) matched %q, want no match (%s)", tc.fp, got.Category, tc.note)
			continue
		}
		if got.Category != NoMatchCategory {
			t.Errorf("Attribute(%q) category = %q, want %q", tc.fp, got.Category, NoMatchCategory)
		}
		if strings.TrimSpace(got.Why) == "" {
			t.Errorf("Attribute(%q) has no reason; an unattributed leak must say why it is unattributed", tc.fp)
		}
		if got.Confidence != ConfidenceNone {
			t.Errorf("Attribute(%q) confidence = %q, want %q: there is no claim to qualify", tc.fp, got.Confidence, ConfidenceNone)
		}
		if !strings.Contains(got.Describe(), NoMatchCategory) {
			t.Errorf("Describe() = %q, want it to contain %q", got.Describe(), NoMatchCategory)
		}
	}
}

// TestMalformedFingerprintIsNotBlamedOnTheRules separates two different failures.
//
// "not a fingerprint" and "no rule matched" both mean no attribution, but only one
// of them is the rule set's fault. Reporting the wrong one sends the reader to
// edit rules for a value that was never a fingerprint.
func TestMalformedFingerprintIsNotBlamedOnTheRules(t *testing.T) {
	for _, fp := range []string{"", "(total)", "eventpoll", "file:"} {
		got := Default().Attribute(fp)
		if got.Matched {
			t.Errorf("Attribute(%q) matched %q, want no match", fp, got.Category)
		}
		if got.Why == NoMatchWhy {
			t.Errorf("Attribute(%q) was blamed on the rule set; %q is not a fingerprint at all", fp, fp)
		}
	}
}

// TestReasonsContainNoGuesswork is the language assertion.
//
// The one promise L1 makes is that it never claims who opened a descriptor. That
// promise lives in prose, so it is checked like prose: the forbidden words are the
// ones that would turn a restatement into an inference. Behavioural tests cannot
// catch this - every rule would still return the right category - which is exactly
// why it needs its own test.
func TestReasonsContainNoGuesswork(t *testing.T) {
	forbidden := []string{
		"probably", "likely", "presumably", "opened by", "opener",
		"because of", "is caused by", "must have", "might be",
	}
	for _, r := range Default().Rules() {
		lower := strings.ToLower(r.Why)
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Errorf("rule %q reason contains %q: L1 may not speculate about origin (%s)", r.Name, word, r.Why)
			}
		}
		if strings.TrimSpace(r.Why) == "" {
			t.Errorf("rule %q has no reason", r.Name)
		}
	}
}

// TestViewOf exposes only what the fingerprint says.
//
// The view is the L1 boundary in code: if it carried the process, the clock or the
// descriptor flags, a rule could reach them and the boundary would exist only in
// the documentation. This test pins the shape so that adding a field is a
// deliberate, visible change.
func TestViewOf(t *testing.T) {
	cases := []struct {
		fp   string
		want View
		ok   bool
	}{
		{
			fp:   "file:/var/log/app.log",
			want: View{Fingerprint: "file:/var/log/app.log", Scheme: "file", Kind: model.KindFile, Path: "/var/log/app.log"},
			ok:   true,
		},
		{
			fp:   "deleted:/tmp/ghost",
			want: View{Fingerprint: "deleted:/tmp/ghost", Scheme: "deleted", Kind: model.KindDeleted, Path: "/tmp/ghost", Deleted: true},
			ok:   true,
		},
		{
			fp:   "socket",
			want: View{Fingerprint: "socket", Scheme: "socket", Kind: model.KindSocket},
			ok:   true,
		},
		{
			fp:   "anon_inode:eventpoll",
			want: View{Fingerprint: "anon_inode:eventpoll", Scheme: "anon_inode", Kind: model.KindAnonInode, Name: "eventpoll"},
			ok:   true,
		},
		{
			fp:   "/dev/null",
			want: View{Fingerprint: "/dev/null", Kind: model.KindDevice, Path: "/dev/null"},
			ok:   true,
		},
		{fp: "nonsense", ok: false},
	}
	for _, tc := range cases {
		got, ok := ViewOf(tc.fp)
		if ok != tc.ok {
			t.Errorf("ViewOf(%q) ok = %t, want %t", tc.fp, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("ViewOf(%q) = %+v, want %+v", tc.fp, got, tc.want)
		}
	}
}

// TestEngineRejectsUnusableRules covers the four ways a rule can be useless
// without failing at run time. Each is rejected at construction, because a rule
// that cannot fire is indistinguishable from a rule that fires and finds nothing.
func TestEngineRejectsUnusableRules(t *testing.T) {
	ok := func(View) bool { return true }
	cases := []struct {
		name string
		rule Rule
		want string
	}{
		{
			name: "no name",
			rule: Rule{Category: "c", Why: "w", Priority: 1, Match: ok},
			want: "no name",
		},
		{
			name: "no category",
			rule: Rule{Name: "n", Why: "w", Priority: 1, Match: ok},
			want: "no category",
		},
		{
			name: "no reason",
			rule: Rule{Name: "n", Category: "c", Priority: 1, Match: ok},
			want: "no reason",
		},
		{
			name: "no predicate",
			rule: Rule{Name: "n", Category: "c", Why: "w", Priority: 1},
			want: "no predicate",
		},
		{
			name: "zero priority",
			rule: Rule{Name: "n", Category: "c", Why: "w", Match: ok},
			want: "priority",
		},
	}
	for _, tc := range cases {
		_, err := New([]Rule{tc.rule})
		if err == nil {
			t.Errorf("%s: New accepted an unusable rule", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

func TestEngineRejectsDuplicateRuleNames(t *testing.T) {
	ok := func(View) bool { return true }
	dup := []Rule{
		{Name: "mine", Category: "c", Why: "w", Priority: 2000, Match: ok},
		{Name: "mine", Category: "c2", Why: "w", Priority: 2001, Match: ok},
	}
	if _, err := New(dup); err == nil {
		t.Fatal("New accepted two rules with the same name: \"rule: mine matched\" would be ambiguous")
	}
}
