package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atop0914/fdscope/internal/analyze"
	"github.com/atop0914/fdscope/internal/attr"
)

// attrCheckJSON mirrors the parts of `check --json` this file asserts on.
type attrCheckJSON struct {
	Attribution []struct {
		Category   string  `json:"category"`
		Rule       string  `json:"rule"`
		Why        string  `json:"why"`
		Confidence string  `json:"confidence"`
		Matched    bool    `json:"matched"`
		Growth     int     `json:"growth"`
		Coverage   float64 `json:"coverage"`
	} `json:"attribution"`
	Verdict struct {
		Leaking bool `json:"leaking"`
		Series  []struct {
			Fingerprint string `json:"fingerprint"`
			Leak        bool   `json:"leak"`
			Attribution *struct {
				Category string `json:"category"`
				Rule     string `json:"rule"`
				Matched  bool   `json:"matched"`
			} `json:"attribution"`
		} `json:"series"`
	} `json:"verdict"`
}

// TestCheckNamesTheResourceClassOfARealLeak is the acceptance case: a child that
// grows two classes of descriptor at once, sampled for real, must come back with
// two categories and shares that add up.
//
// The child opens one log file repeatedly and connects a socket each round, in one
// process, so the growth really is concurrent. Files and sockets are both real: a
// fixture that faked either would prove the renderer and nothing about the claim.
func TestCheckNamesTheResourceClassOfARealLeak(t *testing.T) {
	bin := buildCLI(t)

	// A listener so the child's /dev/tcp connects have somewhere to go. It is never
	// accepted from: the client descriptors are what the test needs, and leaving
	// them in the accept queue keeps them open for the whole window.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	ch, dir := stagedChild(t, fmt.Sprintf(`
echo ready
i=0
while :; do
  i=$((i+1))
  exec {log_fd}>"$d/app.log"
  exec {sock_fd}<>/dev/tcp/127.0.0.1/%d
  sleep 0.05
done
`, port))

	out, errOut, err := runCheckCLI(t, bin, fmt.Sprintf("%d", ch.pid()),
		"--json", "--interval", "100ms", "--samples", "20", "--min-growth", "5")
	if got := exitCodeOf(t, err); got != ExitLeakFound {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s\nchild:\n%s",
			got, ExitLeakFound, out, errOut, ch.out.String())
	}

	// The premise, asserted rather than assumed: if the child died early the report
	// below would describe a shorter window than the test intends.
	opened, globErr := filepath.Glob(filepath.Join(dir, "app.log"))
	if globErr != nil {
		t.Fatalf("glob: %v", globErr)
	}
	if len(opened) != 1 {
		t.Fatalf("the log file was not created in %s: child:\n%s", dir, ch.out.String())
	}

	var rep attrCheckJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--json did not produce a parseable document: %v\n%s", err, out)
	}
	if !rep.Verdict.Leaking {
		t.Fatalf("verdict.leaking = false for a child that opened two classes of descriptor and closed none")
	}

	byCategory := make(map[string]float64, len(rep.Attribution))
	for _, row := range rep.Attribution {
		byCategory[row.Category] = row.Coverage
		if !row.Matched {
			t.Errorf("row %q is not matched but appears in the breakdown", row.Category)
		}
		if row.Why == "" {
			t.Errorf("row %q has no reason", row.Category)
		}
		if row.Growth <= 0 {
			t.Errorf("row %q has growth %d", row.Category, row.Growth)
		}
	}
	for _, want := range []string{"log file", "socket"} {
		if _, ok := byCategory[want]; !ok {
			t.Errorf("no %q row in the breakdown %v", want, byCategory)
		}
	}
	if len(rep.Attribution) < 2 {
		t.Fatalf("got %d breakdown rows, want at least 2: %v", len(rep.Attribution), byCategory)
	}
	var sum float64
	for _, c := range byCategory {
		sum += c
	}
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("shares sum to %v, want 1: %v", sum, byCategory)
	}

	// The per-series verdicts must carry the same words, so the table and the
	// breakdown cannot name different classes for the same fingerprint.
	labelled := 0
	for _, v := range rep.Verdict.Series {
		if !v.Leak {
			if v.Attribution != nil {
				t.Errorf("%s did not leak but carries an attribution", v.Fingerprint)
			}
			continue
		}
		if v.Attribution == nil {
			t.Errorf("%s leaked but carries no attribution", v.Fingerprint)
			continue
		}
		labelled++
		if v.Attribution.Category != "log file" && v.Attribution.Category != "socket" {
			t.Errorf("%s attributed to %q", v.Fingerprint, v.Attribution.Category)
		}
	}
	if labelled == 0 {
		t.Error("no leaked series carried an attribution")
	}
}

// TestCheckRefusesABrokenRuleFile covers the ordering as much as the error: the
// file is read before sampling starts, so a bad one fails immediately instead of
// after a five second window, and it fails with exit 1 rather than 2 - a broken
// configuration is not a leak.
func TestCheckRefusesABrokenRuleFile(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := `{
  "version": 1,
  "rules": [
    {"name": "x" "category": "c"}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, err := runCheckCLI(t, bin, "1", "--attr-rules", path)
	if got := exitCodeOf(t, err); got != 1 {
		t.Fatalf("exit = %d, want 1: a bad rule file is a failure to measure, not a leak\nstdout:\n%s\nstderr:\n%s",
			got, out, errOut)
	}
	// The line number is the whole value of the message on a hand-edited file.
	if !strings.Contains(errOut, "line 4") {
		t.Errorf("stderr does not name the line:\n%s", errOut)
	}
	if strings.Contains(out, "pid") {
		t.Errorf("the run printed a report despite not being able to load its rules:\n%s", out)
	}
}

// TestCheckAttrRulesOverrideTheBuiltinAnswer proves the flag changes the answer,
// end to end, with a real process each time: the built-in rules call the growing
// file a log, and the configured rule renames that same class.
//
// Two children are used because a leak fixture can only leak once; reusing the
// first one would test a constant count and report "no leak", which is a correct
// answer to a different question.
func TestCheckAttrRulesOverrideTheBuiltinAnswer(t *testing.T) {
	bin := buildCLI(t)

	growScript := `
echo ready
i=0
while :; do
  i=$((i+1))
  exec {fd}>"$d/app.log"
  sleep 0.02
done
`
	run := func(t *testing.T, extra ...string) attrCheckJSON {
		t.Helper()
		ch, _ := stagedChild(t, growScript)
		args := append([]string{fmt.Sprintf("%d", ch.pid()), "--json",
			"--interval", "50ms", "--samples", "20", "--min-growth", "5"}, extra...)
		out, errOut, err := runCheckCLI(t, bin, args...)
		if got := exitCodeOf(t, err); got != ExitLeakFound {
			t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s\nchild:\n%s",
				got, ExitLeakFound, out, errOut, ch.out.String())
		}
		var rep attrCheckJSON
		if unmarshalErr := json.Unmarshal([]byte(out), &rep); unmarshalErr != nil {
			t.Fatalf("--json: %v\n%s", unmarshalErr, out)
		}
		return rep
	}

	base := run(t)
	if len(base.Attribution) == 0 || base.Attribution[0].Category != "log file" {
		t.Fatalf("baseline breakdown = %+v, want a log file row", base.Attribution)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := `{"version": 1, "rules": [{
	  "name": "audit-log",
	  "category": "audit log written once per request",
	  "why": "the deployment's audit trail, one descriptor per request when the reaper is missing",
	  "path_suffix": [".log"]
	}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	configured := run(t, "--attr-rules", path)
	if len(configured.Attribution) == 0 {
		t.Fatalf("configured run produced no breakdown")
	}
	if got := configured.Attribution[0].Category; got != "audit log written once per request" {
		t.Errorf("configured category = %q, want the rule file's category", got)
	}
	if got := configured.Attribution[0].Rule; got != "audit-log" {
		t.Errorf("configured rule = %q, want audit-log", got)
	}
}

// TestJudgeTableShowsTheBreakdownAndTheGap asserts the rendering, separately from
// the data: the table is what an operator reads, and a breakdown that only exists
// in the JSON is a feature nobody sees.
//
// The report is built by hand here on purpose - the point is the layout, and
// driving a real leak would test the numbers again rather than the words.
func TestJudgeTableShowsTheBreakdownAndTheGap(t *testing.T) {
	rep := analyze.LeakReport{
		PID:          4242,
		Samples:      20,
		WindowMillis: 1900,
		Leaking:      true,
		Total: analyze.LeakVerdict{
			Fingerprint: "(total)",
			Leak:        true,
			Confidence:  analyze.ConfidenceHigh,
			Reason:      "grew 40 descriptors",
			Evidence:    analyze.LeakEvidence{WindowSamples: 20, Growth: 40, GrowthRequired: 10, Monotonic: true},
		},
		Series: []analyze.LeakVerdict{{
			Fingerprint: "file:/var/log/app.log",
			Leak:        true,
			Confidence:  analyze.ConfidenceHigh,
			Reason:      "grew 30 descriptors",
			Evidence:    analyze.LeakEvidence{WindowSamples: 20, Growth: 30, GrowthRequired: 10, Monotonic: true},
			Attribution: &attr.Attribution{
				Fingerprint: "file:/var/log/app.log",
				Matched:     true,
				Rule:        "log-file",
				Category:    "log file",
				Why:         "the path is a .log file",
				Confidence:  attr.ConfidenceHigh,
			},
		}},
		Attribution: []attr.CategoryAttribution{
			{
				Category: "log file", Rule: "log-file", Why: "the path is a .log file",
				Confidence: attr.ConfidenceHigh, Matched: true,
				Growth: 30, Fingerprints: 1, Coverage: 0.75,
			},
			{
				Category: attr.NoMatchCategory, Why: attr.NoMatchWhy,
				Confidence: attr.ConfidenceNone, Matched: false,
				Growth: 10, Fingerprints: 1, Coverage: 0.25,
			},
		},
	}

	var sb strings.Builder
	if err := renderJudgeTable(&sb, rep); err != nil {
		t.Fatalf("renderJudgeTable: %v", err)
	}
	out := sb.String()

	for _, want := range []string{
		"attribution:",                        // the per-verdict line
		"log file [log-file, L1 high]",        // category, rule and strength together
		"share of the leak by resource class", // the breakdown header
		"75%",                                 // the matched share
		"25%",                                 // the unattributed share, stated not dropped
		attr.NoMatchCategory,                  // the words, not a blank column
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table does not contain %q:\n%s", want, out)
		}
	}
}

// TestJudgeTableOmitsTheBreakdownWithoutALeak is the reverse rendering assertion:
// a clean verdict must not grow an empty "attribution" section that reads as
// "attributed nothing, therefore fine".
func TestJudgeTableOmitsTheBreakdownWithoutALeak(t *testing.T) {
	rep := analyze.LeakReport{
		PID: 4242, Samples: 10, Leaking: false,
		Total: analyze.LeakVerdict{Fingerprint: "(total)", Confidence: analyze.ConfidenceHigh, Reason: "no rise"},
	}
	var sb strings.Builder
	if err := renderJudgeTable(&sb, rep); err != nil {
		t.Fatalf("renderJudgeTable: %v", err)
	}
	if strings.Contains(sb.String(), "attribution") {
		t.Errorf("a clean report mentions attribution:\n%s", sb.String())
	}
}
