package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// correlationJSON is the L2 block as it appears on the wire.
//
// It is asserted through the document rather than through the Go structs because
// the whole value of a correlation is that a CI job can read it: a field that only
// exists in memory would pass a struct test and never reach the log.
type correlationJSON struct {
	Correlations []struct {
		Counter    string   `json:"counter"`
		Baseline   int64    `json:"baseline"`
		Latest     int64    `json:"latest"`
		Delta      int64    `json:"delta"`
		DeltaPct   *float64 `json:"delta_pct"`
		Overlap    int      `json:"overlap_samples"`
		Window     int      `json:"window_samples"`
		Confidence string   `json:"confidence"`
		Note       string   `json:"note"`
	} `json:"correlations"`
	CorrelationAnchor string   `json:"correlation_anchor"`
	CorrelationOnset  int      `json:"correlation_onset"`
	CorrelationNotes  []string `json:"correlation_notes"`
	Totals            []int    `json:"totals"`
	Verdict           struct {
		Leaking      bool `json:"leaking"`
		Correlations []struct {
			Counter string `json:"counter"`
		} `json:"correlations"`
	} `json:"verdict"`
}

// counter returns the note of the correlation for name, if it is present.
func (c correlationJSON) counter(name string) (string, bool) {
	for _, row := range c.Correlations {
		if row.Counter == name {
			return row.Note, true
		}
	}
	return "", false
}

// buildFixture compiles the child process the positive correlation test drives.
//
// It is a Go program under testdata rather than a shell script because a shell
// cannot produce the signal honestly: measured against one, the resident set fell
// from 71MiB to 59MiB across the window as transient buffers were released, which
// would have made the test assert that memory activity looks like a decline.
func buildFixture(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "leakfixture")
	out, err := exec.Command("go", "build", "-o", bin, "./testdata/leakfixture").CombinedOutput()
	if err != nil {
		t.Fatalf("build the leaking fixture: %v\n%s", err, out)
	}
	return bin
}

// buildOpenFixture compiles the descriptor-only child the reverse assertion
// drives.
func buildOpenFixture(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openfixture")
	out, err := exec.Command("go", "build", "-o", bin, "./testdata/openfixture").CombinedOutput()
	if err != nil {
		t.Fatalf("build the descriptor-only fixture: %v\n%s", err, out)
	}
	return bin
}

// startFixture runs the leaking child in its own session and returns its pid.
func startFixture(t *testing.T, bin, dir, gate string) int {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "FIXTURE_DIR="+dir, "FIXTURE_GATE="+gate)
	// Its own session, as everywhere in these tests: killing the group must not be
	// able to reach the test runner.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the leaking fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// triggerAfter starts the check in the background and opens the child's gate once
// sampling is under way.
//
// The delay is what makes the test a test of the onset rather than of a process that
// was already busy: with the gate opened first, the growth would begin at sample 0,
// the correlation layer would (correctly) refuse for want of a baseline, and the
// assertion would be about a case the fixture never meant to create.
func triggerAfter(t *testing.T, bin string, gate string, delay time.Duration, args ...string) (correlationJSON, string, error) {
	t.Helper()
	type run struct {
		out    string
		errOut string
		err    error
	}
	done := make(chan run, 1)
	go func() {
		out, errOut, err := runCheckCLI(t, bin, args...)
		done <- run{out, errOut, err}
	}()
	time.Sleep(delay)
	if err := os.WriteFile(gate, nil, 0o644); err != nil {
		t.Fatalf("open the child's gate: %v", err)
	}
	r := <-done
	var doc correlationJSON
	if err := json.Unmarshal([]byte(r.out), &doc); err != nil {
		t.Fatalf("--json did not produce a parseable document: %v\nstdout:\n%s\nstderr:\n%s",
			err, r.out, r.errOut)
	}
	return doc, r.errOut, r.err
}

// TestCheckCorrelatesTheOnsetWithRealActivity is the Day 8 positive case end to end:
// a real process that starts leaking descriptors and holding memory at one moment.
//
// The assertion is deliberately two-sided. The counter that really moved (the
// resident set, as the child keeps every buffer it allocates) must be reported, and
// the counter that did not (the thread count, flat because the child allocates and
// opens files from one goroutine) must not be. A layer that reported every counter
// would pass the first half and fail the second - and the second is the half that
// decides whether anyone reads the section.
func TestCheckCorrelatesTheOnsetWithRealActivity(t *testing.T) {
	bin := buildCLI(t)
	fixture := buildFixture(t)
	dir := t.TempDir()
	gate := filepath.Join(dir, "gate")
	pid := startFixture(t, fixture, dir, gate)

	doc, errOut, err := triggerAfter(t, bin, gate, 350*time.Millisecond,
		strconv.Itoa(pid), "--json", "--interval", "120ms", "--samples", "25")
	if code := exitCodeOf(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2 for a process opening descriptors without bound\nstdout:\n%+v\nstderr:\n%s",
			code, doc, errOut)
	}
	if !doc.Verdict.Leaking {
		t.Fatalf("verdict.leaking = false for an unbounded opener: %+v", doc.Verdict)
	}
	if doc.CorrelationAnchor != "(total)" {
		t.Errorf("correlation_anchor = %q, want the process total", doc.CorrelationAnchor)
	}
	note, ok := doc.counter("rss")
	if !ok {
		t.Fatalf("no rss correlation for a process that grew its resident set while growing descriptors: "+
			"%+v (notes: %v)", doc.Correlations, doc.CorrelationNotes)
	}
	if !strings.Contains(note, "correlation") {
		t.Errorf("note %q does not say it is a correlation", note)
	}
	for _, word := range []string{"caused", "because", "due to"} {
		if strings.Contains(strings.ToLower(note), word) {
			t.Errorf("note %q contains %q: L2 may report co-occurrence but never a cause", note, word)
		}
	}
	// The counter that did not move must not be listed.
	if got, listed := doc.counter("threads"); listed {
		t.Errorf("threads was reported as correlated (%q) for a process that never spawned one", got)
	}
	// The block must also be present inside the verdict, which is the document an
	// embedder parses; the hoisted copy and the nested one are the same rows.
	if len(doc.Verdict.Correlations) != len(doc.Correlations) {
		t.Errorf("verdict.correlations has %d rows and the hoisted block %d: they must be the same",
			len(doc.Verdict.Correlations), len(doc.Correlations))
	}
}

// TestCheckReportsNoCorrelationForDescriptorsAlone is the reverse assertion from the
// plan: a fixture that only opens descriptors - no writes, no threads, no memory -
// must produce no correlation at all.
//
// This is the case that decides whether L2 is worth reading, so the fixture has to
// be a process that genuinely does nothing else. `exec {fd}>/dev/null` in a bash
// loop was not: on CI its read-syscall counter rose by +300 (+88%) across the
// window, because pacing a bash loop costs syscalls of the shell's own and those
// were reported as co-occurring activity. The fixture is therefore a Go program
// (testdata/openfixture) that opens, sleeps and nothing more - no forks, no reads,
// no allocation growth.
func TestCheckReportsNoCorrelationForDescriptorsAlone(t *testing.T) {
	bin := buildCLI(t)
	fixture := buildOpenFixture(t)
	dir := t.TempDir()
	gate := filepath.Join(dir, "go")
	pid := startFixture(t, fixture, dir, gate)

	doc, errOut, err := triggerAfter(t, bin, gate, 350*time.Millisecond,
		strconv.Itoa(pid), "--json", "--interval", "120ms", "--samples", "25")
	if code := exitCodeOf(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2: the fixture leaks descriptors\nstdout:\n%+v\nstderr:\n%s",
			code, doc, errOut)
	}
	if !doc.Verdict.Leaking {
		t.Fatalf("verdict.leaking = false for an unbounded opener: %+v", doc.Verdict)
	}
	if len(doc.Correlations) != 0 {
		t.Fatalf("correlations = %+v, want none for a process that only opened descriptors", doc.Correlations)
	}
	if doc.CorrelationAnchor == "" {
		t.Error("correlation_anchor is empty: the report must still say what was examined")
	}
	// "Nothing moved" has to be stated, and stated per counter. An empty block with no
	// explanation is indistinguishable from a block that was never computed.
	if len(doc.CorrelationNotes) == 0 {
		t.Fatal("no correlation_notes: silence about the counters that were checked is not evidence")
	}
	if !strings.Contains(strings.Join(doc.CorrelationNotes, " "), "did not move") {
		t.Errorf("notes = %v, want the counters that were checked and ruled out", doc.CorrelationNotes)
	}
}

// TestCheckNamesTheOnsetSample proves the onset index reaches the document, because
// the reader's next question after "what moved" is "from when".
func TestCheckNamesTheOnsetSample(t *testing.T) {
	bin := buildCLI(t)
	ch, _ := stagedChild(t, `
echo ready
while [ ! -e "$d/go" ]; do sleep 0.01; done
i=0
while :; do
  i=$((i+1))
  exec {fd}>"$d/leak-$i.log"
  sleep 0.08
done
`)
	gate := filepath.Join(ch.dir, "go")

	doc, errOut, err := triggerAfter(t, bin, gate, 350*time.Millisecond,
		strconv.Itoa(ch.pid()), "--json", "--interval", "120ms", "--samples", "20")
	if code := exitCodeOf(t, err); code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout:\n%+v\nstderr:\n%s", code, doc, errOut)
	}
	if len(doc.Totals) < 2 {
		t.Fatalf("no series to place an onset in: %+v", doc.Totals)
	}
	if doc.Totals[0] == doc.Totals[len(doc.Totals)-1] {
		t.Fatalf("the fixture did not grow: %v", doc.Totals)
	}
	// The gate opens after roughly three samples, so an onset at sample 0 would mean
	// the growth predates the window - which for this fixture it does not.
	if doc.CorrelationOnset < 1 || doc.CorrelationOnset >= len(doc.Totals) {
		t.Fatalf("correlation_onset = %d, want a sample strictly inside the series (0..%d): "+
			"the gate opened after sampling had begun, so the rise cannot start at sample 0",
			doc.CorrelationOnset, len(doc.Totals))
	}
}
