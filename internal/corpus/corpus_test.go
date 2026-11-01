//go:build linux

package corpus

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/probe"
	"github.com/atop0914/fdscope/pkg/fdscope"
)

// sampleInterval and sampleCount set the observation window every case below is
// judged on: twenty samples 100ms apart, just under two seconds.
//
// Short on purpose. The corpus is about *shapes* - growth that keeps growing, a
// leak that stops being closable, a process that dies - and a shape that needs a
// ten second window to become visible is not one of them. The shorter window also
// costs the suite ten seconds instead of a minute.
const (
	sampleInterval = 100 * time.Millisecond
	sampleCount    = 20
)

// fixture is one running corpus program.
type fixture struct {
	name string
	pid  int
	// dir is the working directory the program reported. Reports group by path,
	// so the assertions need it to count what the program itself holds.
	dir string
}

// repoRoot locates the module root from this file's own path. The corpus
// programs live in testdata, which the go tool does not walk, so their binaries
// have to be built explicitly and the build needs a module-aware directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return abs
}

// startFixture builds and starts one corpus program, and waits for it to report
// that the leak has begun.
//
// Every program here prints "ready <dir>" as its first line. Waiting for that
// line instead of sleeping is what keeps the assertions stable on a slow machine:
// a fixed sleep would either sample before the program started or after a fixed
// leak had already finished, and both readings look like a detector fault.
func startFixture(t *testing.T, name string, args ...string) *fixture {
	t.Helper()

	bin := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", bin, "./testdata/corpus/"+name)
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build corpus program %s: %v\n%s", name, err, out)
	}

	cmd := exec.Command(bin, args...)
	// Its own session, so cleanup can kill the process group without reaching
	// into this test binary: `go test` and the child otherwise share a group and
	// kill(-pgid) takes the runner down with it, which reads as an OOM kill.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("%s: stdout pipe: %v", name, err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: start: %v", name, err)
	}
	pid := cmd.Process.Pid
	// The group id has to be cached here. Asking for it later is a silent no-op:
	// once the process is reaped Getpgid answers ESRCH and cleanup reports
	// success while the group is still alive.
	pgid, pgidErr := syscall.Getpgid(pid)
	if pgidErr != nil {
		pgid = pid
	}

	lines := make(chan string, 8)
	go func() {
		// The read continues to EOF rather than stopping at the marker. A pipe
		// holds 64KiB, and a fixture whose later output nobody drained would
		// block in write(2) - which looks exactly like a slow sampler.
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
		close(lines)
	}()

	var ready string
	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatalf("%s: exited before reporting ready", name)
		}
		ready = line
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		t.Fatalf("%s: never reported ready", name)
	}

	fields := strings.Fields(ready)
	if len(fields) == 0 || fields[0] != "ready" {
		t.Fatalf("%s: first line = %q, want \"ready ...\"", name, ready)
	}
	fx := &fixture{name: name, pid: pid}
	if len(fields) > 1 {
		fx.dir = fields[1]
	}

	t.Cleanup(func() {
		if pgid > 0 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if fx.dir != "" {
			_ = os.RemoveAll(fx.dir)
		}
	})
	return fx
}

// total reads the program's descriptor count from /proc.
//
// Read from the kernel, never from the program's own counters: every defect in
// this corpus is a counter that disagreed with /proc, so a fixture trusted as its
// own witness could reproduce the bug and still pass.
func (f *fixture) total(t *testing.T) int {
	t.Helper()
	snap, err := probe.NewProbe().Snapshot(f.pid)
	if err != nil {
		t.Fatalf("%s: snapshot pid %d: %v", f.name, f.pid, err)
	}
	if !snap.Complete() {
		t.Fatalf("%s: snapshot is incomplete (%d unreadable)", f.name, snap.Unreadable)
	}
	return snap.Len()
}

// held counts the descriptors whose target points into the program's own working
// directory: what the program opened, as opposed to what it needed to start.
func (f *fixture) held(t *testing.T) int {
	t.Helper()
	snap, err := probe.NewProbe().Snapshot(f.pid)
	if err != nil {
		t.Fatalf("%s: snapshot pid %d: %v", f.name, f.pid, err)
	}
	n := 0
	for _, d := range snap.Descriptors {
		if strings.Contains(d.Target, f.dir) {
			n++
		}
	}
	return n
}

// check runs the library verdict on the fixture.
func (f *fixture) check(t *testing.T) fdscope.CheckResult {
	t.Helper()
	// A normaliser that keeps the paths intact: the assertions are about the
	// program's own files, and anonymising a home directory that does not appear
	// in them would only add a moving part.
	res, err := fdscope.CheckPID(f.pid, fdscope.CheckOptions{
		Interval: sampleInterval,
		Samples:  sampleCount,
	})
	if err != nil {
		t.Fatalf("%s: check: %v", f.name, err)
	}
	if res.Snapshots < sampleCount/2 {
		t.Fatalf("%s: only %d of %d samples were collected", f.name, res.Snapshots, sampleCount)
	}
	return res
}

// assertLeakAndCategory is the shared verdict assertion for the two leaking
// programs: the process is convicted, the growth is real and still growing at the
// end of the window, and the growth is attributed to the category the paths
// actually belong to.
func assertLeakAndCategory(t *testing.T, fx *fixture) fdscope.CheckResult {
	t.Helper()
	before := fx.held(t)
	res := fx.check(t)
	after := fx.held(t)

	// Real side effect first: the program really did open more than it closed
	// while the window ran. Asserting the verdict without this would test the
	// analyser against a program that may not have leaked at all.
	if grown := after - before; grown < 10 {
		t.Fatalf("%s: held %d descriptors before and %d after the window: the fixture did not leak, so the verdict below would be a coincidence",
			fx.name, before, after)
	}
	if !res.Leaking() {
		t.Fatalf("%s: not judged a leak; totals %v, total verdict %+v", fx.name, res.Totals, res.Report.Total)
	}
	totals := res.Totals
	if len(totals) < 2 {
		t.Fatalf("%s: %d samples, want at least 2", fx.name, len(totals))
	}
	// The leak must still be growing at the end of the window, not have stopped
	// at its start: "grew and then held" is the shape a pool produces.
	if totals[len(totals)-1] <= totals[len(totals)/2] {
		t.Errorf("%s: the count stopped rising halfway through the window: %v", fx.name, totals)
	}
	// Attribution is the day's actual claim: the growth is not just "something",
	// it is a category of resource the report can name. Every path here is a file
	// under /tmp, so the category is fixed by the rule set rather than by luck.
	if len(res.Report.Attribution) == 0 {
		t.Fatalf("%s: leaking with no attribution at all: %+v", fx.name, res.Report)
	}
	top := res.Report.Attribution[0]
	if top.Category != "temporary file" {
		t.Errorf("%s: top category = %q, want %q (all: %+v)", fx.name, top.Category, "temporary file", res.Report.Attribution)
	}
	if top.Rule != "temp-file" {
		t.Errorf("%s: top rule = %q, want temp-file", fx.name, top.Rule)
	}
	if !top.Matched {
		t.Errorf("%s: top category is the unattributed bucket", fx.name)
	}
	if top.Coverage < 0.9 {
		t.Errorf("%s: temporary file covers %.2f of the growth, want ~1: the rest is unexplained", fx.name, top.Coverage)
	}
	return res
}

// TestFdListDriftIsJudgedALeak covers the first defect: a list count that never
// decreases, so the cache permanently believes it is full and hands out
// descriptors it does not own.
func TestFdListDriftIsJudgedALeak(t *testing.T) {
	fx := startFixture(t, "fdlistdrift")
	res := assertLeakAndCategory(t, fx)

	// This defect leaks over one data file per round, so the growth is spread over
	// hundreds of fingerprints that each gain a single descriptor. Asserting the
	// spread is asserting what makes the category the only actionable answer - and
	// it pins that the breakdown is a real aggregation, not one row copied from the
	// total.
	if top := res.Report.Attribution[0]; top.Fingerprints < 20 {
		t.Errorf("the leaked growth came from %d resource(s), want many: this defect opens a new data file each round",
			top.Fingerprints)
	}
	if top := res.Report.Attribution[0]; top.Growth < 20 {
		t.Errorf("the top category accounts for %d descriptors, want the bulk of the growth", top.Growth)
	}
}

// TestUsingUnderflowIsJudgedALeak covers the second defect: a reference count
// that wraps on a double release, so the descriptor can never be reclaimed.
//
// Every segment has its own path, so no single series grows - the shape is "a
// hundred files, one descriptor each", which is exactly the case the attribution
// breakdown exists for. That is why the assertion is on the category and not on
// a per-series verdict.
func TestUsingUnderflowIsJudgedALeak(t *testing.T) {
	fx := startFixture(t, "usingunderflow")
	res := assertLeakAndCategory(t, fx)

	seriesLeaks := 0
	for _, v := range res.Report.Series {
		if v.Leak {
			seriesLeaks++
		}
	}
	if seriesLeaks != 0 {
		t.Errorf("%d series were individually convicted, want 0: each segment is held exactly once, so the growth is only visible in the total",
			seriesLeaks)
	}
}

// TestProcessDyingMidWindowIsNotAVerdict covers the third defect, and it is the
// most important assertion in the corpus.
//
// A process that panics inside the window releases everything the kernel gave it.
// A sampler that read the empty descriptor table after the death would conclude
// that the leak had been fixed - the tool's answer inverted at the moment it
// matters most. The library's contract says every failure is an error and never a
// verdict; this proves it against a real dying process rather than a fake probe.
func TestProcessDyingMidWindowIsNotAVerdict(t *testing.T) {
	fx := startFixture(t, "panicunknown")

	// Prove the process was alive and growing before anything is asserted about
	// the failure. Without this, "the check failed" would also be satisfied by a
	// fixture that never started.
	//
	// The count is the process total, not the fixture's own files: the total is
	// what the check judges, so it is the quantity whose growth makes the failure
	// interesting.
	before := fx.total(t)
	time.Sleep(350 * time.Millisecond)
	if mid := fx.total(t); mid <= before {
		t.Fatalf("%s: held %d descriptors after 350ms, was %d: this fixture is supposed to grow before it dies",
			fx.name, mid, before)
	}

	res, err := fdscope.CheckPID(fx.pid, fdscope.CheckOptions{Interval: sampleInterval, Samples: sampleCount})
	if err == nil {
		if !res.Leaking() {
			t.Fatalf("%s: the process died mid-window and the check answered \"no leak\" - the one answer that must be impossible", fx.name)
		}
		t.Fatalf("%s: the process died mid-window and the check still returned a verdict: %+v", fx.name, res)
	}
	if !strings.Contains(err.Error(), "stopped after") {
		t.Fatalf("%s: error = %v, want it to say how far the run got", fx.name, err)
	}
	// The run must have failed *during* the window, not before it: a check that
	// never got a sample is not evidence about a process dying.
	m := stoppedAfter.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("%s: error = %v, want a sample count", fx.name, err)
	}
	n, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		t.Fatalf("%s: sample count %q: %v", fx.name, m[1], convErr)
	}
	if n < 2 {
		t.Fatalf("%s: the run stopped after %d samples, which is too early to be a mid-window death", fx.name, n)
	}
}

// stoppedAfter pulls the sample count out of the "stopped after N of M samples"
// sentence the library produces.
var stoppedAfter = regexp.MustCompile(`stopped after (\d+) of`)

// TestCorrectedProgramsAreNotConvicted is the reversal the whole corpus needs.
//
// Each program takes -fixed, which is the same code with the accounting fixed:
// the counter is decremented, the release is guarded, the bad release is reported.
// Same rate, same resources, same process shape - one statement different. A
// detector that convicted these would be convicting "a program holding
// descriptors", which is every program.
func TestCorrectedProgramsAreNotConvicted(t *testing.T) {
	for _, name := range []string{"fdlistdrift", "usingunderflow", "panicunknown"} {
		t.Run(name, func(t *testing.T) {
			fx := startFixture(t, name, "-fixed")
			res := fx.check(t)
			if res.Leaking() {
				t.Fatalf("%s -fixed was judged a leak: total %+v", name, res.Report.Total)
			}
			// The verdict has to be a real "no leak", not a refusal that happens
			// to be silent: CheckPID returns an error for a refusal, so reaching
			// here already proves it answered. Assert the confidence is a real
			// level so a None that slipped through would be visible.
			if res.Report.Total.Confidence == fdscope.ConfidenceNone {
				t.Fatalf("%s -fixed: confidence = none, which is not an answer", name)
			}
		})
	}
}
