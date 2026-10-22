package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests run the shipped binary against real child processes.
//
// A Snapshot built in Go would prove nothing: the whole claim of the tool is
// that it observes what a process actually does to its own descriptors. Every
// assertion below is made on descriptors the kernel really assigned, and the
// children are driven by their own shell scripts so the timing is part of what
// is tested rather than something the test fakes.
//
// The scripts block on `while :; do sleep 0.02; done` rather than on a pipe.
// That matters: a pipe can only be waited on once (a second read after EOF
// returns immediately), so a fixture built on one cannot be sampled, changed and
// sampled again - the exact sequence a diff needs.

// buildCLI compiles the command once per test binary and returns its path.
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fdscope")
	out, err := exec.Command("go", "build", "-o", bin, "../../cmd/fdscope").CombinedOutput()
	if err != nil {
		t.Fatalf("build fdscope: %v\n%s", err, out)
	}
	return bin
}

// child is a shell script running in the background under test control.
type child struct {
	cmd *exec.Cmd
	dir string
}

// startChild runs script with sh and waits for marker to appear on its stdout.
//
// marker is printed by the script itself once it has reached the state the test
// wants to observe, so no sleep decides when sampling happens.
func startChild(t *testing.T, script, marker string) *child {
	t.Helper()
	return startChildWith(t, "sh", script, marker)
}

// startChildWith is startChild with an explicit interpreter.
func startChildWith(t *testing.T, shell, script, marker string) *child {
	t.Helper()
	dir := t.TempDir()
	full := "d=" + shellQuote(dir) + "\n" + script

	cmd := exec.Command(shell, "-c", full)
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd.Stdout = outW
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	// The child owns this end now; keeping a copy would prevent EOF.
	_ = outW.Close()

	ch := &child{cmd: cmd, dir: dir}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = outR.Close()
	})

	// Read until the marker. Reading in the test goroutine (not a helper
	// goroutine) means a script that dies before the marker fails the test
	// immediately instead of hanging.
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 512)
		for {
			n, err := outR.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
				if strings.Contains(sb.String(), marker) {
					done <- sb.String()
					// Keep draining so the child never blocks on a full pipe.
					go func() {
						_, _ = outR.Read(make([]byte, 4096))
					}()
					return
				}
			}
			if err != nil {
				done <- sb.String()
				return
			}
		}
	}()

	select {
	case got := <-done:
		if !strings.Contains(got, marker) {
			t.Fatalf("child exited before printing %q; output:\n%s", marker, got)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("child never printed %q", marker)
	}
	return ch
}

func (c *child) pid() int { return c.cmd.Process.Pid }

// shellQuote wraps s in single quotes so a path containing spaces survives.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runDiffCLI executes the diff command and returns stdout, failing on error.
func runDiffCLI(t *testing.T, bin string, pid int, extra ...string) string {
	t.Helper()
	args := append([]string{"diff", strconv.Itoa(pid), "--interval", "100ms"}, extra...)
	cmd := exec.Command(bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("fdscope %v: %v\nstdout:\n%s\nstderr:\n%s", args, err, out.String(), errOut.String())
	}
	return out.String()
}

// diffJSON is the wire shape asserted on. Field names here mirror the shipped
// JSON contract; a rename in the report breaks these tests on purpose.
type diffJSON struct {
	PID          int `json:"pid"`
	BeforeTotal  int `json:"before_total"`
	AfterTotal   int `json:"after_total"`
	NetChange    int `json:"net_change"`
	Changes      []changeJSON
	Added        []changeJSON     `json:"added"`
	Removed      []changeJSON     `json:"removed"`
	DeletedFiles deletedFilesJSON `json:"deleted_files"`
	Notes        []string         `json:"notes"`
}

type changeJSON struct {
	Fingerprint string `json:"fingerprint"`
	Kind        string `json:"kind"`
	Before      int    `json:"before"`
	After       int    `json:"after"`
	Delta       int    `json:"delta"`
	Sample      string `json:"sample"`
	Deleted     bool   `json:"deleted"`
}

type deletedFilesJSON struct {
	Files []struct {
		Fingerprint       string `json:"fingerprint"`
		Path              string `json:"path"`
		OpenCount         int    `json:"open_count"`
		WritableOpenCount int    `json:"writable_open_count"`
		Sample            string `json:"sample"`
	} `json:"files"`
	Usable bool   `json:"usable"`
	Reason string `json:"reason"`
}

func parseDiff(t *testing.T, out string) diffJSON {
	t.Helper()
	var rep diffJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	return rep
}

// TestDiffLeakDetected is the positive case: files opened during the sampling
// window and never closed must be reported.
func TestDiffLeakDetected(t *testing.T) {
	bin := buildCLI(t)
	// bash allocates descriptors explicitly, so five files stay open instead of
	// the last one closing the previous. The opens happen inside the sampling
	// window: the child reports "idle", waits long enough for the first sample,
	// then opens the files and reports "leaked". A leak that already existed
	// before the first sample would be invisible to a diff.
	ch := startChildWith(t, "bash", `
echo idle
sleep 0.6
for f in "$d"/leaked-*.log; do :; done
for i in 0 1 2 3 4; do
  exec {fd}>"$d/leaked-$i.log"
done
echo leaked
while :; do sleep 0.05; done
`, "idle")

	rep := parseDiff(t, runDiffCLI(t, bin, ch.pid(), "--json", "--interval", "700ms"))

	leaked, rows := 0, 0
	for _, c := range rep.Changes {
		if !strings.Contains(c.Fingerprint, "/leaked-") {
			continue
		}
		leaked += c.Delta
		rows++
		if c.After != 1 {
			t.Errorf("%q count = %d, want 1 (distinct paths are distinct resources)", c.Fingerprint, c.After)
		}
	}
	if leaked != 5 {
		t.Errorf("leaked descriptors = %d, want 5 (changes: %+v)", leaked, rep.Changes)
	}
	// Five distinct paths must stay five rows: merging them would hide a leak.
	if rows != 5 {
		t.Errorf("leaked rows = %d, want 5: %+v", rows, rep.Changes)
	}
}

// TestDiffQuietProcessNoNoise is the reverse assertion that keeps the tool
// usable: a process doing nothing must produce an empty diff.
func TestDiffQuietProcessNoNoise(t *testing.T) {
	bin := buildCLI(t)
	ch := startChild(t, `
echo ready
while :; do sleep 0.05; done
`, "ready")

	out := runDiffCLI(t, bin, ch.pid(), "--json")
	rep := parseDiff(t, out)
	if len(rep.Changes) != 0 {
		t.Errorf("an idle process reported changes: %+v", rep.Changes)
	}
	if rep.NetChange != 0 {
		t.Errorf("net change = %d, want 0", rep.NetChange)
	}
	if len(rep.DeletedFiles.Files) != 0 {
		t.Errorf("deleted files reported for an idle process: %+v", rep.DeletedFiles.Files)
	}
	// The text form must say "no change" rather than print nothing: empty
	// output is indistinguishable from a failed run.
	text := runDiffCLI(t, bin, ch.pid())
	if !strings.Contains(text, "no fingerprint changed count") {
		t.Errorf("clean diff did not say so:\n%s", text)
	}
	if !strings.Contains(text, "deleted files: none open") {
		t.Errorf("deleted section missing:\n%s", text)
	}
}

// TestDiffDetectsDescriptorReuse is the case a number-based diff cannot see: the
// child closes one file, opens another, and the kernel reuses the number.
//
// The premise is verified against the child's own view of its descriptors before
// any assertion about the report. Without that, a pass could mean the interesting
// situation never occurred.
func TestDiffDetectsDescriptorReuse(t *testing.T) {
	bin := buildCLI(t)
	// bash picks the number that was just freed, so the two samples carry the
	// same descriptor number for two different files. The swap happens inside
	// the sampling window: "staged" means fd 8 holds first.log, the sleep lets
	// the first sample land, and the swap follows.
	ch := startChildWith(t, "bash", `
printf x > "$d/first.log"
exec {fd}<"$d/first.log"
first=$fd
readlink /proc/$$/fd/$fd > "$d/first-path"
echo "first_fd=$fd"
echo staged
sleep 0.6
exec {fd}<&-
printf x > "$d/second.log"
exec {fd}<"$d/second.log"
second=$fd
readlink /proc/$$/fd/$fd > "$d/second-path"
echo "second_fd=$fd"
echo swapped
while :; do sleep 0.05; done
`, "staged")

	firstPath := readTrimmed(t, filepath.Join(ch.dir, "first-path"))

	rep := parseDiff(t, runDiffCLI(t, bin, ch.pid(), "--json", "--interval", "800ms"))

	// Premise first: the kernel must really have handed back the same number.
	// Without this check a pass could mean the interesting situation never
	// happened, which would make the whole test worthless.
	waitForFile(t, filepath.Join(ch.dir, "second-path"))
	secondPath := readTrimmed(t, filepath.Join(ch.dir, "second-path"))
	if firstPath == secondPath {
		t.Fatalf("child did not swap the resource behind one descriptor")
	}

	// Invariant: a number-based diff would see identical fd sets on both sides.
	// The diff must nonetheless report the swap.
	if rep.NetChange != 0 {
		t.Fatalf("net change = %d, want 0: this case exists to show resource "+
			"swaps that leave the count untouched", rep.NetChange)
	}
	// Compare on the base name, not on the full path: fingerprints anonymise
	// the home directory to "~", and the temp dir lives under it here.
	firstBase, secondBase := filepath.Base(firstPath), filepath.Base(secondPath)
	var sawRemoved, sawAdded bool
	for _, c := range rep.Removed {
		if strings.HasSuffix(c.Fingerprint, "/"+firstBase) {
			sawRemoved = true
		}
	}
	for _, c := range rep.Added {
		if strings.HasSuffix(c.Fingerprint, "/"+secondBase) {
			sawAdded = true
		}
	}
	if !sawRemoved || !sawAdded {
		t.Fatalf("the resource behind one descriptor changed but the diff missed "+
			"it (removed=%+v added=%+v); this is the signature of comparing by "+
			"descriptor number", rep.Removed, rep.Added)
	}
}

// TestDiffDeletedFileReported is the operationally valuable case: a file
// unlinked while held open must be listed with its now-nonexistent path, and a
// live file in the same directory must stay out of that list.
func TestDiffDeletedFileReported(t *testing.T) {
	for _, tc := range []struct {
		name     string
		openMode string
		wantWr   bool
	}{
		{"rw", "rw", true},
		{"ro", "<", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := buildCLI(t)
			var script string
			if tc.openMode == "rw" {
				script = `
printf 'payload' > "$d/ghost.dat"
exec 8<>"$d/ghost.dat"
rm -f "$d/ghost.dat"
printf live > "$d/alive.dat"
exec 9<"$d/alive.dat"
echo ready
while :; do sleep 0.05; done
`
			} else {
				script = `
printf 'payload' > "$d/ghost.dat"
exec 8<"$d/ghost.dat"
rm -f "$d/ghost.dat"
printf live > "$d/alive.dat"
exec 9<"$d/alive.dat"
echo ready
while :; do sleep 0.05; done
`
			}
			ch := startChild(t, script, "ready")

			ghost := filepath.Join(ch.dir, "ghost.dat")
			alive := filepath.Join(ch.dir, "alive.dat")
			// The premise: the path really is gone from the filesystem, so this
			// test cannot be describing a live file.
			if _, err := os.Stat(ghost); !os.IsNotExist(err) {
				t.Fatalf("%s still exists (err=%v)", ghost, err)
			}

			rep := parseDiff(t, runDiffCLI(t, bin, ch.pid(), "--json"))
			if !rep.DeletedFiles.Usable {
				t.Fatalf("deleted view unusable: %s", rep.DeletedFiles.Reason)
			}

			var found bool
			for _, f := range rep.DeletedFiles.Files {
				if f.Path == alive {
					t.Errorf("live file %s reported as deleted", alive)
				}
				if f.Path != ghost {
					continue
				}
				found = true
				if f.OpenCount < 1 {
					t.Errorf("open count = %d, want >= 1", f.OpenCount)
				}
				if got := f.WritableOpenCount > 0; got != tc.wantWr {
					t.Errorf("writable = %v (count %d), want %v", got, f.WritableOpenCount, tc.wantWr)
				}
				if !strings.HasSuffix(f.Sample, "(deleted)") {
					t.Errorf("sample %q lacks the kernel's (deleted) marker", f.Sample)
				}
			}
			if !found {
				t.Fatalf("deleted file %s not reported: %+v", ghost, rep.DeletedFiles.Files)
			}

			// The text report must state the size caveat rather than let a
			// reader assume the numbers are disk usage.
			text := runDiffCLI(t, bin, ch.pid())
			if !strings.Contains(text, "sizes are not available") {
				t.Errorf("no size caveat in the reported output:\n%s", text)
			}
		})
	}
}

// TestDiffRequiresTwoSamples pins that a single sample is refused: an empty diff
// would be indistinguishable from "nothing changed".
func TestDiffRequiresTwoSamples(t *testing.T) {
	var out, errOut strings.Builder
	if err := Run([]string{"diff", itoa(os.Getpid()), "--count", "1"}, &out, &errOut); err == nil {
		t.Fatal("--count 1 accepted")
	}
	if out.Len() != 0 {
		t.Errorf("produced a report despite the usage error: %q", out.String())
	}
}

func TestDiffRejectsNegativeInterval(t *testing.T) {
	var out, errOut strings.Builder
	if err := Run([]string{"diff", itoa(os.Getpid()), "--interval", "-1s"}, &out, &errOut); err == nil {
		t.Fatal("negative interval accepted")
	}
	if out.Len() != 0 {
		t.Errorf("produced a report despite the usage error: %q", out.String())
	}
}

// TestDiffMissingProcess proves a nonexistent pid fails instead of producing an
// empty (and therefore reassuring) diff.
func TestDiffMissingProcess(t *testing.T) {
	var out, errOut strings.Builder
	if err := Run([]string{"diff", "999999999", "--interval", "1ms"}, &out, &errOut); err == nil {
		t.Fatal("nonexistent pid accepted")
	}
	if out.Len() != 0 {
		t.Errorf("wrote a report for a missing process: %q", out.String())
	}
}

// TestDiffTableIsWrittenOnce proves the report is built in full before any byte
// reaches the caller. A consumer that stops reading (a closed pipe, `| head`)
// must not decide which sections get built.
func TestDiffTableIsWrittenOnce(t *testing.T) {
	cw := &countingWriter{}
	var errOut strings.Builder
	if err := Run([]string{"diff", itoa(os.Getpid()), "--interval", "20ms"}, cw, &errOut); err != nil {
		t.Fatalf("diff: %v", err)
	}
	if cw.calls != 1 {
		t.Errorf("report reached the caller in %d writes, want 1", cw.calls)
	}
}

type countingWriter struct {
	calls int
	n     int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.calls++
	w.n += len(p)
	return len(p), nil
}

// readTrimmed reads a file the child wrote and strips whitespace.
func readTrimmed(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}

// waitForFile waits until path exists, then a beat longer so the child is
// certainly past its write.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}
