package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"version"}, &out, &out); err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.HasPrefix(out.String(), "fdscope ") {
		t.Errorf("version output = %q", out.String())
	}
}

func TestNoCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run(nil, &out, &errOut)
	if err == nil {
		t.Fatal("no args accepted, want error")
	}
	if !strings.Contains(errOut.String(), "Usage:") {
		t.Error("usage not printed to stderr")
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	err := Run([]string{"frobnicate"}, &out, &errOut)
	if err == nil {
		t.Fatal("unknown command accepted")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("err = %v", err)
	}
}

func TestHelp(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"--help"}, &out, &out); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(out.String(), "snapshot") {
		t.Errorf("help output missing subcommands: %q", out.String())
	}
}

func TestSnapshotRequiresOnePID(t *testing.T) {
	cases := [][]string{
		{"snapshot"},
		{"snapshot", "1", "2"},
	}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		if err := Run(args, &out, &errOut); err == nil {
			t.Errorf("args %v accepted, want error", args)
		}
	}
}

func TestSnapshotInvalidPID(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"snapshot", "notanumber"}, &out, &errOut); err == nil {
		t.Fatal("non-numeric pid accepted")
	}
}

func TestNegativeTopRejected(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := Run([]string{"snapshot", "1", "--top", "-1"}, &out, &errOut); err == nil {
		t.Fatal("negative --top accepted")
	}
}

// TestExitCode pins the exit-code contract. CI branches on these values, so a
// silent change would turn a failing security gate into a passing one.
func TestExitCode(t *testing.T) {
	if got := ExitCode(nil); got != 0 {
		t.Errorf("nil -> %d, want 0", got)
	}
	if got := ExitCode(errLeakFound); got != 2 {
		t.Errorf("leak -> %d, want 2", got)
	}
	if got := ExitCode(errors.New("boom")); got != 1 {
		t.Errorf("generic -> %d, want 1", got)
	}
}

// TestSnapshotOfSelfJSON exercises the whole path against the live kernel and
// asserts the JSON contract, not just that it ran.
func TestSnapshotOfSelfJSON(t *testing.T) {
	if _, err := os.Stat(filepath.Join("/proc", "self", "fd")); err != nil {
		t.Skip("no Linux /proc available")
	}

	var out, errOut bytes.Buffer
	if err := Run([]string{"snapshot", itoa(os.Getpid()), "--json"}, &out, &errOut); err != nil {
		t.Fatalf("snapshot: %v (stderr %q)", err, errOut.String())
	}

	var rep snapshotReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if rep.PID != os.Getpid() {
		t.Errorf("pid = %d, want %d", rep.PID, os.Getpid())
	}
	if rep.Total == 0 {
		t.Error("total = 0 for a live process")
	}
	if len(rep.Groups) == 0 {
		t.Error("no fingerprint groups reported")
	}
	if !rep.Complete {
		t.Errorf("live snapshot reported incomplete (unreadable=%d)", rep.Unreadable)
	}
	// The sum of group counts must equal the reported total, otherwise the
	// report contradicts itself and a reader cannot trust either number.
	sum := 0
	for _, g := range rep.Groups {
		sum += g.Count
	}
	if sum != rep.Total {
		t.Errorf("group counts sum to %d but total says %d", sum, rep.Total)
	}
}

func TestTopLimitsGroups(t *testing.T) {
	if _, err := os.Stat(filepath.Join("/proc", "self", "fd")); err != nil {
		t.Skip("no Linux /proc available")
	}
	var out bytes.Buffer
	if err := Run([]string{"snapshot", itoa(os.Getpid()), "--json", "--top", "1"}, &out, &out); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var rep snapshotReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Groups) > 1 {
		t.Errorf("--top 1 returned %d groups", len(rep.Groups))
	}
}

// TestPIDAfterFlags proves the reordering works: without it, flag.Parse stops
// at the pid and silently ignores every flag that follows.
func TestPIDAfterFlags(t *testing.T) {
	if _, err := os.Stat(filepath.Join("/proc", "self", "fd")); err != nil {
		t.Skip("no Linux /proc available")
	}
	pid := itoa(os.Getpid())

	for _, args := range [][]string{
		{"snapshot", pid, "--json"},
		{"snapshot", "--json", pid},
	} {
		var out bytes.Buffer
		if err := Run(args, &out, &out); err != nil {
			t.Fatalf("args %v: %v", args, err)
		}
		// JSON is the observable proof that --json was honoured in both orders.
		if !strings.HasPrefix(strings.TrimSpace(out.String()), "{") {
			t.Errorf("args %v did not produce JSON, so the flag was ignored:\n%s", args, out.String())
		}
	}
}

func TestMissingProcess(t *testing.T) {
	if _, err := os.Stat(filepath.Join("/proc", "self", "fd")); err != nil {
		t.Skip("no Linux /proc available")
	}
	var out, errOut bytes.Buffer
	// pid 999999999 is above /proc/sys/kernel/pid_max by default.
	if err := Run([]string{"snapshot", "999999999"}, &out, &errOut); err == nil {
		t.Fatal("nonexistent pid accepted")
	}
}

// TestWriteErrorPropagates proves a truncated write is reported rather than
// swallowed. This matters because `fdscope snapshot 1 | head -1` closes the
// pipe early, and exiting 0 there would tell CI the report was complete.
func TestWriteErrorPropagates(t *testing.T) {
	if _, err := os.Stat(filepath.Join("/proc", "self", "fd")); err != nil {
		t.Skip("no Linux /proc available")
	}
	w := &failingWriter{remaining: 8}
	err := Run([]string{"snapshot", itoa(os.Getpid())}, w, &bytes.Buffer{})
	if err == nil {
		t.Fatal("write failure was swallowed; a truncated report must not exit 0")
	}
}

// failingWriter accepts a limited number of bytes then fails, emulating a
// closed pipe.
type failingWriter struct{ remaining int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("broken pipe")
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errors.New("broken pipe")
	}
	w.remaining -= len(p)
	return len(p), nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
