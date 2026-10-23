package probe

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// TestParseZombie covers the parsing directly, including the comm shapes that
// break a naive whitespace split: a process name containing a space and one
// containing parentheses.
func TestParseZombie(t *testing.T) {
	cases := []struct {
		name string
		stat string
		want bool
	}{
		{"running", "1000 (bash) S 1 1000 1000 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 0 0", false},
		{"zombie", "1000 (bash) Z 1 1000 1000 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 0 0", true},
		{"comm with space", "1000 (my app) Z 1 1000 1000 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 0 0", true},
		{"comm with parens", "1000 (my (app)) Z 1 1000 1000 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 0 0", true},
		{"disk sleep", "1000 (bash) D 1 1000 1000 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 0 0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseZombie(tc.stat)
			if err != nil {
				t.Fatalf("parseZombie: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseZombie = %v, want %v", got, tc.want)
			}
		})
	}
	if _, err := parseZombie("garbage"); err == nil {
		t.Error("parseZombie accepted a malformed stat line")
	}
	if _, err := parseZombie("1000 (bash)"); err == nil {
		t.Error("parseZombie accepted a stat line with no state field")
	}
}

// TestSnapshotRefusesZombie is the regression test for a real defect.
//
// A zombie keeps its /proc directory and answers readdir on /fd with an empty
// list. Before this check existed, Snapshot returned a valid-looking snapshot with
// zero descriptors - so an audit that sampled a process the moment it died
// reported every descriptor as released, which is the exact inverse of the truth
// for a leak. The assertion is on the error, and the reverse assertion below pins
// that a live process holding nothing open is still accepted.
func TestSnapshotRefusesZombie(t *testing.T) {
	// A child that exits immediately becomes a zombie until reaped: its parent,
	// this test, deliberately does not call Wait until the assertions are done.
	cmd := exec.Command("sh", "-c", "exec sleep 0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Wait()
	})

	pid := cmd.Process.Pid
	// Wait for the state to actually become Z. Asserting on a process that might
	// still be alive would make this test pass for the wrong reason.
	p := NewProbe()
	var dead bool
	for attempt := 0; attempt < 500; attempt++ {
		state, err := p.exited(pid)
		if err != nil {
			t.Fatalf("read state of %d: %v", pid, err)
		}
		if state {
			dead = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !dead {
		t.Fatalf("child %d never became a zombie", pid)
	}

	// The /proc entry still exists - that is what makes this case dangerous.
	if !p.Exists(pid) {
		t.Fatalf("pid %d has no /proc entry; the zombie premise did not hold", pid)
	}
	// And the fd directory is present but empty, which is exactly what used to be
	// read as "holds zero descriptors".
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		t.Logf("fd directory unreadable (%v); the zombie check still must reject", err)
	} else if len(entries) != 0 {
		t.Fatalf("zombie %d still exposes %d descriptors; premise did not hold", pid, len(entries))
	}

	if _, err := p.Snapshot(pid); err == nil {
		t.Fatal("Snapshot returned a snapshot for a zombie; an audit would read this as 'every descriptor was released'")
	} else if !errors.Is(err, ErrProcessExited) {
		t.Errorf("Snapshot error = %v, want ErrProcessExited", err)
	}
}

// TestSnapshotAcceptsLiveIdleProcess is the reverse assertion for the zombie
// check: a live process that genuinely holds almost nothing open must still be
// sampled. A check that rejected every process with few descriptors would be worse
// than the bug it fixed.
func TestSnapshotAcceptsLiveIdleProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	snap, err := NewProbe().Snapshot(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Snapshot of a live child: %v", err)
	}
	if !snap.Complete() {
		t.Errorf("snapshot of a live child is incomplete: unreadable=%d", snap.Unreadable)
	}
	// `sleep` holds at least its own stdio descriptors; a zero count here would
	// mean the probe returned nothing and still claimed success.
	if snap.Len() == 0 {
		t.Error("a live sleep process reported zero descriptors")
	}
}
