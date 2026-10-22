package probe

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestParseStartTime covers the parsing rule, including the comm name case that
// breaks every naive implementation.
func TestParseStartTime(t *testing.T) {
	cases := []struct {
		name string
		line string
		want uint64
	}{
		{
			name: "plain",
			// proc_pid_stat(5) fields after comm: 3 state, 4 ppid, 5 pgrp,
			// 6 session, 7 tty_nr, 8 tpgid, 9 flags, 10 minflt, 11 cminflt,
			// 12 majflt, 13 cmajflt, 14 utime, 15 stime, 16 cutime,
			// 17 cstime, 18 priority, 19 nice, 20 num_threads,
			// 21 itrealvalue, 22 starttime, 23 vsize, 24 rss.
			line: "1234 (bash) R 1 1234 1234 0 -1 4194304 " +
				"10 0 1 0 2 3 4 0 5 20 0 1 " + // fields 3..21 (19 values)
				"98765 1234 512", // fields 22..24
			want: 98765,
		},
		{
			name: "comm contains space and parenthesis",
			// A thread named "(my app)" shifts every left-to-right split.
			line: "1234 (my app)) S 1 1234 1234 0 -1 4194304 " +
				"10 0 1 0 2 3 4 0 5 20 0 1 424242 1234 512",
			want: 424242,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStartTime(tc.line)
			if err != nil {
				t.Fatalf("parseStartTime: %v", err)
			}
			if got != tc.want {
				t.Errorf("start time = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestParseStartTimeRejectsMalformed proves a truncated line errors rather than
// silently returning 0, which Compare would otherwise treat as "unknown".
func TestParseStartTimeRejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"",
		"1234 (bash) R 1",
		"no parens at all",
		"1234 (bash) R 1 1234 1234 0 -1 4194304 10 0 1 0 2 3 4 0 5 20 0 1 notanumber 1234 512",
	} {
		if _, err := parseStartTime(line); err == nil {
			t.Errorf("line %q parsed without error", line)
		}
	}
}

// TestStartTimeOfSelfAndMissingProcess exercises the file reading path against
// the live kernel and the error classification for a pid that cannot exist.
func TestStartTimeOfSelfAndMissingProcess(t *testing.T) {
	if !IsSupported() {
		t.Skip("no Linux /proc available")
	}
	p := NewProbe()

	start, err := p.StartTime(pidOfSelf(t))
	if err != nil {
		t.Fatalf("StartTime(self): %v", err)
	}
	if start == 0 {
		t.Error("start time is 0; a real process always has a non-zero value")
	}

	if _, err := p.StartTime(999999999); !errors.Is(err, ErrNoSuchProcess) {
		t.Errorf("missing process error = %v, want ErrNoSuchProcess", err)
	}
}

// TestSnapshotsOf exercises the multi-sample capture used by `fdscope diff`.
func TestSnapshotsOf(t *testing.T) {
	if !IsSupported() {
		t.Skip("no Linux /proc available")
	}
	p := NewProbe()
	pid := pidOfSelf(t)

	pair1, err := p.SnapshotsOf(pid, 1, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("SnapshotsOf: %v", err)
	}
	if pair1.Before.Len() == 0 {
		t.Fatal("first snapshot holds no descriptors")
	}
	if pair1.BeforeStart == 0 {
		t.Fatal("start time unavailable")
	}

	// A real descriptor must show up in a real snapshot: open one, take a
	// snapshot and find it. Asserting on the descriptor list rather than on a
	// count keeps this honest when the runtime opens fds behind our back.
	f := openTempFile(t)
	wantFP, wantKind := p.Normalizer.Fingerprint(f.Name())

	pair2, err := p.SnapshotsOf(pid, 2, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("SnapshotsOf: %v", err)
	}
	if pair2.AfterStart != pair1.BeforeStart {
		t.Fatalf("start time changed within one test: %d -> %d", pair1.BeforeStart, pair2.AfterStart)
	}
	if pair2.After.Taken < pair2.Before.Taken {
		t.Fatalf("second sample is older than the first: %d < %d", pair2.After.Taken, pair2.Before.Taken)
	}
	after := pair2.After

	var found bool
	for _, d := range after.Descriptors {
		if d.FD == int(f.Fd()) {
			found = true
			if d.Fingerprint != wantFP {
				t.Errorf("fd %d fingerprint = %q, want %q", d.FD, d.Fingerprint, wantFP)
			}
			if d.Kind != wantKind {
				t.Errorf("fd %d kind = %q, want %q", d.FD, d.Kind, wantKind)
			}
		}
	}
	if !found {
		t.Errorf("descriptor %d for %s missing from the snapshot", f.Fd(), f.Name())
	}
}

func TestSnapshotsOfRejectsBadArguments(t *testing.T) {
	p := NewProbe()
	if _, err := p.SnapshotsOf(0, 1, time.Millisecond); err == nil {
		t.Error("pid 0 accepted")
	}
	if _, err := p.SnapshotsOf(1, 0, time.Millisecond); err == nil {
		t.Error("count 0 accepted")
	}
	if !IsSupported() {
		return
	}
	if _, err := p.SnapshotsOf(pidOfSelf(t), 2, -time.Second); err == nil {
		t.Error("negative delay accepted")
	}
}

// pidOfSelf and openTempFile live in the test file rather than in production
// code: the package must not ship helpers that only tests use.
func pidOfSelf(t *testing.T) int {
	t.Helper()
	return os.Getpid()
}

// openTempFile creates a uniquely named open file so that a snapshot can be
// asserted on a descriptor whose fingerprint cannot be shared with anything
// else the process holds.
func openTempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", "fdscope-probe-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	t.Cleanup(func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	})
	return f
}
