package probe

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// TestParseStatusCounters covers the two readings taken from /proc/<pid>/status.
//
// The cases that matter are the ones where a key is absent or carries a unit this
// build does not understand: each must leave that counter unknown rather than
// produce a zero, because "0 RSS" and "VmRSS not reported" are different facts and
// only one of them is true of a kernel thread.
func TestParseStatusCounters(t *testing.T) {
	cases := []struct {
		name        string
		text        string
		wantThreads model.Counter
		wantRSS     model.Counter
	}{
		{
			name:        "typical",
			text:        "Name:\tapp\nState:\tS (sleeping)\nThreads:\t12\nVmRSS:\t  20480 kB\n",
			wantThreads: model.NewCounter(12),
			// VmRSS is in kB and is reported in bytes, so a caller comparing it
			// with a memory figure does not have to know the kernel's unit.
			wantRSS: model.NewCounter(20480 * 1024),
		},
		{
			name:        "kernel thread has no VmRSS",
			text:        "Name:\tkworker\nState:\tI (idle)\nThreads:\t1\n",
			wantThreads: model.NewCounter(1),
			wantRSS:     model.UnknownCounter(),
		},
		{
			name:        "VmRSS in an unexpected unit is not guessed",
			text:        "Threads:\t3\nVmRSS:\t  20480 MB\n",
			wantThreads: model.NewCounter(3),
			wantRSS:     model.UnknownCounter(),
		},
		{
			name:        "unparsable numbers stay unknown",
			text:        "Threads:\tmany\nVmRSS:\t  lots kB\n",
			wantThreads: model.UnknownCounter(),
			wantRSS:     model.UnknownCounter(),
		},
		{
			name:        "zero threads is not a reading",
			text:        "Threads:\t0\n",
			wantThreads: model.UnknownCounter(),
			wantRSS:     model.UnknownCounter(),
		},
		{
			name:        "empty file",
			text:        "",
			wantThreads: model.UnknownCounter(),
			wantRSS:     model.UnknownCounter(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			threads, rss := parseStatusCounters(tc.text)
			if threads != tc.wantThreads {
				t.Errorf("threads = %+v, want %+v", threads, tc.wantThreads)
			}
			if rss != tc.wantRSS {
				t.Errorf("rss = %+v, want %+v", rss, tc.wantRSS)
			}
		})
	}
}

// TestParseIOCounters covers syscr/syscw, including a zero that is a real answer.
//
// syscw 0 for a process that has never written is a fact the report is allowed to
// state; it is only "unknown" when the file itself could not be read (proved in
// TestSnapshotCountersUnknownWhenUnreadable).
func TestParseIOCounters(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		wantRead  model.Counter
		wantWrite model.Counter
	}{
		{
			name:      "typical",
			text:      "rchar: 9000\nwchar: 300\nsyscr: 120\nsyscw: 45\n",
			wantRead:  model.NewCounter(120),
			wantWrite: model.NewCounter(45),
		},
		{
			name:      "zero writes is a reading, not an absence",
			text:      "rchar: 0\nwchar: 0\nsyscr: 7\nsyscw: 0\n",
			wantRead:  model.NewCounter(7),
			wantWrite: model.NewCounter(0),
		},
		{
			name:      "older kernel without syscw",
			text:      "rchar: 9000\nsyscr: 120\n",
			wantRead:  model.NewCounter(120),
			wantWrite: model.UnknownCounter(),
		},
		{
			name:      "empty file",
			text:      "",
			wantRead:  model.UnknownCounter(),
			wantWrite: model.UnknownCounter(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			syscr, syscw := parseIOCounters(tc.text)
			if syscr != tc.wantRead {
				t.Errorf("syscr = %+v, want %+v", syscr, tc.wantRead)
			}
			if syscw != tc.wantWrite {
				t.Errorf("syscw = %+v, want %+v", syscw, tc.wantWrite)
			}
		})
	}
}

// TestSnapshotCarriesCounters proves the readings reach the snapshot rather than
// being parsed and dropped - the failure mode a parsing-only test cannot see.
func TestSnapshotCarriesCounters(t *testing.T) {
	root := t.TempDir()
	pidDir := writeFakeProc(t, root, 4242, map[string]string{"0": "/dev/null"})
	writeFile(t, pidDir, "status", "Name:\tapp\nThreads:\t9\nVmRSS:\t   1024 kB\n")
	writeFile(t, pidDir, "io", "syscr: 300\nsyscw: 4\n")

	snap, err := newTestProbe(root).Snapshot(4242)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got, want := snap.Counters.Threads, model.NewCounter(9); got != want {
		t.Errorf("threads = %+v, want %+v", got, want)
	}
	if got, want := snap.Counters.SyscallsRead, model.NewCounter(300); got != want {
		t.Errorf("syscr = %+v, want %+v", got, want)
	}
	if got, want := snap.Counters.SyscallsWrite, model.NewCounter(4); got != want {
		t.Errorf("syscw = %+v, want %+v", got, want)
	}
	if got, want := snap.Counters.RSSBytes, model.NewCounter(1024*1024); got != want {
		t.Errorf("rss = %+v, want %+v", got, want)
	}
}

// TestSnapshotCountersUnknownWhenUnreadable is the honesty assertion for Day 8's
// data layer: a missing /proc/<pid>/io must leave syscr and syscw unknown, not
// zero.
//
// A zero here would be worse than a missing number. A counter at 0 that never
// moves looks exactly like a process that is not writing, so a correlation layer
// would quietly rule out the very activity it was supposed to find - and nothing
// in the report would show that the reading never happened.
func TestSnapshotCountersUnknownWhenUnreadable(t *testing.T) {
	root := t.TempDir()
	// status present, io absent: the state of a process owned by another user
	// without CAP_SYS_PTRACE.
	pidDir := writeFakeProc(t, root, 4243, map[string]string{"0": "/dev/null"})
	writeFile(t, pidDir, "status", "Threads:\t5\nVmRSS:\t  512 kB\n")

	snap, err := newTestProbe(root).Snapshot(4243)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got := snap.Counters.SyscallsRead; got.Known || got.Value != 0 {
		t.Errorf("syscr = %+v, want unknown", got)
	}
	if got := snap.Counters.SyscallsWrite; got.Known || got.Value != 0 {
		t.Errorf("syscw = %+v, want unknown", got)
	}
	// The counters that were readable must still be reported: one missing file
	// may not blank the whole set.
	if got, want := snap.Counters.Threads, model.NewCounter(5); got != want {
		t.Errorf("threads = %+v, want %+v (a missing io file may not clear status readings)", got, want)
	}
}

// TestSnapshotNeedsNoCountersToSucceed proves a missing auxiliary file never fails
// the snapshot. Losing the descriptor table - the evidence the caller came for -
// over an optional counter would be the wrong trade.
func TestSnapshotNeedsNoCountersToSucceed(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 4244, map[string]string{"0": "/dev/null", "1": "/var/log/app.log"})

	snap, err := newTestProbe(root).Snapshot(4244)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got, want := snap.Len(), 2; got != want {
		t.Errorf("descriptor count = %d, want %d", got, want)
	}
}

// TestCountersOfRealProcess reads the counters of this test process.
//
// It is the only check that the field names are the ones the running kernel
// actually uses: the fixture tests above would keep passing if the kernel renamed
// Threads, because they feed the parser its own expected input.
func TestCountersOfRealProcess(t *testing.T) {
	p := NewProbe()
	snap, err := p.Snapshot(os.Getpid())
	if err != nil {
		t.Fatalf("Snapshot(self): %v", err)
	}
	if !snap.Counters.Threads.Known || snap.Counters.Threads.Value < 1 {
		t.Errorf("threads = %+v, want at least one thread for a running test process", snap.Counters.Threads)
	}
	if !snap.Counters.RSSBytes.Known || snap.Counters.RSSBytes.Value <= 0 {
		t.Errorf("rss = %+v, want a positive resident set", snap.Counters.RSSBytes)
	}
	// /proc/<pid>/io exists only when the kernel was built with
	// CONFIG_TASK_IO_ACCOUNTING, and several container kernels are not. The
	// assertion is therefore conditional on the file's presence - but sharp in both
	// directions: present must mean readable, absent must mean unknown rather than
	// a zero the report could mistake for "this process never wrote".
	_, ioErr := os.Stat(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "io"))
	wantIOCounters := ioErr == nil
	if got := snap.Counters.SyscallsRead.Known; got != wantIOCounters {
		t.Errorf("syscr known = %t, want %t (is this kernel's /proc/<pid>/io readable? %v)",
			got, wantIOCounters, ioErr)
	}
	if got := snap.Counters.SyscallsWrite.Known; got != wantIOCounters {
		t.Errorf("syscw known = %t, want %t", got, wantIOCounters)
	}
}

// writeFile writes one file into a fake /proc/<pid> directory.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
