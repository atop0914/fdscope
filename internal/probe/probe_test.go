package probe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// writeFakeProc builds a minimal /proc/<pid> tree under dir.
//
// Tests use a synthetic tree rather than the real /proc for two reasons: real
// descriptor contents vary by machine (so assertions would be unreproducible),
// and the interesting cases - deleted files, unreadable entries, unknown
// limits - cannot be arranged on demand against the live kernel.
func writeFakeProc(t *testing.T, dir string, pid int, links map[string]string) string {
	t.Helper()
	pidDir := filepath.Join(dir, itoa(pid))
	fdDir := filepath.Join(pidDir, "fd")
	infoDir := filepath.Join(pidDir, "fdinfo")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(infoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(fdDir, name)); err != nil {
			// Some /proc-style targets are not valid symlink payloads on all
			// filesystems; a regular file keeps the entry present so the test
			// still exercises counting.
			if werr := os.WriteFile(filepath.Join(fdDir, name), nil, 0o644); werr != nil {
				t.Fatalf("create fd entry %s: %v", name, werr)
			}
		}
	}
	return pidDir
}

func writeLimits(t *testing.T, pidDir string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(pidDir, "limits"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func newTestProbe(root string) *Probe {
	p := NewProbe()
	p.ProcRoot = root
	p.Normalizer.HomeDir = "/home/alice"
	return p
}

func TestSnapshotCountsAndSorts(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{
		"0": "/dev/null",
		"1": "/var/log/app.log",
		"3": "/var/log/app.log.2026-10-22",
		"7": "socket:[12345]",
		"9": "/tmp/scratch (deleted)",
	}
	pidDir := writeFakeProc(t, root, 4242, links)
	writeLimits(t, pidDir, "Max open files            4096                 1048576              files     \n")

	snap, err := newTestProbe(root).Snapshot(4242)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if got, want := snap.Len(), 5; got != want {
		t.Errorf("descriptor count = %d, want %d", got, want)
	}
	if !snap.Complete() {
		t.Errorf("snapshot reported as incomplete, Unreadable=%d", snap.Unreadable)
	}
	if got, want := snap.OpenLimit, 4096; got != want {
		t.Errorf("OpenLimit = %d, want %d", got, want)
	}

	// Ordering must be numeric, not lexicographic: fd 9 sorts after fd 7, and
	// fd 10 would sort after 9 even though "10" < "9" as a string.
	for i := 1; i < len(snap.Descriptors); i++ {
		if snap.Descriptors[i-1].FD >= snap.Descriptors[i].FD {
			t.Fatalf("descriptors not sorted ascending at index %d: %d then %d",
				i, snap.Descriptors[i-1].FD, snap.Descriptors[i].FD)
		}
	}

	// The rotated log and the live log must share one fingerprint, otherwise a
	// single rotating log looks like unbounded growth.
	byFP := snap.CountByFingerprint()
	if got := len(byFP["file:/var/log/app.log"]); got != 2 {
		t.Errorf("rotated log grouped into %d descriptors, want 2 (fingerprints: %v)", got, byFP)
	}
	if _, ok := byFP["socket"]; !ok {
		t.Errorf("socket fingerprint missing; the inode must be stripped. groups: %v", byFP)
	}
	if _, ok := byFP["deleted:/tmp/scratch"]; !ok {
		t.Errorf("deleted file must keep a distinct fingerprint. groups: %v", byFP)
	}
}

func TestSnapshotNumericOrderingBeyondSingleDigit(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{}
	for _, fd := range []string{"2", "10", "9"} {
		links[fd] = "/dev/null"
	}
	writeFakeProc(t, root, 1, links)

	snap, err := newTestProbe(root).Snapshot(1)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	got := []int{}
	for _, d := range snap.Descriptors {
		got = append(got, d.FD)
	}
	want := []int{2, 9, 10}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ordering = %v, want %v (string sort would give [10 2 9])", got, want)
		}
	}
}

func TestSnapshotIgnoresNonNumericEntries(t *testing.T) {
	root := t.TempDir()
	pidDir := writeFakeProc(t, root, 7, map[string]string{"0": "/dev/null"})
	// A stray non-numeric entry must not be counted as a descriptor.
	if err := os.WriteFile(filepath.Join(pidDir, "fd", "README"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := newTestProbe(root).Snapshot(7)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Len() != 1 {
		t.Errorf("descriptor count = %d, want 1 (non-numeric entries ignored)", snap.Len())
	}
}

func TestSnapshotMissingProcess(t *testing.T) {
	root := t.TempDir()
	_, err := newTestProbe(root).Snapshot(999999)
	if !errors.Is(err, ErrNoSuchProcess) {
		t.Fatalf("err = %v, want ErrNoSuchProcess", err)
	}
}

func TestSnapshotInvalidPID(t *testing.T) {
	root := t.TempDir()
	for _, pid := range []int{0, -1} {
		if _, err := newTestProbe(root).Snapshot(pid); err == nil {
			t.Errorf("pid %d accepted, want error", pid)
		}
	}
}

func TestOpenLimitUnknownReturnsZero(t *testing.T) {
	root := t.TempDir()
	// No limits file at all: the limit must be reported as unknown (0), never
	// as unlimited. "Unknown" and "unlimited" lead to opposite risk reads.
	writeFakeProc(t, root, 11, map[string]string{"0": "/dev/null"})

	snap, err := newTestProbe(root).Snapshot(11)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.OpenLimit != 0 {
		t.Errorf("OpenLimit = %d, want 0 for unknown", snap.OpenLimit)
	}
}

func TestOpenLimitParsesSoftNotHard(t *testing.T) {
	root := t.TempDir()
	pidDir := writeFakeProc(t, root, 12, map[string]string{"0": "/dev/null"})
	writeLimits(t, pidDir, "Limit                     Soft Limit           Hard Limit           Units\n"+
		"Max open files            1024                 1048576              files     \n")

	snap, err := newTestProbe(root).Snapshot(12)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.OpenLimit != 1024 {
		t.Errorf("OpenLimit = %d, want soft limit 1024 (not the 1048576 hard limit)", snap.OpenLimit)
	}
}

func TestExists(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 13, map[string]string{"0": "/dev/null"})
	p := newTestProbe(root)

	if !p.Exists(13) {
		t.Error("Exists(13) = false, want true")
	}
	if p.Exists(14) {
		t.Error("Exists(14) = true, want false")
	}
}

// TestSnapshotOfSelf proves the probe works against the live kernel, not just
// the synthetic tree. This is the only test that can catch a wire-format
// change in /proc that a hand-built fixture would happily keep passing.
func TestSnapshotOfSelf(t *testing.T) {
	if !IsSupported() {
		t.Skip("no Linux /proc available")
	}
	p := NewProbe()
	snap, err := p.Snapshot(os.Getpid())
	if err != nil {
		t.Fatalf("Snapshot(self): %v", err)
	}
	if snap.Len() == 0 {
		t.Fatal("live snapshot has zero descriptors, which is impossible for a running Go process")
	}
	if snap.OpenLimit == 0 {
		t.Error("OpenLimit = 0 for a live process; ulimit is always set")
	}
	// Every descriptor must carry a non-empty fingerprint, or grouping later
	// would collapse everything into one bucket.
	for _, d := range snap.Descriptors {
		if d.Fingerprint == "" {
			t.Errorf("fd %d has empty fingerprint (target %q)", d.FD, d.Target)
		}
	}
	// The descriptor we are reading this test through must be present.
	found := false
	for _, d := range snap.Descriptors {
		if d.Kind == model.KindFile || d.Kind == model.KindPipe || d.Kind == model.KindSocket {
			found = true
			break
		}
	}
	if !found {
		t.Error("no file/pipe/socket descriptors found in a live Go test process")
	}
}
