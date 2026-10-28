package probe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if got, want := snap.OpenLimit.Soft, 4096; got != want {
		t.Errorf("OpenLimit.Soft = %d, want %d", got, want)
	}
	if !snap.OpenLimit.Known() {
		t.Errorf("OpenLimit state = %q, want known", snap.OpenLimit.State)
	}
	if got, want := snap.OpenLimit.Hard, 1048576; got != want {
		t.Errorf("OpenLimit.Hard = %d, want the hard column %d", got, want)
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

func TestOpenLimitUnknownIsNotZero(t *testing.T) {
	root := t.TempDir()
	// No limits file at all: the limit must be reported as unknown, never as
	// unlimited and never as a number. "Unknown" and "unlimited" lead to
	// opposite risk reads, and 0 turns every headroom subtraction negative.
	writeFakeProc(t, root, 11, map[string]string{"0": "/dev/null"})

	snap, err := newTestProbe(root).Snapshot(11)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !snap.OpenLimit.Unknown() {
		t.Errorf("OpenLimit state = %q, want unknown", snap.OpenLimit.State)
	}
	if snap.OpenLimit.Unlimited() {
		t.Error("a missing limits file was reported as unlimited")
	}
	if _, ok := snap.OpenLimit.Remaining(10); ok {
		t.Error("Remaining reported a number for an unknown limit")
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
	if got := snap.OpenLimit.Soft; got != 1024 {
		t.Errorf("OpenLimit.Soft = %d, want soft limit 1024 (not the 1048576 hard limit)", got)
	}
	if got := snap.OpenLimit.Hard; got != 1048576 {
		t.Errorf("OpenLimit.Hard = %d, want 1048576", got)
	}
}

// TestParseLimitsThreeStates pins the three answers the kernel can give, using
// the literal text of real /proc/<pid>/limits files.
//
// The "unlimited" case cannot be arranged on a normal machine - root can raise
// RLIMIT_NOFILE but the container's hard limit is still a number - so the text
// is the fixture. The states, not the plumbing, are what go wrong.
func TestParseLimitsThreeStates(t *testing.T) {
	cases := []struct {
		name string
		text string
		want model.OpenLimit
	}{
		{
			name: "finite",
			text: "Limit                     Soft Limit           Hard Limit           Units\n" +
				"Max open files            4096                 1048576              files\n",
			want: model.KnownLimitPair(4096, 1048576),
		},
		{
			name: "unlimited",
			text: "Limit                     Soft Limit           Hard Limit           Units\n" +
				"Max open files            unlimited            unlimited            files\n",
			want: model.UnlimitedLimit(),
		},
		{
			// The container's real shape: soft unlimited, hard a number. The
			// soft column governs EMFILE, so this is unlimited for our purposes.
			name: "soft unlimited with finite hard",
			text: "Max open files            unlimited            1048576              files\n",
			want: model.UnlimitedLimit(),
		},
		{
			name: "soft numeric with unlimited hard",
			text: "Max open files            1024                 unlimited            files\n",
			want: model.KnownLimit(1024),
		},
		{
			name: "no matching line",
			text: "Max processes             100                  200                  processes\n",
			want: model.UnknownLimit(),
		},
		{
			name: "garbage",
			text: "Max open files            lots                 lots                 files\n",
			want: model.UnknownLimit(),
		},
		{
			name: "empty",
			text: "",
			want: model.UnknownLimit(),
		},
		{
			// A parse that yields 0 must not become "known 0": every headroom
			// subtraction would come out negative and report an emergency.
			name: "zero is not a known limit",
			text: "Max open files            0                    0                    files\n",
			want: model.UnknownLimit(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLimits(tc.text)
			if got.StateOrUnknown() != tc.want.StateOrUnknown() {
				t.Fatalf("state = %q, want %q", got.StateOrUnknown(), tc.want.StateOrUnknown())
			}
			if got.Soft != tc.want.Soft {
				t.Errorf("Soft = %d, want %d", got.Soft, tc.want.Soft)
			}
			if got.Hard != tc.want.Hard {
				t.Errorf("Hard = %d, want %d", got.Hard, tc.want.Hard)
			}
		})
	}
}

// TestSnapshotReportsUnlimitedLimit walks the unlimited state through the real
// snapshot path, not just the parser.
//
// A live process with RLIMIT_NOFILE = unlimited cannot be arranged in this
// container - `ulimit -Hn unlimited` is refused even as root - so the fixture is
// a synthetic /proc tree. That is a limitation of the environment, not of the
// code path: Snapshot reads the same file through the same parser either way.
func TestSnapshotReportsUnlimitedLimit(t *testing.T) {
	root := t.TempDir()
	pidDir := writeFakeProc(t, root, 14, map[string]string{"0": "/dev/null"})
	writeLimits(t, pidDir, "Limit                     Soft Limit           Hard Limit           Units\n"+
		"Max open files            unlimited            unlimited            files     \n")

	snap, err := newTestProbe(root).Snapshot(14)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !snap.OpenLimit.Unlimited() {
		t.Fatalf("OpenLimit state = %q, want unlimited", snap.OpenLimit.State)
	}
	if _, ok := snap.OpenLimit.Remaining(5); ok {
		t.Error("an unlimited limit produced a remaining count")
	}

	h := model.NewHeadroom(14, snap.Len(), snap.OpenLimit)
	if got := h.String(); !strings.Contains(got, "unlimited") {
		t.Errorf("Headroom.String() = %q, want it to say unlimited", got)
	}
	if got := h.String(); strings.Contains(got, "remaining") {
		t.Errorf("Headroom.String() = %q offered a remaining count for an unlimited limit", got)
	}
}

// TestOpenLimitOfRealProcess reads the limit of this very process, which is the
// one case a synthetic fixture cannot prove: the real file's column order.
func TestOpenLimitOfRealProcess(t *testing.T) {
	if !IsSupported() {
		t.Skip("no Linux /proc available")
	}
	lim := NewProbe().OpenLimit(os.Getpid())
	if lim.Unknown() {
		t.Fatal("the limit of this process could not be read; /proc/<pid>/limits is always present on Linux")
	}
	if lim.Known() && lim.Soft <= 0 {
		t.Errorf("known limit with Soft = %d", lim.Soft)
	}
	// The test binary's own open descriptors must fit under a finite limit;
	// if the parser read the wrong column this is where it shows.
	snap, err := NewProbe().Snapshot(os.Getpid())
	if err != nil {
		t.Fatalf("Snapshot(self): %v", err)
	}
	if left, ok := lim.Remaining(snap.Len()); ok && left <= 0 {
		t.Errorf("this process is already past its own limit: %d open, limit %d", snap.Len(), lim.Soft)
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
	if snap.OpenLimit.Unknown() {
		t.Error("OpenLimit is unknown for a live process; /proc/<pid>/limits is always readable for self")
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
