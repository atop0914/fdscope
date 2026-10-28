package diff

import (
	"errors"
	"strings"
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// snap builds a snapshot from fd -> raw target pairs. Fingerprints are computed
// with the same normalizer production uses, so a change to the fingerprint rules
// shows up here rather than being papered over by hand-written expectations.
func snap(t *testing.T, taken int64, fds map[int]string, extras ...func(*model.Snapshot)) model.Snapshot {
	t.Helper()
	n := model.DefaultNormalizer()
	s := model.Snapshot{PID: 4242, Taken: taken, OpenLimit: model.KnownLimit(1024)}
	for fd, target := range fds {
		fp, kind := n.Fingerprint(target)
		s.Descriptors = append(s.Descriptors, model.Descriptor{
			FD:          fd,
			Target:      target,
			Fingerprint: fp,
			Kind:        kind,
			Deleted:     strings.HasSuffix(target, " (deleted)"),
		})
	}
	for _, extra := range extras {
		extra(&s)
	}
	return s
}

func TestCompareDetectsGrowth(t *testing.T) {
	before := snap(t, 100, map[int]string{
		3: "/tmp/app.log",
		4: "/tmp/app.log",
		5: "/dev/null",
	})
	after := snap(t, 200, map[int]string{
		3: "/tmp/app.log",
		4: "/tmp/app.log",
		5: "/dev/null",
		6: "/tmp/app.log",
		7: "/tmp/app.log",
		8: "/tmp/app.log",
	})

	d, err := Compare(before, after, 10, 10)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if d.NetDescriptorChange() != 3 {
		t.Errorf("net change = %d, want 3", d.NetDescriptorChange())
	}
	if len(d.Changes) != 1 {
		t.Fatalf("changes = %d, want 1: %+v", len(d.Changes), d.Changes)
	}
	c := d.Changes[0]
	if c.Fingerprint != "file:/tmp/app.log" {
		t.Errorf("fingerprint = %q", c.Fingerprint)
	}
	if c.Before != 2 || c.After != 5 || c.Delta != 3 {
		t.Errorf("counts = %d -> %d (delta %d), want 2 -> 5 (delta 3)", c.Before, c.After, c.Delta)
	}
	// The unchanged fingerprint must not appear: a report full of "delta 0"
	// rows buries the line that matters.
	for _, ch := range d.Changes {
		if ch.Fingerprint == "/dev/null" {
			t.Error("unchanged device reported as a change")
		}
	}
}

// TestCompareDetectsReuseOfDescriptorNumber is the reason this package compares
// fingerprints at all.
//
// A close followed by an open commonly lands on the same number, so the two
// snapshots have identical fd sets and identical totals. Comparing by number
// would report "no change" for exactly the case fdscope exists to find: one
// resource released and a different one acquired.
func TestCompareDetectsReuseOfDescriptorNumber(t *testing.T) {
	before := snap(t, 100, map[int]string{
		7: "/var/log/old.log",
	})
	after := snap(t, 200, map[int]string{
		7: "/var/log/new.log",
	})

	d, err := Compare(before, after, 10, 10)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if d.NetDescriptorChange() != 0 {
		t.Fatalf("net change = %d, want 0 (the point of this case)", d.NetDescriptorChange())
	}
	if d.Unchanged() {
		t.Fatal("fd 7 changed resource but the diff reports no change; this is the " +
			"signature of comparing by descriptor number instead of fingerprint")
	}
	if len(d.Changes) != 2 {
		t.Fatalf("changes = %+v, want two (one gone, one added)", d.Changes)
	}

	added, removed := d.Added(), d.Removed()
	if len(added) != 1 || added[0].Fingerprint != "file:/var/log/new.log" {
		t.Errorf("added = %+v", added)
	}
	if len(removed) != 1 || removed[0].Fingerprint != "file:/var/log/old.log" {
		t.Errorf("removed = %+v", removed)
	}
}

// TestCompareStableOnUnchangedInput is the reverse assertion: a process that
// only reads must produce an empty diff. Noise here would make the tool
// unusable on any busy process.
func TestCompareStableOnUnchangedInput(t *testing.T) {
	fds := map[int]string{
		3: "/tmp/app.log",
		4: "socket:[111]",
		5: "socket:[222]",
		6: "pipe:[333]",
		7: "/dev/null",
	}
	before := snap(t, 100, fds)
	after := snap(t, 200, fds)

	d, err := Compare(before, after, 99, 99)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !d.Unchanged() {
		t.Errorf("unchanged input produced changes: %+v", d.Changes)
	}
	if len(d.Added()) != 0 || len(d.Removed()) != 0 || len(d.Grew()) != 0 {
		t.Error("unchanged input produced added/removed/grown entries")
	}
	if len(d.DeletedFiles) != 0 {
		t.Errorf("unchanged input produced deleted files: %+v", d.DeletedFiles)
	}
}

// TestCompareIgnoresSocketInodeChurn pins that reconnecting does not look like a
// change: two snapshots with different socket inodes are the same fingerprint.
func TestCompareIgnoresSocketInodeChurn(t *testing.T) {
	before := snap(t, 100, map[int]string{3: "socket:[100]", 4: "socket:[101]"})
	after := snap(t, 200, map[int]string{3: "socket:[900]", 4: "socket:[901]"})

	d, err := Compare(before, after, 10, 10)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !d.Unchanged() {
		t.Errorf("socket inode churn reported as a change: %+v", d.Changes)
	}
}

func TestCompareRejectsDifferentProcesses(t *testing.T) {
	before := snap(t, 100, map[int]string{3: "/tmp/a"})
	after := snap(t, 200, map[int]string{3: "/tmp/a"})
	after.PID = 4243

	if _, err := Compare(before, after, 10, 10); !errors.Is(err, ErrSamePIDRequired) {
		t.Fatalf("err = %v, want ErrSamePIDRequired", err)
	}
}

// TestCompareRejectsRestartedProcess covers the recycled-pid case: same pid,
// different start time. The snapshots look perfectly diffable, which is exactly
// why this must be an error rather than a best effort.
func TestCompareRejectsRestartedProcess(t *testing.T) {
	before := snap(t, 100, map[int]string{3: "/tmp/a"})
	after := snap(t, 200, map[int]string{3: "/tmp/b"})

	if _, err := Compare(before, after, 111, 222); !errors.Is(err, ErrProcessRestarted) {
		t.Fatalf("err = %v, want ErrProcessRestarted", err)
	}
	// An unknown start time is not "same process": it is unproven.
	if _, err := Compare(before, after, 0, 0); !errors.Is(err, ErrProcessRestarted) {
		t.Fatalf("zero start times: err = %v, want ErrProcessRestarted", err)
	}
}

// TestCompareRejectsIncompleteSnapshot proves a partial read is refused instead
// of being silently rendered as "these descriptors disappeared".
func TestCompareRejectsIncompleteSnapshot(t *testing.T) {
	before := snap(t, 100, map[int]string{3: "/tmp/a"}, func(s *model.Snapshot) { s.Unreadable = 2 })
	after := snap(t, 200, map[int]string{3: "/tmp/a"})

	if _, err := Compare(before, after, 10, 10); !errors.Is(err, ErrIncompleteSnapshot) {
		t.Fatalf("err = %v, want ErrIncompleteSnapshot", err)
	}
}

func TestCompareRejectsOutOfOrderSnapshots(t *testing.T) {
	before := snap(t, 200, map[int]string{3: "/tmp/a"})
	after := snap(t, 100, map[int]string{3: "/tmp/a"})

	if _, err := Compare(before, after, 10, 10); err == nil {
		t.Fatal("reversed snapshots accepted")
	}
}

// TestChangesSortedByMagnitude pins the ordering that decides what a reader sees
// first: largest absolute movement, growth before shrinkage at equal size.
func TestChangesSortedByMagnitude(t *testing.T) {
	before := snap(t, 100, map[int]string{
		3:  "/tmp/one",
		4:  "/tmp/two",
		5:  "/tmp/two",
		6:  "/tmp/three",
		7:  "/tmp/three",
		8:  "/tmp/three",
		9:  "/tmp/three",
		10: "/tmp/four",
	})
	after := snap(t, 200, map[int]string{
		3: "/tmp/one",
		4: "/tmp/one",
		5: "/tmp/one",
		6: "/tmp/three",
	})

	d, err := Compare(before, after, 10, 10)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	// three: 4 -> 1 (-3) outranks one: 1 -> 3 (+2) because magnitude decides
	// first; growth only wins a tie.
	want := []string{"file:/tmp/three", "file:/tmp/one", "file:/tmp/two", "file:/tmp/four"}
	if len(d.Changes) != len(want) {
		t.Fatalf("got %d changes, want %d: %+v", len(d.Changes), len(want), d.Changes)
	}
	for i, fp := range want {
		if d.Changes[i].Fingerprint != fp {
			t.Errorf("change %d = %q, want %q (order: %+v)", i, d.Changes[i].Fingerprint, fp, d.Changes)
		}
	}
	// one: 1 -> 3 (+2); two: 2 -> 0 (-2); three: 4 -> 1 (-3); four: 1 -> 0 (-1)
	if d.Changes[0].Delta != -3 || d.Changes[1].Delta != 2 {
		t.Errorf("deltas = %d, %d", d.Changes[0].Delta, d.Changes[1].Delta)
	}
	// Equal magnitude must put growth first: "what is accumulating" is the
	// question a reader has, and a release of the same size must not outrank it.
	if d.Changes[1].Delta < 0 || d.Changes[2].Delta > 0 {
		t.Errorf("equal-magnitude tie put shrinkage first: %+v", d.Changes)
	}
}

// TestDeletedFilesView is the operationally valuable view: unlinked files that
// are still pinned open. `du` cannot see any of them.
func TestDeletedFilesView(t *testing.T) {
	s := model.Snapshot{PID: 1}
	n := model.DefaultNormalizer()
	add := func(fd int, target string, flags uint64) {
		fp, kind := n.Fingerprint(target)
		s.Descriptors = append(s.Descriptors, model.Descriptor{
			FD: fd, Target: target, Fingerprint: fp, Kind: kind,
			Deleted: strings.HasSuffix(target, " (deleted)"), Flags: flags,
		})
	}
	const (
		oRdOnly = 0x0
		oWrOnly = 0x1
		oRdWr   = 0x2
	)
	add(3, "/tmp/ghost (deleted)", oRdWr)
	add(4, "/tmp/ghost (deleted)", oRdWr)
	add(5, "/tmp/readonly (deleted)", oRdOnly)
	add(6, "/tmp/ghost", oRdWr) // the live file at the same path: not deleted

	files := DeletedFiles(s)
	if len(files) != 2 {
		t.Fatalf("deleted files = %+v, want 2", files)
	}
	if files[0].Path != "/tmp/ghost" || files[0].OpenCount != 2 {
		t.Errorf("first entry = %+v", files[0])
	}
	if files[0].WritableOpenCount != 2 || !files[0].HoldsDiskSpace() {
		t.Errorf("writable count = %d, want 2", files[0].WritableOpenCount)
	}
	if files[0].Fingerprint != "deleted:/tmp/ghost" {
		t.Errorf("fingerprint = %q", files[0].Fingerprint)
	}
	// Reverse assertion: the live file must not appear in the deleted view, and
	// its fingerprint must be different from the deleted one.
	if files[1].Path != "/tmp/readonly" {
		t.Errorf("second entry = %+v, want /tmp/readonly", files[1])
	}
	if files[1].HoldsDiskSpace() {
		t.Error("a deleted file opened read-only reported as holding disk space")
	}
	for _, f := range files {
		if f.Path == "/tmp/ghost" && f.OpenCount == 3 {
			t.Error("the live descriptor was counted as a deleted one")
		}
	}
}

// TestDeletedFilesIgnoresPrefixOnly proves the deleted view is driven by the
// kernel's own " (deleted)" suffix, never by a fingerprint that merely looks
// like one. A process can hold a file literally named "deleted:/tmp/x".
func TestDeletedFilesIgnoresPrefixOnly(t *testing.T) {
	n := model.DefaultNormalizer()
	target := "/tmp/deleted:/tmp/x"
	fp, kind := n.Fingerprint(target)
	s := model.Snapshot{PID: 1, Descriptors: []model.Descriptor{{
		FD: 3, Target: target, Fingerprint: fp, Kind: kind, Deleted: false,
	}}}
	if got := DeletedFiles(s); len(got) != 0 {
		t.Errorf("a live file was reported as deleted: %+v", got)
	}
}

// TestDiffReportsDeletedGrowth proves the two views compose: a deleted file that
// gained descriptors shows up both as a change and in the deleted view.
func TestDiffReportsDeletedGrowth(t *testing.T) {
	held := snap(t, 100, map[int]string{3: "/tmp/ghost (deleted)"})
	grown := snap(t, 200, map[int]string{
		3: "/tmp/ghost (deleted)",
		4: "/tmp/ghost (deleted)",
	})

	d, err := Compare(held, grown, 10, 10)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.DeletedFiles) != 1 || d.DeletedFiles[0].After != 2 {
		t.Fatalf("deleted files = %+v", d.DeletedFiles)
	}
	// A released deleted file must leave the view rather than linger at 0.
	releasedSnap := snap(t, 300, map[int]string{})
	released, err := Compare(grown, releasedSnap, 10, 10)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(released.DeletedFiles) != 0 {
		t.Errorf("released deleted file still in view: %+v", released.DeletedFiles)
	}
	if len(released.Removed()) != 1 {
		t.Errorf("released deleted file not reported as removed: %+v", released.Changes)
	}
}
