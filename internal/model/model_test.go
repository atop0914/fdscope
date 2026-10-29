package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFingerprintNormalisation(t *testing.T) {
	n := DefaultNormalizer()
	n.HomeDir = "/home/alice"

	cases := []struct {
		name   string
		target string
		wantFP string
		wantK  FDKind
	}{
		// Sockets: the inode is unique per socket instance, so it must go.
		// Without this, 1000 reconnects look like 1000 distinct resources.
		{"socket drops inode", "socket:[12345]", "socket", KindSocket},
		{"socket other inode", "socket:[99999999]", "socket", KindSocket},

		// Pipes likewise.
		{"pipe drops inode", "pipe:[4242]", "pipe", KindPipe},

		// anon_inode keeps the meaningful payload but drops instance digits.
		{"anon epoll", "anon_inode:[eventpoll]", "anon_inode:eventpoll", KindAnonInode},
		{"anon inotify bracketed", "anon_inode:[inotify]", "anon_inode:inotify", KindAnonInode},
		{"anon inotify already normalised", "anon_inode:inotify", "anon_inode:inotify", KindAnonInode},
		{"anon unnamed", "anon_inode:", "anon_inode:unnamed", KindAnonInode},

		// Plain files keep their path.
		{"regular file", "/var/log/app.log", "file:/var/log/app.log", KindFile},
		{"dev null", "/dev/null", "/dev/null", KindDevice},
		{"dev shm is a file", "/dev/shm/buf", "file:/dev/shm/buf", KindFile},

		// Rotation: every rotation of one log is the same resource.
		{"rotation numeric", "/var/log/app.log.1", "file:/var/log/app.log", KindFile},
		{"rotation multiple", "/var/log/app.log.42", "file:/var/log/app.log", KindFile},
		{"rotation date", "/var/log/app.log.2026-10-22", "file:/var/log/app.log", KindFile},
		{"rotation dashed date", "/var/log/app.log-20261022", "file:/var/log/app.log", KindFile},
		{"rotation datetime", "/var/log/app.log.2026-10-22T03:04:05", "file:/var/log/app.log", KindFile},

		// Extension-looking tails must NOT be stripped.
		{"extension kept", "/var/log/app.log", "file:/var/log/app.log", KindFile},
		{"txt kept", "/tmp/notes.txt", "file:/tmp/notes.txt", KindFile},
		{"numeric basename kept", "/tmp/12345", "file:/tmp/12345", KindFile},

		// Deleted files are their own fingerprint: the action item differs.
		{"deleted file", "/tmp/scratch (deleted)", "deleted:/tmp/scratch", KindDeleted},

		// Home anonymisation stops usernames leaking into shared reports.
		{"home anonymised", "/home/alice/.cache/x", "file:~/.cache/x", KindFile},
		{"home exact", "/home/alice", "file:~", KindFile},
		{"similar prefix kept", "/home/alicia/x", "file:/home/alicia/x", KindFile},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp, kind := n.Fingerprint(tc.target)
			if fp != tc.wantFP {
				t.Errorf("fingerprint(%q) = %q, want %q", tc.target, fp, tc.wantFP)
			}
			if kind != tc.wantK {
				t.Errorf("kind(%q) = %q, want %q", tc.target, kind, tc.wantK)
			}
		})
	}
}

// TestFingerprintIsIdempotent guards against a normaliser that keeps shrinking
// on repeated application, which would make grouping depend on call count.
func TestFingerprintIsIdempotent(t *testing.T) {
	n := DefaultNormalizer()
	n.HomeDir = "/home/alice"

	targets := []string{
		"/var/log/app.log.2026-10-22",
		"/home/alice/a/b/c.log.3",
		"anon_inode:[eventpoll]",
		"socket:[1]",
		"/tmp/x (deleted)",
	}
	for _, target := range targets {
		first, _ := n.Fingerprint(target)
		second, _ := n.Fingerprint(first)
		if first != second {
			t.Errorf("not idempotent for %q: first %q, second %q", target, first, second)
		}
	}
}

// TestFingerprintSeparatesDifferentResources is the reverse assertion: two
// genuinely different leaks must never be merged into one row, because a
// merged report makes the bigger leak invisible.
func TestFingerprintSeparatesDifferentResources(t *testing.T) {
	n := DefaultNormalizer()

	pairs := [][2]string{
		{"/var/log/a.log", "/var/log/b.log"},
		{"/var/log/a.log", "/var/log/sub/a.log"}, // same name, different directory
		{"socket:[1]", "pipe:[1]"},               // same inode number, different kind
		{"/tmp/x", "/tmp/x (deleted)"},           // live vs still-held deleted
		{"/dev/null", "/dev/zero"},               // different devices
	}
	for _, pair := range pairs {
		a, _ := n.Fingerprint(pair[0])
		b, _ := n.Fingerprint(pair[1])
		if a == b {
			t.Errorf("distinct resources collapsed to one fingerprint: %q and %q both -> %q",
				pair[0], pair[1], a)
		}
	}
}

// TestFingerprintPrefixAgreesWithKind locks in an invariant that a live run
// caught: the fingerprint prefix and the kind are rendered side by side, so a
// deleted file classified as KindFile produced a self-contradicting row
// ("file  deleted:/tmp/x"). Any caller filtering by kind to find disk-leak
// candidates would also silently miss them.
func TestFingerprintPrefixAgreesWithKind(t *testing.T) {
	n := DefaultNormalizer()
	n.HomeDir = "/home/alice"

	cases := map[string]FDKind{
		"/tmp/x (deleted)":            KindDeleted,
		"/tmp/x":                      KindFile,
		"socket:[1]":                  KindSocket,
		"pipe:[2]":                    KindPipe,
		"anon_inode:[eventpoll]":      KindAnonInode,
		"/dev/null":                   KindDevice,
		"/var/log/app.log.2026-10-22": KindFile,
	}
	for target, want := range cases {
		fp, kind := n.Fingerprint(target)
		if kind != want {
			t.Errorf("Fingerprint(%q): kind = %q, want %q (fp %q)", target, kind, want, fp)
		}
		// Cross-check: the prefix and the kind must never disagree.
		if strings.HasPrefix(fp, "deleted:") != (kind == KindDeleted) {
			t.Errorf("Fingerprint(%q) = %q classified as %q: prefix and kind disagree", target, fp, kind)
		}
	}
}

func TestNormalizerOptionsAreHonoured(t *testing.T) {
	t.Run("KeepDir false collapses directories", func(t *testing.T) {
		n := DefaultNormalizer()
		n.KeepDir = false
		a, _ := n.Fingerprint("/data/shard1/seg.dat")
		b, _ := n.Fingerprint("/data/shard2/seg.dat")
		if a != b {
			t.Errorf("KeepDir=false should collapse shard directories, got %q and %q", a, b)
		}
		if a != "file:seg.dat" {
			t.Errorf("got %q, want file:seg.dat", a)
		}
	})

	t.Run("StripRotation false keeps rotations apart", func(t *testing.T) {
		n := DefaultNormalizer()
		n.StripRotation = false
		a, _ := n.Fingerprint("/var/log/app.log.1")
		b, _ := n.Fingerprint("/var/log/app.log.2")
		if a == b {
			t.Error("StripRotation=false must not merge rotations")
		}
	})

	t.Run("StripDeleted false keeps the suffix in the path", func(t *testing.T) {
		n := DefaultNormalizer()
		n.StripDeleted = false
		fp, _ := n.Fingerprint("/tmp/x (deleted)")
		if fp != "deleted:/tmp/x (deleted)" {
			t.Errorf("got %q, want deleted:/tmp/x (deleted)", fp)
		}
	})

	t.Run("AnonymiseHome false keeps the username", func(t *testing.T) {
		n := DefaultNormalizer()
		n.AnonymiseHome = false
		n.HomeDir = "/home/alice"
		fp, _ := n.Fingerprint("/home/alice/x")
		if fp != "file:/home/alice/x" {
			t.Errorf("got %q, want username preserved", fp)
		}
	})
}

func TestTargetKind(t *testing.T) {
	cases := map[string]FDKind{
		"":                     KindUnknown,
		"socket:[1]":           KindSocket,
		"pipe:[2]":             KindPipe,
		"anon_inode:[eventfd]": KindAnonInode,
		"/dev/null":            KindDevice,
		"/dev/shm/a":           KindFile,
		"/var/log/x":           KindFile,
		"relative/path":        KindUnknown,
		"/proc/1/fd/3":         KindFile,
	}
	for target, want := range cases {
		if got := TargetKind(target); got != want {
			t.Errorf("TargetKind(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestHeadroom(t *testing.T) {
	h := NewHeadroom(1, 4095, KnownLimit(4096))
	if got, ok := h.Remaining(); !ok || got != 1 {
		t.Errorf("Remaining = %d (ok=%t), want 1", got, ok)
	}
	if got := h.UsagePercent(); got < 99.9 || got > 100 {
		t.Errorf("UsagePercent = %f, want just under 100", got)
	}
	// A shrunk limit really does leave a running process over the limit; the
	// remaining count must go negative rather than clamping to zero.
	over := NewHeadroom(1, 5000, KnownLimit(4096))
	if got, ok := over.Remaining(); !ok || got != -904 {
		t.Errorf("Remaining = %d (ok=%t), want -904", got, ok)
	}
	// An unreadable limit must not divide by zero, must not claim 100%, and must
	// not pretend a number is available.
	unknown := NewHeadroom(1, 10, UnknownLimit())
	if got := unknown.UsagePercent(); got != 0 {
		t.Errorf("UsagePercent with unknown limit = %f, want 0", got)
	}
	if _, ok := unknown.Remaining(); ok {
		t.Error("Remaining returned a number for an unknown limit")
	}
	if got, want := unknown.String(), "10 open (limit unknown)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestHeadroomThreeStatesAreDistinguishable is the acceptance test for Day 6's
// first half: "unlimited" and "could not be read" must never print the same
// thing, because they mean opposite things about risk.
func TestHeadroomThreeStatesAreDistinguishable(t *testing.T) {
	states := []struct {
		name   string
		limit  OpenLimit
		want   string
		banned string
	}{
		{
			name:   "finite",
			limit:  KnownLimit(4096),
			want:   "100/4096 open (2.4%), 3996 remaining",
			banned: "unlimited",
		},
		{
			name:   "unlimited",
			limit:  UnlimitedLimit(),
			want:   "100 open (limit unlimited)",
			banned: "unknown",
		},
		{
			name:   "unknown",
			limit:  UnknownLimit(),
			want:   "100 open (limit unknown)",
			banned: "unlimited",
		},
		{
			// The zero value is what a forgotten assignment looks like. It must
			// read as unknown, not as "0/0 open" and not as unlimited.
			name:   "zero value",
			limit:  OpenLimit{},
			want:   "100 open (limit unknown)",
			banned: "unlimited",
		},
	}
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			got := NewHeadroom(7, 100, tc.limit).String()
			if got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, tc.banned) {
				t.Errorf("String() = %q must not contain %q", got, tc.banned)
			}
		})
	}

	// JSON keeps the old field names and adds the state; a caller that reads
	// only `limit` must still see 4096 for a finite limit and 0 otherwise.
	raw, err := json.Marshal(NewHeadroom(1, 10, KnownLimit(4096)))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"pid":1`, `"used":10`, `"limit":4096`, `"limit_state":"known"`, `"limit_known":true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON %s missing %s", raw, want)
		}
	}
	raw, err = json.Marshal(NewHeadroom(1, 10, UnlimitedLimit()))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"limit":0`, `"limit_state":"unlimited"`, `"unlimited":true`, `"limit_known":false`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("JSON %s missing %s", raw, want)
		}
	}
}

func TestSnapshotGrouping(t *testing.T) {
	snap := Snapshot{
		PID: 1,
		Descriptors: []Descriptor{
			{FD: 3, Fingerprint: "socket", Kind: KindSocket, Target: "socket:[1]"},
			{FD: 4, Fingerprint: "socket", Kind: KindSocket, Target: "socket:[2]"},
			{FD: 5, Fingerprint: "file:/a", Kind: KindFile, Target: "/a"},
			{FD: 6, Fingerprint: "file:/a", Kind: KindFile, Target: "/a"},
			{FD: 7, Fingerprint: "file:/a", Kind: KindFile, Target: "/a"},
		},
	}
	rows := snap.SortedFingerprints()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Descending by count: file:/a (3) before socket (2).
	if rows[0].Fingerprint != "file:/a" || rows[0].Count != 3 {
		t.Errorf("row 0 = %+v, want file:/a with count 3", rows[0])
	}
	if rows[1].Fingerprint != "socket" || rows[1].Count != 2 {
		t.Errorf("row 1 = %+v, want socket with count 2", rows[1])
	}

	byKind := snap.CountByKind()
	if byKind[KindSocket] != 2 || byKind[KindFile] != 3 {
		t.Errorf("CountByKind = %v", byKind)
	}
}

// TestDecomposeFingerprint covers every form Fingerprint emits, because a form
// this function cannot decompose is a form no attribution rule can ever see. The
// bare device path is the easy one to forget: devices are emitted without a
// scheme, so a decomposer that only knows the prefixed forms would silently
// return "not a fingerprint" for "/dev/null" - the one resource a reader is most
// likely to check by hand.
func TestDecomposeFingerprint(t *testing.T) {
	cases := []struct {
		fp      string
		want    FingerprintInfo
		wantOK  bool
		comment string
	}{
		{
			fp:      "file:/var/log/app.log",
			want:    FingerprintInfo{Scheme: "file", Payload: "/var/log/app.log", Kind: KindFile},
			wantOK:  true,
			comment: "a live file keeps its path",
		},
		{
			fp:      "deleted:/tmp/ghost",
			want:    FingerprintInfo{Scheme: "deleted", Payload: "/tmp/ghost", Kind: KindDeleted, Deleted: true},
			wantOK:  true,
			comment: "the deleted scheme is what makes Deleted true",
		},
		{
			fp:      "socket",
			want:    FingerprintInfo{Scheme: "socket", Kind: KindSocket},
			wantOK:  true,
			comment: "sockets carry no payload: the inode is not identity",
		},
		{
			fp:      "pipe",
			want:    FingerprintInfo{Scheme: "pipe", Kind: KindPipe},
			wantOK:  true,
			comment: "pipes likewise",
		},
		{
			fp:      "anon_inode:eventpoll",
			want:    FingerprintInfo{Scheme: "anon_inode", Payload: "eventpoll", Kind: KindAnonInode},
			wantOK:  true,
			comment: "the anon_inode name is the only thing /proc names",
		},
		{
			fp:      "/dev/null",
			want:    FingerprintInfo{Payload: "/dev/null", Kind: KindDevice},
			wantOK:  true,
			comment: "devices are emitted as their raw path, with no scheme",
		},
		{
			fp:      "file:~/notes.txt",
			want:    FingerprintInfo{Scheme: "file", Payload: "~/notes.txt", Kind: KindFile},
			wantOK:  true,
			comment: "an anonymised home is still a path",
		},
		{
			fp:      "(total)",
			wantOK:  false,
			comment: "the process total is not a resource and must not be attributed",
		},
		{
			fp:      "eventpoll",
			wantOK:  false,
			comment: "a bare word is not a fingerprint, however much it looks like one",
		},
		{
			fp:      "",
			wantOK:  false,
			comment: "the empty string must not decompose into an empty kind",
		},
	}
	for _, tc := range cases {
		got, ok := DecomposeFingerprint(tc.fp)
		if ok != tc.wantOK {
			t.Errorf("DecomposeFingerprint(%q) ok = %t, want %t (%s)", tc.fp, ok, tc.wantOK, tc.comment)
			continue
		}
		if !ok {
			continue
		}
		if got != tc.want {
			t.Errorf("DecomposeFingerprint(%q) = %+v, want %+v (%s)", tc.fp, got, tc.want, tc.comment)
		}
	}
}

// TestDecomposeFingerprintAgreesWithFingerprint states the invariant the
// attribution engine depends on: whatever Fingerprint emits must decompose back
// to the same kind and the same path. A violation would let a resource be judged
// as one kind and attributed as another, and nothing else in the code base
// compares the two.
func TestDecomposeFingerprintAgreesWithFingerprint(t *testing.T) {
	n := DefaultNormalizer()
	targets := []string{
		"/var/log/app.log",
		"/tmp/worker",
		"/dev/null",
		"/dev/pts/0",
		"/dev/shm/seg",
		"/home/u/data.bin",
		"/var/log/app.log.2026-10-22",
		"/tmp/ghost (deleted)",
		"socket:[12345]",
		"pipe:[6789]",
		"anon_inode:[eventpoll]",
		"anon_inode:inotify",
	}
	for _, target := range targets {
		fp, kind := n.Fingerprint(target)
		info, ok := DecomposeFingerprint(fp)
		if !ok {
			t.Fatalf("Fingerprint(%q) produced %q, which does not decompose", target, fp)
		}
		if info.Kind != kind {
			t.Errorf("Fingerprint(%q) = %q kind %q, but DecomposeFingerprint says %q",
				target, fp, kind, info.Kind)
		}
		// Path must be empty exactly for the kinds that have no path.
		switch kind {
		case KindSocket, KindPipe, KindAnonInode:
			if info.Path() != "" {
				t.Errorf("Fingerprint(%q) kind %q reports path %q", target, kind, info.Path())
			}
		default:
			if info.Path() == "" {
				t.Errorf("Fingerprint(%q) kind %q reports no path", target, kind)
			}
		}
	}
}
