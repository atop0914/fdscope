package model

import "testing"

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
		{"deleted file", "/tmp/scratch (deleted)", "deleted:/tmp/scratch", KindFile},

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
		"":                      KindUnknown,
		"socket:[1]":            KindSocket,
		"pipe:[2]":              KindPipe,
		"anon_inode:[eventfd]":  KindAnonInode,
		"/dev/null":             KindDevice,
		"/dev/shm/a":            KindFile,
		"/var/log/x":            KindFile,
		"relative/path":         KindUnknown,
		"/proc/1/fd/3":          KindFile,
	}
	for target, want := range cases {
		if got := TargetKind(target); got != want {
			t.Errorf("TargetKind(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestHeadroom(t *testing.T) {
	h := Headroom{PID: 1, Used: 4095, Limit: 4096}
	if got := h.Remaining(); got != 1 {
		t.Errorf("Remaining = %d, want 1", got)
	}
	if got := h.UsagePercent(); got < 99.9 || got > 100 {
		t.Errorf("UsagePercent = %f, want just under 100", got)
	}
	// A shrunk limit really does leave a running process over the limit; the
	// remaining count must go negative rather than clamping to zero.
	over := Headroom{PID: 1, Used: 5000, Limit: 4096}
	if got := over.Remaining(); got != -904 {
		t.Errorf("Remaining = %d, want -904", got)
	}
	// Unknown limit must not divide by zero or claim 100%.
	unknown := Headroom{Used: 10, Limit: 0}
	if got := unknown.UsagePercent(); got != 0 {
		t.Errorf("UsagePercent with unknown limit = %f, want 0", got)
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
