package attr

import (
	"path/filepath"
	"strings"

	"github.com/atop0914/fdscope/internal/model"
)

// Built-in priorities, ordered from the specific fact to the general one.
//
// The ladder is a single decision made once, written down here so it can be
// argued with:
//
//	consequence  a descriptor that pins disk space is the most actionable thing
//	             an operator can be told, so "unlinked but still held" outranks
//	             every statement about what the path was for.
//	identity     socket, pipe and the named anonymous inodes are exact: the
//	             kernel names them, so they beat anything inferred from a path.
//	role         a log file is a log file wherever it lives; the suffix is a
//	             stronger statement than the directory.
//	location     a temporary file is classified by where it lives and by no
//	             other property.
//
// Numbers, not an enum, because a configured rule has to be able to sit anywhere
// in the ladder and because the gaps leave room for the next level without
// renumbering everything.
const (
	priorityDeleted    = 300
	priorityAnonNamed  = 280
	priorityAnonOther  = 240
	prioritySocket     = 200
	priorityPipe       = 190
	priorityTerminal   = 180
	priorityNullDevice = 175
	priorityDevice     = 165
	priorityLog        = 150
	prioritySharedMem  = 145
	priorityTemp       = 140
	// UserRulePriority is the floor for a configured rule. It is above every
	// built-in one so that adding a rule always beats guessing, and it leaves
	// the space above it for a user who wants to order their own rules.
	UserRulePriority = 1000
)

// anonRule describes one anonymous-inode name.
//
// The kernel spells these as "anon_inode:[eventpoll]" or "anon_inode:inotify";
// the normaliser keeps the payload, so the name is all a rule has to work with -
// and it is enough, because the names are a closed set defined by the kernel.
type anonRule struct {
	name     string
	category string
	why      string
}

// anonRules is the closed set worth naming.
//
// "other" is deliberately not here: an unknown anonymous inode gets the generic
// rule below, because naming a resource "timerfd" when the kernel said something
// else would be an invented fact.
var anonRules = []anonRule{
	{
		name:     "eventpoll",
		category: "epoll instance",
		why:      "an epoll set from epoll_create: one per event loop, and it grows with the sockets it watches rather than on its own",
	},
	{
		name:     "inotify",
		category: "inotify watch",
		why:      "a watch set from inotify_init: one descriptor per set, however many paths it watches",
	},
	{
		name:     "timerfd",
		category: "timer",
		why:      "a timer from timerfd_create: a count that only rises means the timers are created and never closed",
	},
	{
		name:     "eventfd",
		category: "event counter",
		why:      "an eventfd used for wakeups between threads or processes",
	},
	{
		name:     "signalfd",
		category: "signal queue",
		why:      "a signalfd that turns signals into readable events",
	},
	{
		name:     "io_uring",
		category: "io_uring ring",
		why:      "an io_uring submission or completion ring",
	},
}

// builtinRules is the set that Default and New both build on. It is computed once
// at package initialisation: the predicates are pure, so sharing them is safe, and
// a caller that attributes on every report should not rebuild nineteen closures
// each time.
var builtinRules = DefaultRules()

// DefaultRules returns the built-in rule set.
//
// Every rule states what the fingerprint showed and stops there. The wording is
// checked by a test, because a rule that drifted into "probably the logger" would
// pass every behavioural assertion in this package while breaking the one promise
// the project makes about attribution.
func DefaultRules() []Rule {
	rules := []Rule{
		{
			Name:     "deleted-file",
			Category: "unlinked file still held",
			Why:      "the path was unlinked while the descriptor stayed open: the space is not reclaimed and du cannot see it",
			Priority: priorityDeleted,
			Match:    func(v View) bool { return v.Deleted },
		},
		{
			Name:     "socket",
			Category: "socket",
			Why:      "/proc records the socket inode and nothing else, so L1 can say it is a socket and not what it connects to",
			Priority: prioritySocket,
			Match:    func(v View) bool { return v.Kind == model.KindSocket },
		},
		{
			Name:     "pipe",
			Category: "pipe",
			Why:      "an anonymous pipe: a count that only rises usually means a reader stopped draining it",
			Priority: priorityPipe,
			Match:    func(v View) bool { return v.Kind == model.KindPipe },
		},
		{
			Name:     "terminal",
			Category: "terminal",
			Why:      "a tty under /dev/pts or /dev/tty: normally one per process, so a growing count is worth a look",
			Priority: priorityTerminal,
			Match: func(v View) bool {
				return v.Kind == model.KindDevice &&
					(underDir(v.Path, "/dev/pts") || strings.HasPrefix(v.Path, "/dev/tty"))
			},
		},
		{
			Name:     "null-device",
			Category: "discard device",
			Why:      "/dev/null: opening it costs a descriptor but holds no resource, so a growing count is descriptor bookkeeping alone",
			Priority: priorityNullDevice,
			// The exact path, not a /dev prefix: /dev/sda is a block device and
			// /dev/urandom a random source, and filing either under "discard"
			// would be a made-up fact about what the process does with it.
			Match: func(v View) bool { return v.Kind == model.KindDevice && v.Path == "/dev/null" },
		},
		{
			Name:     "device",
			Category: "device node",
			Why:      "a character or block device other than /dev/null or a tty",
			Priority: priorityDevice,
			Match:    func(v View) bool { return v.Kind == model.KindDevice },
		},
		{
			Name:     "log-file",
			Category: "log file",
			Why:      "the path is a .log file or lives in a log directory: a count that only rises means a rotation or a reaper is missing",
			Priority: priorityLog,
			Match: func(v View) bool {
				return v.Kind != model.KindDeleted && looksLikeLog(v.Path)
			},
		},
		{
			Name:     "shared-memory",
			Category: "shared memory file",
			Why:      "a file in /dev/shm: a tmpfs object that occupies memory until the last holder closes it",
			Priority: prioritySharedMem,
			Match: func(v View) bool {
				return v.Kind != model.KindDeleted && underDir(v.Path, "/dev/shm")
			},
		},
		{
			Name:     "temp-file",
			Category: "temporary file",
			Why:      "the path is under /tmp or /var/tmp: a scratch file that was opened and not closed",
			Priority: priorityTemp,
			Match: func(v View) bool {
				return v.Kind != model.KindDeleted &&
					(underDir(v.Path, "/tmp") || underDir(v.Path, "/var/tmp"))
			},
		},
		{
			Name:     "anon-inode",
			Category: "anonymous inode (other)",
			Why:      "an anonymous inode the built-in rules do not name; the fingerprint carries the kernel's own name for it",
			Priority: priorityAnonOther,
			Match:    func(v View) bool { return v.Kind == model.KindAnonInode },
		},
	}
	for _, a := range anonRules {
		rules = append(rules, Rule{
			Name:     "anon-inode/" + a.name,
			Category: a.category,
			Why:      a.why,
			Priority: priorityAnonNamed,
			Match:    func(v View) bool { return v.Kind == model.KindAnonInode && v.Name == a.name },
		})
	}
	return rules
}

// looksLikeLog reports whether a normalised path names a log by its own shape.
//
// The test is a ".log" suffix or a directory segment spelled log/logs. A plain
// substring search - the obvious reading of "the path contains log" - was
// rejected: it classifies /var/lib/catalog/index as a log, and a rule that fires
// on catalogues is worse than no rule, because the reader learns to distrust the
// column instead of the pattern.
func looksLikeLog(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".log") {
		return true
	}
	dir := filepath.Dir(lower)
	for _, seg := range strings.Split(dir, "/") {
		if seg == "log" || seg == "logs" {
			return true
		}
	}
	return false
}

// underDir reports whether path is dir or inside it.
//
// It compares whole segments rather than a string prefix: "/tmpfoo" starts with
// "/tmp" and is not a temporary file, and the version that used HasPrefix put
// every user's "tmp" directory in the temporary-file category.
func underDir(path, dir string) bool {
	if path == "" {
		return false
	}
	if path == dir {
		return true
	}
	return strings.HasPrefix(path, dir+"/")
}
