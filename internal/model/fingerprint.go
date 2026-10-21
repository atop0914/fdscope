package model

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Normalizer turns raw readlink targets into stable fingerprints.
//
// The zero value is usable and applies every default rule. Rules are
// configurable because the right answer depends on the process being audited:
// a service rotating logs hourly and one holding a single file care about
// different things, and hard-coding either one would be wrong for the other.
type Normalizer struct {
	// KeepDir keeps the directory part of a file fingerprint. When false only
	// the base name is kept, which is useful for processes that fan out over
	// many shard directories.
	KeepDir bool
	// ExpandTildeStyle lets /proc-style " (deleted)" suffixes be stripped.
	// It exists as a field only so tests can prove the behaviour is optional;
	// production callers should leave it true.
	StripDeleted bool
	// StripRotation removes a trailing rotation marker (.1, .2, .2026-10-22,
	// -20261022) so that all rotations of one log map to one fingerprint.
	StripRotation bool
	// AnonymiseHome replaces the user's home directory with "~" so that
	// fingerprints do not leak usernames into shared reports.
	AnonymiseHome bool
	// HomeDir is the directory replaced when AnonymiseHome is set.
	HomeDir string
}

// DefaultNormalizer returns the rules fdscope uses when none are configured.
//
// The defaults are deliberately conservative: they merge things that are
// virtually always the same resource (log rotations, temp-file suffixes) and
// they keep the directory, because collapsing directories would merge two
// genuinely different leaks into one row.
func DefaultNormalizer() Normalizer {
	return Normalizer{
		KeepDir:       true,
		StripDeleted:  true,
		StripRotation: true,
		AnonymiseHome: true,
		HomeDir:       "",
	}
}

const deletedSuffix = " (deleted)"

// rotationSuffix matches common log-rotation tails:
//
//	app.log.1        app.log.2026-10-22      app.log-20261022
//	app.log.2026-10-22T03:04:05
//
// It must not match a legitimate extension such as ".log" or ".txt", nor a
// version-like name such as "v1.2". Only numeric/dotted-date tails qualify.
var rotationSuffix = regexp.MustCompile(
	`(?:\.|-)(?:\d{1,5}|\d{8}|\d{4}-\d{2}-\d{2}(?:[T_-]\d{2}[:.-]?\d{2}[:.-]?\d{2})?)$`,
)

// Fingerprint normalises one raw target into its stable identifier.
//
// The returned value is what reports group by, so it must be deterministic and
// must never include an inode. That is the whole point: inodes change every
// time a socket is recreated, and grouping by them would make one leak look
// like thousands of unrelated rows.
func (n Normalizer) Fingerprint(target string) (fp string, kind FDKind) {
	// Accept an already-normalised fingerprint and return it unchanged.
	//
	// This is what makes the normaliser idempotent. Without it, feeding a
	// fingerprint back in (which several report paths do when re-grouping)
	// would prepend "file:" a second time and produce "file:file:/a" - a
	// fingerprint that never matches anything else. The failure is silent:
	// rows simply stop merging.
	if f, prefix, ok := splitFingerprint(target); ok {
		kind = fingerprintKind(prefix, f)
		return target, kind
	}

	raw := target
	kind = TargetKind(raw)

	// Sockets, pipes and anon inodes carry a bare inode after the colon.
	// Drop the inode: the kind is all we can honestly claim from /proc.
	switch kind {
	case KindSocket:
		return "socket", kind
	case KindPipe:
		return "pipe", kind
	case KindAnonInode:
		// anon_inode targets look like "anon_inode:[eventpoll]" or
		// "anon_inode:inotify". The bracket payload is meaningful and stable,
		// so keep it, but strip any numeric instance suffix.
		name := strings.TrimPrefix(raw, "anon_inode:")
		name = strings.Trim(name, "[]")
		if idx := strings.IndexByte(name, ':'); idx >= 0 {
			name = name[:idx]
		}
		if name == "" {
			name = "unnamed"
		}
		return "anon_inode:" + name, kind
	case KindDevice:
		return raw, kind
	}

	path := raw
	dead := false
	if strings.HasSuffix(path, deletedSuffix) {
		dead = true
		if n.StripDeleted {
			path = strings.TrimSuffix(path, deletedSuffix)
		}
	}

	if n.AnonymiseHome && n.HomeDir != "" {
		if path == n.HomeDir {
			path = "~"
		} else if strings.HasPrefix(path, n.HomeDir+string(filepath.Separator)) {
			path = "~" + strings.TrimPrefix(path, n.HomeDir)
		}
	}

	if n.StripRotation {
		path = stripRotation(path)
	}

	if !n.KeepDir && strings.HasPrefix(path, "/") {
		path = filepath.Base(path)
	}

	prefix := "file:"
	if dead {
		// Deleted descriptors keep a distinct fingerprint even when the path
		// is stripped, because "this file is gone but still held" is an action
		// item (disk is not reclaimed) and must not be merged with a live file.
		prefix = "deleted:"
	}
	// A deleted file is its own kind, not just its own fingerprint prefix.
	//
	// The two must agree: reports show the fingerprint's prefix and the kind
	// side by side, so classifying a deleted file as a plain file produces a
	// row that reads "file  deleted:/tmp/x" and contradicts itself. It also
	// matters for any caller that filters by kind to find disk-leak candidates.
	if dead {
		return prefix + path, KindDeleted
	}
	return prefix + path, kind
}

// stripRotation removes one trailing rotation marker from a path, leaving the
// path untouched when the marker would consume the whole base name.
func stripRotation(path string) string {
	loc := rotationSuffix.FindStringIndex(path)
	if loc == nil || loc[1] != len(path) {
		return path
	}
	trimmed := path[:loc[0]]
	// Never strip down to a bare directory or empty name: "app.log" must stay
	// "app.log", and a file literally named "12345" must stay "12345".
	base := filepath.Base(trimmed)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return path
	}
	if _, err := strconv.Atoi(base); err == nil {
		return path
	}
	return trimmed
}

// fingerprintPrefixes lists the scheme prefixes Fingerprint emits.
//
// A prefix must be recognised here to be treated as "already normalised"; the
// reverse direction (emitting a prefix that is not listed) would break
// idempotence in a way only repeated normalisation tests can catch.
var fingerprintPrefixes = []string{"file:", "deleted:", "socket", "pipe", "anon_inode:"}

// splitFingerprint reports whether s is already a fingerprint and returns the
// bare payload for kind lookup.
//
// The check is intentionally strict. A raw target like "/var/log/file:x" (yes,
// a file can be named that) must not be mistaken for a fingerprint, so the
// payload after "file:" must itself look like a path.
func splitFingerprint(s string) (payload string, prefix string, ok bool) {
	for _, p := range fingerprintPrefixes {
		if !strings.HasPrefix(s, p) {
			continue
		}
		switch p {
		case "socket", "pipe":
			// Exact match only: these carry no payload by design.
			if s == p {
				return "", p, true
			}
			return "", "", false
		case "anon_inode:":
			// The raw kernel form is "anon_inode:[eventpoll]" or
			// "anon_inode:inotify". Neither is a normalised fingerprint, so
			// they must fall through to normal classification. Only a payload
			// without brackets and without a colon is already normalised
			// (i.e. "anon_inode:eventpoll" or "anon_inode:unnamed").
			payload = strings.TrimPrefix(s, p)
			if payload == "" {
				return "", "", false
			}
			if strings.HasPrefix(payload, "[") || strings.Contains(payload, ":") {
				return "", "", false
			}
			return payload, p, true
		default:
			payload = strings.TrimPrefix(s, p)
			if payload == "" {
				return "", "", false
			}
			// "~/..." is a valid anonymised payload; everything else must be
			// rooted, so that a bare word never counts as a fingerprint.
			if !strings.HasPrefix(payload, "/") && !strings.HasPrefix(payload, "~") {
				return "", "", false
			}
			return payload, p, true
		}
	}
	return "", "", false
}

// fingerprintKind maps a fingerprint scheme prefix back to its descriptor kind.
//
// It exists because the prefix is the authoritative statement of what the
// fingerprint means. Re-deriving the kind from the payload would get
// "anon_inode:inotify" wrong (its payload holds no colon, so TargetKind sees an
// unrecognised bare word).
func fingerprintKind(prefix, payload string) FDKind {
	switch prefix {
	case "socket":
		return KindSocket
	case "pipe":
		return KindPipe
	case "deleted:":
		return KindDeleted
	case "file:":
		// The payload of a file fingerprint may be an anonymised "~/..." form,
		// which is still a file once expanded.
		if k := TargetKind(payload); k == KindFile || k == KindDevice {
			return k
		}
		return KindFile
	case "anon_inode:":
		return KindAnonInode
	}
	return KindUnknown
}
