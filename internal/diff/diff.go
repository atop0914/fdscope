// Package diff compares two snapshots of the same process and reports what
// changed between them, expressed in fingerprints rather than descriptor
// numbers.
//
// The distinction is load-bearing. Descriptor numbers are reused by the kernel
// as soon as they are closed: a process that closes /etc/passwd and immediately
// opens a fresh socket will very likely get the same number back. Comparing by
// number therefore reports "no change" for exactly the case fdscope exists to
// find - one resource leaving and another arriving under an identical label.
//
// Everything in this package is a pure function of two snapshots. All OS access
// stays in internal/probe, so the comparison itself is tested with plain
// structs built by hand.
package diff

import (
	"errors"
	"fmt"
	"sort"

	"github.com/atop0914/fdscope/internal/model"
)

// ErrSamePIDRequired is returned when the two snapshots describe different
// processes. Diffing across processes has no meaning: every number in the
// result would be noise.
var ErrSamePIDRequired = errors.New("snapshots must belong to the same process")

// ErrProcessRestarted is returned when the observed process is not the same
// process as before, even though the pid matches.
//
// A pid is only unique among live processes; once a process exits its pid is
// handed to the next one. Diffing across a restart compares two unrelated
// processes and produces a change list that looks plausible and is entirely
// fictional. The only trustworthy identity a live process exposes cheaply is
// the start time from /proc/<pid>/stat, so a mismatch there means restart.
var ErrProcessRestarted = errors.New("process restarted between snapshots")

// ErrIncompleteSnapshot is returned when a snapshot is partial.
//
// A descriptor that could not be read is indistinguishable from a descriptor
// that was closed, so a partial snapshot turns into phantom "gone" entries and
// can hide real "new" entries. Refusing to diff is the only honest answer.
var ErrIncompleteSnapshot = errors.New("snapshot is incomplete, refusing to diff")

// Change is one fingerprint-level difference between two snapshots.
type Change struct {
	// Fingerprint is the normalised resource identifier.
	Fingerprint string `json:"fingerprint"`
	// Kind is the descriptor kind of the fingerprint.
	Kind model.FDKind `json:"kind"`
	// Before and After are the descriptor counts at each sampling point.
	Before int `json:"before"`
	After  int `json:"after"`
	// Delta is After - Before. It is negative for fingerprints that shrank or
	// disappeared.
	Delta int `json:"delta"`
	// Sample is the raw link target of the lowest-numbered descriptor in the
	// "after" snapshot, or in the "before" snapshot when the fingerprint is
	// gone. It keeps a report traceable back to what the kernel actually said.
	Sample string `json:"sample"`
	// Deleted reports whether this fingerprint is a deleted-but-held file.
	Deleted bool `json:"deleted,omitempty"`
}

// Changed reports whether the count actually changed. A fingerprint present in
// both snapshots with the same count is not a change and is never emitted.
func (c Change) Changed() bool { return c.Delta != 0 }

// Diff is the comparison of two snapshots of one process.
//
// The three views overlap on purpose: Changes answers "what moved" (either
// direction), Added/Removed answer "what appeared / disappeared", and
// DeletedFiles answers the narrower question that has the largest operational
// payoff - which unlinked files are still pinned open.
type Diff struct {
	// PID is the observed process.
	PID int `json:"pid"`
	// BeforeTaken and AfterTaken are the sampling times in Unix nanoseconds.
	BeforeTaken int64 `json:"-"`
	AfterTaken  int64 `json:"-"`
	// BeforeTotal and AfterTotal are the descriptor counts at each point.
	BeforeTotal int `json:"before_total"`
	AfterTotal  int `json:"after_total"`
	// BeforeLimit and AfterLimit are the soft open-file limits, 0 = unknown.
	BeforeLimit int `json:"before_limit"`
	AfterLimit  int `json:"after_limit"`
	// Changes lists every fingerprint whose count moved, largest absolute
	// delta first (growth before shrinkage at equal magnitude).
	Changes []Change `json:"changes"`
	// DeletedFiles lists deleted fingerprints that are still held open.
	DeletedFiles []Change `json:"deleted_files"`
}

// Added returns the fingerprints that appeared, largest first.
func (d Diff) Added() []Change { return filterSign(d.Changes, 1) }

// Removed returns the fingerprints that disappeared, largest first.
func (d Diff) Removed() []Change { return filterSign(d.Changes, -1) }

// Grew returns the fingerprints whose count increased, whether or not they
// existed before. This is the view to read when asking "what is accumulating".
func (d Diff) Grew() []Change { return filterSign(d.Changes, 1, true) }

// Unchanged reports whether no fingerprint changed count at all.
//
// It is deliberately computed from the change list rather than from the totals:
// a close and an open that cancel out leave the total untouched while both
// resources changed.
func (d Diff) Unchanged() bool { return len(d.Changes) == 0 }

// NetDescriptorChange is the total descriptor delta. It can be 0 while
// Unchanged() is false, and that combination is exactly the fd-number-reuse
// case fdscope has to survive.
func (d Diff) NetDescriptorChange() int { return d.AfterTotal - d.BeforeTotal }

// filterSign selects changes by the sign of Delta.
//
// includeGrowth widens it to "any increase", including fingerprints that did
// not exist before, which is what a caller asking for accumulating resources
// wants; without it only pure additions are returned.
func filterSign(changes []Change, sign int, includeGrowth ...bool) []Change {
	anyIncrease := len(includeGrowth) > 0 && includeGrowth[0]
	out := make([]Change, 0, len(changes))
	for _, c := range changes {
		if anyIncrease {
			if sign > 0 && c.After > c.Before || sign < 0 && c.After < c.Before {
				out = append(out, c)
			}
			continue
		}
		if sign > 0 && c.Before == 0 && c.After > 0 {
			out = append(out, c)
		}
		if sign < 0 && c.After == 0 && c.Before > 0 {
			out = append(out, c)
		}
	}
	return out
}

// Compare diffs two snapshots of the same process.
//
// The snapshots must be ordered: before must have been taken no later than
// after. Both must be complete, and startTime - the /proc/<pid>/stat field 22
// value captured alongside each snapshot - must be equal and non-zero, which is
// what distinguishes "the same process is still running" from "a different
// process inherited the pid".
func Compare(before, after model.Snapshot, beforeStart, afterStart uint64) (Diff, error) {
	if before.PID != after.PID {
		return Diff{}, fmt.Errorf("%w: %d vs %d", ErrSamePIDRequired, before.PID, after.PID)
	}
	if beforeStart == 0 || afterStart == 0 {
		// Without a start time there is no way to tell a running process from a
		// recycled pid, and a fabricated diff is worse than no diff.
		return Diff{}, fmt.Errorf("%w: start time unavailable", ErrProcessRestarted)
	}
	if beforeStart != afterStart {
		return Diff{}, fmt.Errorf("%w: pid %d start time %d -> %d",
			ErrProcessRestarted, before.PID, beforeStart, afterStart)
	}
	if !before.Complete() || !after.Complete() {
		return Diff{}, fmt.Errorf("%w: unreadable before=%d after=%d",
			ErrIncompleteSnapshot, before.Unreadable, after.Unreadable)
	}
	if after.Taken < before.Taken {
		return Diff{}, fmt.Errorf("snapshots are out of order: %d < %d", after.Taken, before.Taken)
	}

	beforeGroups := before.CountByFingerprint()
	afterGroups := after.CountByFingerprint()

	d := Diff{
		PID:         before.PID,
		BeforeTaken: before.Taken,
		AfterTaken:  after.Taken,
		BeforeTotal: before.Len(),
		AfterTotal:  after.Len(),
		BeforeLimit: before.OpenLimit,
		AfterLimit:  after.OpenLimit,
	}

	seen := make(map[string]struct{}, len(beforeGroups)+len(afterGroups))
	for fp, group := range afterGroups {
		seen[fp] = struct{}{}
		beforeCount := len(beforeGroups[fp])
		if beforeCount == len(group) {
			continue
		}
		d.Changes = append(d.Changes, Change{
			Fingerprint: fp,
			Kind:        group[0].Kind,
			Before:      beforeCount,
			After:       len(group),
			Delta:       len(group) - beforeCount,
			Sample:      group[0].Target,
			Deleted:     group[0].Deleted,
		})
	}
	for fp, group := range beforeGroups {
		if _, ok := seen[fp]; ok {
			continue
		}
		// Gone entirely. There is no "after" descriptor to describe it, so the
		// sample and kind come from the before snapshot.
		d.Changes = append(d.Changes, Change{
			Fingerprint: fp,
			Kind:        group[0].Kind,
			Before:      len(group),
			After:       0,
			Delta:       -len(group),
			Sample:      group[0].Target,
			Deleted:     group[0].Deleted,
		})
	}

	sortChanges(d.Changes)

	for _, c := range d.Changes {
		if c.Deleted && c.After > 0 {
			d.DeletedFiles = append(d.DeletedFiles, c)
		}
	}

	return d, nil
}

// sortChanges orders by absolute delta descending, then growth before
// shrinkage, then fingerprint. A caller reading the top of the list must see the
// largest movement first regardless of direction; the growth-first tie-break
// means "what is accumulating" never loses to a same-sized release.
func sortChanges(changes []Change) {
	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		absA, absB := a.Delta, b.Delta
		if absA < 0 {
			absA = -absA
		}
		if absB < 0 {
			absB = -absB
		}
		if absA != absB {
			return absA > absB
		}
		if a.Delta != b.Delta {
			return a.Delta > b.Delta
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// DeletedFile is one unlinked file that a process still holds open.
type DeletedFile struct {
	// Fingerprint is the normalised identifier, prefixed "deleted:".
	Fingerprint string `json:"fingerprint"`
	// Path is the path the file had before it was unlinked. It no longer
	// exists on any filesystem.
	Path string `json:"path"`
	// OpenCount is how many descriptors hold this file open at the time of the
	// snapshot.
	OpenCount int `json:"open_count"`
	// WritableOpenCount is how many of those descriptors were opened for
	// writing. A deleted file held only for reading pins an inode but not its
	// blocks; one held for writing is still linked to disk space that `du`
	// cannot see.
	WritableOpenCount int `json:"writable_open_count"`
	// Sample is the raw target of the lowest-numbered descriptor, including the
	// kernel's " (deleted)" suffix.
	Sample string `json:"sample"`
}

// HoldsDiskSpace reports whether this file is holding disk space hostage.
//
// It is true only when at least one descriptor was opened for writing:
// O_WRONLY and O_RDWR both imply the file may still be extended or truncated,
// so the kernel keeps its blocks allocated. A read-only held deleted file
// costs an inode and a descriptor but not its data blocks.
func (f DeletedFile) HoldsDiskSpace() bool { return f.WritableOpenCount > 0 }

// DeletedFiles returns the unlinked-but-open files in a snapshot.
//
// The output answers a question `du` structurally cannot: these files have no
// directory entry, so nothing walks them, and only a descriptor level view sees
// them at all.
//
// What it deliberately does NOT provide is a byte count. Sizing the file would
// require stat(2) on the path, which no longer exists; the only route left is
// /proc/<pid>/map_files or fstat on the target process's own descriptor, both of
// which fdscope refuses. Reporting a guessed size here would be worse than
// reporting none, because the whole point of the view is "this is how much disk
// you are losing".
func DeletedFiles(s model.Snapshot) []DeletedFile {
	type acc struct {
		file     DeletedFile
		writable int
	}
	byFP := make(map[string]*acc)
	order := make([]string, 0, 8)

	for _, d := range s.Descriptors {
		if !d.Deleted {
			// "Deleted" comes from the kernel's own suffix, never from the
			// fingerprint prefix. The two are kept in agreement by an
			// invariant test; here the kernel's statement is authoritative.
			continue
		}
		a, ok := byFP[d.Fingerprint]
		if !ok {
			a = &acc{file: DeletedFile{
				Fingerprint: d.Fingerprint,
				Path:        trimDeletedSuffix(d.Target),
				Sample:      d.Target,
			}}
			byFP[d.Fingerprint] = a
			order = append(order, d.Fingerprint)
		}
		a.file.OpenCount++
		// flags are the kernel's open(2) flags. Bit 0 (O_WRONLY) and bit 1
		// (O_RDWR) both mean the descriptor may write. A zero flags value comes
		// from an unreadable fdinfo file and is genuinely ambiguous, so it is
		// not counted as writable.
		const oWrOnly, oRdWr = 0x1, 0x2
		if d.Flags&(oWrOnly|oRdWr) != 0 {
			a.writable++
		}
	}

	out := make([]DeletedFile, 0, len(order))
	for _, fp := range order {
		f := byFP[fp].file
		f.WritableOpenCount = byFP[fp].writable
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OpenCount != out[j].OpenCount {
			return out[i].OpenCount > out[j].OpenCount
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// trimDeletedSuffix strips the kernel's " (deleted)" marker from a raw target.
func trimDeletedSuffix(target string) string {
	const suffix = " (deleted)"
	if len(target) >= len(suffix) && target[len(target)-len(suffix):] == suffix {
		return target[:len(target)-len(suffix)]
	}
	return target
}
