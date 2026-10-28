// Package model defines the data types shared by every fdscope layer.
//
// The central idea of this package is the fingerprint: a stable, comparable
// identifier for a file descriptor. Two descriptors that refer to the same
// logical resource must produce the same fingerprint even if the kernel
// reports them differently (a rotated log file, a socket with a fresh inode,
// a deleted-but-still-open path).
package model

import (
	"fmt"
	"sort"
	"strings"
)

// FDKind classifies what a descriptor points at. The classification is coarse
// on purpose: fdscope never claims more precision than /proc actually offers.
type FDKind string

const (
	// KindFile is a regular file, including files that have been unlinked but
	// are still held open.
	KindFile FDKind = "file"
	// KindSocket is a socket. /proc reports the inode only, never the peer, so
	// fdscope cannot attribute these to a remote endpoint without extra work.
	KindSocket FDKind = "socket"
	// KindPipe is an anonymous pipe, including FIFOs opened as pipes.
	KindPipe FDKind = "pipe"
	// KindAnonInode covers epoll, eventfd, timerfd, signalfd and similar.
	// A growing epoll count usually means growing sockets, not an epoll leak,
	// so this kind is reported but never judged alone.
	KindAnonInode FDKind = "anon_inode"
	// KindDevice is a character or block device such as /dev/null or a tty.
	KindDevice FDKind = "device"
	// KindDir is a directory descriptor.
	KindDir FDKind = "dir"
	// KindDeleted is a file that has been unlinked while still held open.
	//
	// It is a distinct kind rather than a flag on KindFile because the
	// consequence is different: a leaked live file costs one descriptor, while
	// a leaked deleted file also pins disk space that `du` cannot see and only
	// `lsof | grep deleted` reveals.
	KindDeleted FDKind = "deleted"
	// KindUnknown is the fallback when the link target cannot be classified.
	KindUnknown FDKind = "unknown"
)

// Descriptor is one entry from /proc/<pid>/fd at a single point in time.
type Descriptor struct {
	// FD is the numeric descriptor value.
	FD int
	// Target is the raw link target as reported by readlink(2), unmodified.
	// It is kept so that output can always be traced back to the kernel's view.
	Target string
	// Fingerprint is the normalised, stable identifier derived from Target.
	Fingerprint string
	// Kind is the coarse classification of Target.
	Kind FDKind
	// Deleted reports whether the target ends with " (deleted)", meaning the
	// path has been unlinked while the descriptor is still open. These fds
	// hold disk space that `du` will not show.
	Deleted bool
	// Offset and Flags come from /proc/<pid>/fdinfo and may be zero when the
	// file is unreadable (permission, or the fd closed between readdir and read).
	Offset int64
	Flags  uint64
}

// String renders a descriptor for human output.
func (d Descriptor) String() string {
	return fmt.Sprintf("%d\t%s\t%s", d.FD, d.Kind, d.Target)
}

// Snapshot is the set of descriptors a process held at one instant.
//
// Taken carries the observation time as a Unix nanosecond value so that
// snapshots can be ordered without depending on a monotonic clock that does
// not survive being written to disk.
type Snapshot struct {
	// PID is the process that was observed.
	PID int
	// Taken is the observation time in Unix nanoseconds.
	Taken int64
	// Descriptors holds every readable descriptor, ordered by FD.
	Descriptors []Descriptor
	// OpenLimit is the process descriptor limit at the moment of capture: a
	// finite soft limit, "unlimited", or unknown. The three cases are distinct
	// on purpose; a zero here would have to mean all three at once.
	OpenLimit OpenLimit
	// Unreadable counts descriptor entries that existed in the directory but
	// could not be resolved. A non-zero value means the snapshot is partial
	// and must be reported as such rather than silently treated as complete.
	Unreadable int
}

// Len returns the number of captured descriptors.
func (s Snapshot) Len() int { return len(s.Descriptors) }

// Complete reports whether every directory entry could be resolved.
// Callers that make leak judgements must skip incomplete snapshots, because a
// partial snapshot looks exactly like a drop in descriptor count.
func (s Snapshot) Complete() bool { return s.Unreadable == 0 }

// CountByFingerprint groups descriptors by fingerprint, keeping the lowest fd
// number for each group so that output remains deterministic.
func (s Snapshot) CountByFingerprint() map[string][]Descriptor {
	out := make(map[string][]Descriptor, len(s.Descriptors))
	for _, d := range s.Descriptors {
		out[d.Fingerprint] = append(out[d.Fingerprint], d)
	}
	for _, group := range out {
		sort.Slice(group, func(i, j int) bool { return group[i].FD < group[j].FD })
	}
	return out
}

// CountByKind totals descriptors per kind. The map is returned rather than a
// slice so that callers can iterate deterministically after sorting keys.
func (s Snapshot) CountByKind() map[FDKind]int {
	out := make(map[FDKind]int, len(s.Descriptors))
	for _, d := range s.Descriptors {
		out[d.Kind]++
	}
	return out
}

// SortedFingerprints returns fingerprints ordered by descending count, then by
// name, so that reports are stable across runs.
func (s Snapshot) SortedFingerprints() []FingerprintCount {
	groups := s.CountByFingerprint()
	out := make([]FingerprintCount, 0, len(groups))
	for fp, ds := range groups {
		out = append(out, FingerprintCount{
			Fingerprint: fp,
			Kind:        ds[0].Kind,
			Count:       len(ds),
			Sample:      ds[0].Target,
			Deleted:     ds[0].Deleted,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// FingerprintCount is one aggregated row: how many descriptors share a
// fingerprint, plus a representative raw target for display.
type FingerprintCount struct {
	Fingerprint string `json:"fingerprint"`
	Kind        FDKind `json:"kind"`
	Count       int    `json:"count"`
	Sample      string `json:"sample"`
	Deleted     bool   `json:"deleted,omitempty"`
}

// Headroom describes how much of the open-file limit is consumed.
//
// The used value is the snapshot length rather than the kernel's global count,
// because fdscope can only vouch for descriptors it actually read.
//
// Limit keeps its old meaning - the finite soft limit, or 0 when there is no
// finite number to report - so that every existing reader of the JSON keeps
// working. The additions say why it might be 0: State distinguishes "the kernel
// said unlimited" from "the limit could not be read", and those two must never
// be collapsed again. Known and Unlimited are redundant with State on purpose;
// they are what a log query or a jq filter reaches for.
type Headroom struct {
	PID   int `json:"pid"`
	Used  int `json:"used"`
	Limit int `json:"limit"`
	// Hard is the ceiling the soft limit can be raised to, 0 when unlimited or
	// unreadable. A leak that will hit a low soft limit matters less when the
	// hard limit is huge, and that fact should not have to be guessed.
	Hard int `json:"limit_hard,omitempty"`
	// State is one of "known", "unlimited", "unknown".
	State LimitState `json:"limit_state"`
	// Unlimited is true only when the kernel reported "unlimited".
	Unlimited bool `json:"unlimited,omitempty"`
	// Known is true only when Limit is a usable finite number.
	Known bool `json:"limit_known"`
}

// NewHeadroom builds the headroom view for used descriptors against limit.
func NewHeadroom(pid, used int, limit OpenLimit) Headroom {
	l := limit.Normalized()
	return Headroom{
		PID:       pid,
		Used:      used,
		Limit:     l.Soft,
		Hard:      l.Hard,
		State:     l.StateOrUnknown(),
		Unlimited: l.Unlimited(),
		Known:     l.Known(),
	}
}

// LimitValue reconstructs the limit this headroom was built from.
func (h Headroom) LimitValue() OpenLimit {
	return OpenLimit{State: h.State, Soft: h.Limit, Hard: h.Hard}.Normalized()
}

// Remaining is the number of descriptors left before allocation starts
// failing. It is negative when the process is already over a lowered limit,
// which really happens after `ulimit -n` is shrunk on a running process. The
// second result is false when no finite limit is known - the case where a
// subtraction would produce a number that means nothing.
func (h Headroom) Remaining() (int, bool) {
	return h.LimitValue().Remaining(h.Used)
}

// UsagePercent is the consumed share of the limit, or 0 when the limit is not a
// finite number. It is intentionally a float so that 4095/4096 does not report
// 100%.
func (h Headroom) UsagePercent() float64 {
	if !h.Known || h.Limit <= 0 {
		return 0
	}
	return float64(h.Used) / float64(h.Limit) * 100
}

// String renders headroom for human output.
//
// "unlimited" and "unknown" are printed as words rather than as a number: a
// reader who sees "0/0 open" concludes the process is at its limit.
func (h Headroom) String() string {
	switch h.LimitValue().StateOrUnknown() {
	case LimitKnown:
		left, _ := h.Remaining()
		return fmt.Sprintf("%d/%d open (%.1f%%), %d remaining", h.Used, h.Limit, h.UsagePercent(), left)
	case LimitUnlimited:
		return fmt.Sprintf("%d open (limit unlimited)", h.Used)
	}
	return fmt.Sprintf("%d open (limit unknown)", h.Used)
}

// TargetKind classifies a raw readlink target. The rules are ordered from most
// specific to least, and every branch is covered by a test.
func TargetKind(target string) FDKind {
	switch {
	case target == "":
		return KindUnknown
	case strings.HasPrefix(target, "socket:"):
		return KindSocket
	case strings.HasPrefix(target, "pipe:"):
		return KindPipe
	case strings.HasPrefix(target, "anon_inode:"):
		return KindAnonInode
	case target == "socket" || target == "pipe":
		// Already-normalised forms carry no payload.
		if target == "socket" {
			return KindSocket
		}
		return KindPipe
	case strings.HasPrefix(target, "/dev/"):
		// /dev/null and ttys are devices; /dev/shm entries are regular files.
		if strings.HasPrefix(target, "/dev/shm/") {
			return KindFile
		}
		return KindDevice
	}

	// Anything else that starts with a slash is a filesystem path. fdscope
	// cannot stat it reliably: a deleted file's path no longer exists, and a
	// path in another mount namespace may not resolve at all. Classification
	// therefore stops at "some kind of file object".
	if strings.HasPrefix(target, "/") {
		return KindFile
	}
	return KindUnknown
}
