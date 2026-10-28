// Package fdscope audits file descriptor usage of a Linux process.
//
// The problem it solves is narrow and recurring: a long-running Go service
// eventually hits "too many open files", and the available tools report a
// number without naming a culprit. lsof shows a snapshot; /proc shows a count;
// pprof shows goroutines, which are related but not the same thing. None of
// them say *which resource* is accumulating.
//
// # Fingerprints
//
// The unit of analysis is the fingerprint: a normalised identifier for a
// descriptor. Raw /proc targets are unusable for grouping because every socket
// embeds a unique inode and every log rotation looks like a new file, so a
// single leak would appear as thousands of unrelated rows. Fingerprints
// collapse those while keeping genuinely distinct resources apart.
//
//	/var/log/app.log.2026-10-22  -> file:/var/log/app.log
//	socket:[12345]               -> socket
//	/tmp/scratch (deleted)       -> deleted:/tmp/scratch   (live file stays file:/tmp/scratch)
//
// # Platform
//
// fdscope reads /proc and therefore only works on Linux. On other platforms
// every entry point returns ErrNotLinux. There is deliberately no fallback
// implementation: an empty snapshot is indistinguishable from a process that
// holds no descriptors, and any leak check built on it would silently pass.
//
// Quick start:
//
//	p := fdscope.NewProbe()
//	snap, err := p.Snapshot(os.Getpid())
//	if err != nil { return err }
//	for _, row := range snap.SortedFingerprints() {
//		fmt.Println(row.Count, row.Fingerprint)
//	}
package fdscope

import (
	"github.com/atop0914/fdscope/internal/analyze"
	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/probe"
)

// Re-exported types keep callers independent of the internal package layout.
//
// The indirection is deliberate: internal/model can be rearranged as the
// analyser grows while this file preserves a stable public surface.
type (
	// Descriptor is one entry from /proc/<pid>/fd.
	Descriptor = model.Descriptor
	// Snapshot is the descriptor set a process held at one instant.
	Snapshot = model.Snapshot
	// FingerprintCount is one aggregated row of a report.
	FingerprintCount = model.FingerprintCount
	// Headroom reports how much of the open-file limit is consumed.
	Headroom = model.Headroom
	// OpenLimit is the process descriptor limit: a finite number, unlimited, or
	// unknown. The three cases must stay apart; a 0 does not mean unlimited.
	OpenLimit = model.OpenLimit
	// LimitState says which of the three answers the kernel gave.
	LimitState = model.LimitState
	// Projection is the distance to EMFILE, with the rate and sample count it
	// was computed from.
	Projection = analyze.Projection
	// FDKind classifies what a descriptor points at.
	FDKind = model.FDKind
	// Normalizer turns raw link targets into fingerprints.
	Normalizer = model.Normalizer
	// Probe reads descriptor state from /proc.
	Probe = probe.Probe
)

// Descriptor kinds reported by fdscope.
const (
	KindFile      = model.KindFile
	KindSocket    = model.KindSocket
	KindPipe      = model.KindPipe
	KindAnonInode = model.KindAnonInode
	KindDevice    = model.KindDevice
	KindDir       = model.KindDir
	KindDeleted   = model.KindDeleted
	KindUnknown   = model.KindUnknown
)

// Limit states reported by fdscope.
const (
	// LimitKnown means a finite soft limit was read.
	LimitKnown = model.LimitKnown
	// LimitUnlimited means the kernel reported "unlimited".
	LimitUnlimited = model.LimitUnlimited
	// LimitUnknown means the limit could not be determined.
	LimitUnknown = model.LimitUnknown
)

// Sentinel errors.
var (
	// ErrNotLinux means the platform cannot be audited.
	ErrNotLinux = probe.ErrNotLinux
	// ErrNoSuchProcess means the pid has no /proc entry.
	ErrNoSuchProcess = probe.ErrNoSuchProcess
	// ErrPermission means /proc entries exist but could not be read.
	ErrPermission = probe.ErrPermission
)

// NewProbe returns a Probe using the default normalizer.
func NewProbe() *Probe { return probe.NewProbe() }

// NewNormalizer returns the default fingerprint rules: keep directories, fold
// log rotations, strip " (deleted)" but keep deleted files distinct.
func NewNormalizer() Normalizer { return model.DefaultNormalizer() }

// IsSupported reports whether this build can audit the running system.
func IsSupported() bool { return probe.IsSupported() }

// NewHeadroom builds the headroom view for used descriptors against limit.
func NewHeadroom(pid, used int, limit OpenLimit) Headroom {
	return model.NewHeadroom(pid, used, limit)
}
