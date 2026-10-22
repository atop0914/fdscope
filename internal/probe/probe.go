// Package probe reads file descriptor state from /proc. It is the only layer
// in fdscope that touches the operating system, so everything above it can be
// tested with plain structs.
package probe

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atop0914/fdscope/internal/model"
)

// ErrNotLinux is returned by every entry point on platforms that do not expose
// a Linux-compatible /proc. fdscope refuses to pretend it works there rather
// than returning an empty snapshot, because an empty snapshot is
// indistinguishable from "the process holds no descriptors" and would silently
// turn every leak check into a pass.
var ErrNotLinux = errors.New("fdscope only supports Linux: /proc/<pid>/fd is required")

// ErrNoSuchProcess is returned when the target pid has no /proc entry.
var ErrNoSuchProcess = errors.New("process not found")

// ErrPermission is returned when /proc entries exist but cannot be read, which
// happens for processes owned by another user without CAP_SYS_PTRACE.
var ErrPermission = errors.New("permission denied reading process descriptors")

// ProcRoot is the mount point probed for process state. Tests override it.
var ProcRoot = "/proc"

// Probe captures descriptor state for a process.
type Probe struct {
	// Normalizer produces fingerprints from raw link targets.
	Normalizer model.Normalizer
	// ProcRoot overrides the /proc mount point; empty means the package default.
	ProcRoot string
}

// NewProbe returns a Probe with the default normalizer.
func NewProbe() *Probe {
	return &Probe{Normalizer: model.DefaultNormalizer()}
}

func (p *Probe) procRoot() string {
	if p.ProcRoot != "" {
		return p.ProcRoot
	}
	return ProcRoot
}

// fdDir returns the directory holding the descriptors of pid.
func (p *Probe) fdDir(pid int) string {
	return filepath.Join(p.procRoot(), strconv.Itoa(pid), "fd")
}

// Snapshot captures the current descriptor set of pid.
//
// The capture is not atomic: descriptors opened or closed while it runs may be
// missed or double-counted. That is inherent to reading /proc without stopping
// the target, and a target that is busy will always have some churn. Leak
// detection works on trends across many snapshots, so per-snapshot churn is
// tolerated, but Unreadable is reported so a caller can tell a busy process
// from a genuinely partial read.
func (p *Probe) Snapshot(pid int) (model.Snapshot, error) {
	if !IsSupported() {
		return model.Snapshot{}, ErrNotLinux
	}
	if pid <= 0 {
		return model.Snapshot{}, fmt.Errorf("invalid pid %d", pid)
	}

	dir := p.fdDir(pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return model.Snapshot{}, fmt.Errorf("%w: %d", ErrNoSuchProcess, pid)
		case os.IsPermission(err):
			return model.Snapshot{}, fmt.Errorf("%w: %d", ErrPermission, pid)
		default:
			return model.Snapshot{}, fmt.Errorf("read %s: %w", dir, err)
		}
	}

	snap := model.Snapshot{
		PID:   pid,
		Taken: time.Now().UnixNano(),
		// Preallocate an exact-capacity slice: descriptor counts reach the
		// thousands on a loaded server and repeated growth reallocations would
		// dominate the sampling cost.
		Descriptors: make([]model.Descriptor, 0, len(entries)),
	}

	for _, entry := range entries {
		fdNum, convErr := strconv.Atoi(entry.Name())
		if convErr != nil {
			// /proc/<pid>/fd contains only numeric names; anything else is not
			// a descriptor and must not inflate the count.
			continue
		}

		full := filepath.Join(dir, entry.Name())
		target, linkErr := os.Readlink(full)
		if linkErr != nil {
			// The descriptor was closed between readdir and readlink. This is
			// normal churn, not a partial snapshot.
			if os.IsNotExist(linkErr) {
				continue
			}
			if os.IsPermission(linkErr) {
				snap.Unreadable++
				continue
			}
			snap.Unreadable++
			continue
		}

		fp, kind := p.Normalizer.Fingerprint(target)
		d := model.Descriptor{
			FD:          fdNum,
			Target:      target,
			Fingerprint: fp,
			Kind:        kind,
			Deleted:     strings.HasSuffix(target, " (deleted)"),
		}
		if off, flags, infoErr := readFDInfo(filepath.Join(p.procRoot(), strconv.Itoa(pid), "fdinfo", entry.Name())); infoErr == nil {
			d.Offset, d.Flags = off, flags
		}
		snap.Descriptors = append(snap.Descriptors, d)
	}

	sort.Slice(snap.Descriptors, func(i, j int) bool {
		return snap.Descriptors[i].FD < snap.Descriptors[j].FD
	})

	snap.OpenLimit = p.OpenLimit(pid)
	return snap, nil
}

// readFDInfo parses the pos and flags fields of one fdinfo file.
//
// Both fields are optional in practice: some descriptor types omit them, so a
// missing field is not an error and leaves the zero value in place.
func readFDInfo(path string) (offset int64, flags uint64, err error) {
	f, openErr := os.Open(path)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "pos":
			if v, parseErr := strconv.ParseInt(strings.TrimSpace(value), 10, 64); parseErr == nil {
				offset = v
			}
		case "flags":
			// flags is printed in octal by the kernel.
			if v, parseErr := strconv.ParseUint(strings.TrimSpace(value), 8, 64); parseErr == nil {
				flags = v
			}
		}
	}
	return offset, flags, scanner.Err()
}

// OpenLimit reads the soft limit on open files from /proc/<pid>/limits.
//
// It returns 0 when the limit cannot be read. Callers must treat 0 as
// "unknown" and suppress headroom maths, never as "unlimited": the two lead to
// opposite conclusions about risk.
func (p *Probe) OpenLimit(pid int) int {
	f, err := os.Open(filepath.Join(p.procRoot(), strconv.Itoa(pid), "limits"))
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// The line is: "Max open files            4096   1048576   files"
		// Soft limit is the second numeric field when "open files" is present.
		if len(fields) < 4 || !strings.Contains(strings.Join(fields[:3], " "), "Max open files") {
			continue
		}
		for _, field := range fields {
			if n, convErr := strconv.Atoi(field); convErr == nil {
				return n
			}
		}
	}
	return 0
}

// Exists reports whether pid currently has a /proc entry.
func (p *Probe) Exists(pid int) bool {
	_, err := os.Stat(filepath.Join(p.procRoot(), strconv.Itoa(pid)))
	return err == nil
}

// StartTime reads the process start time from field 22 of /proc/<pid>/stat.
//
// The value is in clock ticks since boot, not wall-clock: it is only ever
// compared with another reading from the same machine, which is exactly what
// diffing two snapshots needs. A pid is unique only among live processes, so
// "same pid" proves nothing on its own - comparing start times is how a
// restarted process is told apart from a running one.
//
// The field is extracted by scanning from the last ')' because field 2 (comm)
// may contain spaces and parentheses, e.g. "(my app)"; splitting on whitespace
// from the left is the standard way to get this wrong.
func (p *Probe) StartTime(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	data, err := os.ReadFile(filepath.Join(p.procRoot(), strconv.Itoa(pid), "stat"))
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return 0, fmt.Errorf("%w: %d", ErrNoSuchProcess, pid)
		case os.IsPermission(err):
			return 0, fmt.Errorf("%w: %d", ErrPermission, pid)
		default:
			return 0, fmt.Errorf("read stat of %d: %w", pid, err)
		}
	}
	return parseStartTime(string(data))
}

// parseStartTime extracts field 22 from a raw /proc/<pid>/stat line.
//
// Split out so the parsing - the part that is easy to get wrong - is reachable
// from tests without a live process.
func parseStartTime(stat string) (uint64, error) {
	// Find the closing paren of comm. Everything after it is space-separated
	// with no quoting, starting at field 3 (state).
	end := strings.LastIndexByte(stat, ')')
	if end < 0 || end+1 >= len(stat) {
		return 0, fmt.Errorf("malformed stat line %q", stat)
	}
	fields := strings.Fields(stat[end+1:])
	// fields[0] is field 3, so field 22 is fields[22-3].
	const startTimeField = 22
	idx := startTimeField - 3
	if len(fields) <= idx {
		return 0, fmt.Errorf("malformed stat line: %d fields after comm, need %d", len(fields), idx+1)
	}
	v, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse start time %q: %w", fields[idx], err)
	}
	return v, nil
}
