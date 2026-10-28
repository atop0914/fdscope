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

// ErrProcessExited is returned when the pid still has a /proc entry but the entry
// belongs to a zombie.
//
// This distinction is not pedantry, it is the difference between a correct report
// and a fabricated one. A zombie keeps its /proc directory - so the pid still
// "exists" - but its fd directory is empty, because the kernel has already
// released its file table. Reading that as a snapshot produces a perfectly valid
// looking sample in which every descriptor was released at once. Applied to a leak
// audit that is the worst possible answer: the leaked resource is reported as
// freed at the exact moment the process died, and the tool's central claim
// silently inverts.
var ErrProcessExited = errors.New("process exited: pid now belongs to a zombie")

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

	// A process that has exited but not been reaped must be rejected before
	// anything is read from its fd directory. A zombie keeps its /proc directory
	// and its fd directory still exists, but the kernel has already dropped its
	// file table, so readdir can answer either an empty list (what this check
	// originally guarded against) or a flat EACCES, depending on whether the
	// entry is readable by the caller at all. Handing the EACCES to the caller
	// as ErrPermission names the wrong cause: "you may not look at this live
	// process" instead of "this process is gone, there is nothing to look at".
	//
	// Getting this wrong is not a small inaccuracy. A leak audit that sampled a
	// zombie would report every descriptor as released at the moment the process
	// died, which inverts the tool's conclusion at the worst possible time. The
	// live case (a process that genuinely holds nothing open) is unaffected
	// because its state is S/R/D, never Z.
	if exited, stateErr := p.exited(pid); stateErr == nil && exited {
		return model.Snapshot{}, fmt.Errorf("%w: %d", ErrProcessExited, pid)
	}

	dir := p.fdDir(pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return model.Snapshot{}, fmt.Errorf("%w: %d", ErrNoSuchProcess, pid)
		case os.IsPermission(err):
			// Re-read the state: the process may have been reaped between the
			// check above and this read, in which case EACCES is still the wrong
			// diagnosis and "not found" (or "exited") is the right one.
			if exited, stateErr := p.exited(pid); stateErr == nil && exited {
				return model.Snapshot{}, fmt.Errorf("%w: %d", ErrProcessExited, pid)
			}
			if !p.Exists(pid) {
				return model.Snapshot{}, fmt.Errorf("%w: %d", ErrNoSuchProcess, pid)
			}
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

// OpenLimit reads RLIMIT_NOFILE from /proc/<pid>/limits.
//
// The three outcomes are kept apart. The kernel writes either a number or the
// literal "unlimited" in each of the two columns, and the file may be missing or
// unreadable - and folding that last case into 0 is how a report ends up
// subtracting descriptors from a limit of zero and announcing an emergency.
// Unknown is therefore its own state, never 0 and never unlimited.
func (p *Probe) OpenLimit(pid int) model.OpenLimit {
	f, err := os.Open(filepath.Join(p.procRoot(), strconv.Itoa(pid), "limits"))
	if err != nil {
		return model.UnknownLimit()
	}
	defer func() { _ = f.Close() }()

	var b strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		b.WriteString(scanner.Text())
		b.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		// A partial read could stop before the line we need, and a limit we did
		// not see is not a limit of zero.
		return model.UnknownLimit()
	}
	return parseLimits(b.String())
}

// parseLimits extracts both RLIMIT_NOFILE columns from the text of a limits file.
//
// Split out from the file read so the parsing is testable without a process
// whose ulimit was arranged for the occasion - the "unlimited" and "unreadable"
// cases are otherwise very hard to reproduce on a machine running as root.
func parseLimits(text string) model.OpenLimit {
	for _, line := range strings.Split(text, "\n") {
		// The line is: "Max open files            4096   1048576   files"
		// Names are padded with spaces, so fields are the only reliable split.
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)
		// "Max" "open" "files" <soft> <hard> <units>
		if len(fields) < 5 {
			return model.UnknownLimit()
		}
		soft, softState := parseLimitField(fields[3])
		hard, hardState := parseLimitField(fields[4])
		switch softState {
		case model.LimitUnlimited:
			return model.UnlimitedLimit()
		case model.LimitKnown:
			if hardState == model.LimitKnown {
				return model.KnownLimitPair(soft, hard)
			}
			return model.KnownLimit(soft)
		}
		return model.UnknownLimit()
	}
	return model.UnknownLimit()
}

// parseLimitField reads one column: a number, "unlimited", or neither.
func parseLimitField(field string) (int, model.LimitState) {
	if field == "unlimited" {
		return 0, model.LimitUnlimited
	}
	n, err := strconv.ParseInt(field, 10, 64)
	if err != nil || n <= 0 {
		return 0, model.LimitUnknown
	}
	// A limit beyond the address space of this build cannot be used in
	// arithmetic; report it as unknown rather than wrapping to a negative.
	if n > int64(^uint(0)>>1) {
		return 0, model.LimitUnknown
	}
	return int(n), model.LimitKnown
}

// Exists reports whether pid currently has a /proc entry.
func (p *Probe) Exists(pid int) bool {
	_, err := os.Stat(filepath.Join(p.procRoot(), strconv.Itoa(pid)))
	return err == nil
}

// exited reports whether the pid's /proc entry belongs to a zombie.
//
// It is deliberately separate from Exists: a zombie satisfies Exists, so any
// caller that uses Exists as a liveness check will treat a dead process as alive.
// The state is field 3 of /proc/<pid>/stat, which sits after the comm field and
// therefore has to be located from the last ')' - comm may contain both spaces and
// parentheses.
func (p *Probe) exited(pid int) (bool, error) {
	data, err := os.ReadFile(filepath.Join(p.procRoot(), strconv.Itoa(pid), "stat"))
	if err != nil {
		return false, err
	}
	return parseZombie(string(data))
}

// parseZombie reports whether a raw /proc/<pid>/stat line describes a zombie.
//
// Split out so the parsing is reachable from tests without a dying process.
func parseZombie(stat string) (bool, error) {
	state, err := parseState(stat)
	if err != nil {
		return false, err
	}
	return state == "Z", nil
}

// parseState extracts field 3 (the process state letter) from a stat line.
func parseState(stat string) (string, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 || end+1 >= len(stat) {
		return "", fmt.Errorf("malformed stat line %q", stat)
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) == 0 {
		return "", fmt.Errorf("malformed stat line: no fields after comm")
	}
	return fields[0], nil
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
