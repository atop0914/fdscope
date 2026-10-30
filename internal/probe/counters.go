package probe

// This file reads the process-level counters that /proc exposes beside the
// descriptor table: threads, read/write syscall counts, resident set size.
//
// They exist for one question, asked in Day 8: "what else was the process doing
// when its descriptors started growing?" The answer is a correlation, never a
// cause - /proc does not record who opened a descriptor, and nothing here changes
// that.
//
// Two properties matter more than the parsing:
//
//	per-counter honesty - each reading is known or unknown on its own. VmRSS is
//	                     absent for a kernel thread while Threads is present, and
//	                     /proc/<pid>/io can be denied while status is not.
//	no zero fallback    - an unreadable counter is unknown, never 0. A zero
//	                     syscw is a fact ("this process has not written"), and
//	                     conflating it with "I could not look" is how a report
//	                     ends up claiming a process was idle.
//
// Reading these files does not require privileges for a process the caller owns,
// and no ptrace is involved: fdscope observes, it does not instrument.

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/atop0914/fdscope/internal/model"
)

// readCounters reads the process-level counters of pid.
//
// It never returns an error: a counter that cannot be read is reported as
// unknown, because losing the descriptor snapshot over a missing auxiliary file
// would discard the evidence the caller actually came for.
func (p *Probe) readCounters(pid int) model.ProcessCounters {
	var out model.ProcessCounters
	if text, err := readSmallFile(filepath.Join(p.procRoot(), strconv.Itoa(pid), "status")); err == nil {
		out.Threads, out.RSSBytes = parseStatusCounters(text)
	}
	if text, err := readSmallFile(filepath.Join(p.procRoot(), strconv.Itoa(pid), "io")); err == nil {
		out.SyscallsRead, out.SyscallsWrite = parseIOCounters(text)
	}
	return out
}

// readSmallFile reads a /proc file whole.
//
// /proc/<pid>/status is a few kilobytes; bufio over the bytes is enough and keeps
// the sampling path from allocating a scanner per sample.
func readSmallFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseStatusCounters extracts Threads and VmRSS from the text of a status file.
//
// Each key is optional and each has its own known flag: a kernel thread has no
// VmRSS line at all, and reporting 0 bytes for it would read as "this process
// uses no memory".
func parseStatusCounters(text string) (threads, rss model.Counter) {
	threads, rss = model.UnknownCounter(), model.UnknownCounter()
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "Threads":
			if n, err := strconv.ParseInt(fields[0], 10, 64); err == nil && n > 0 {
				threads = model.NewCounter(n)
			}
		case "VmRSS":
			// The kernel prints "VmRSS:  1234 kB". Anything else is a unit this
			// build does not know how to convert, and guessing bytes from it
			// would put a wrong number in the report.
			if len(fields) < 2 || fields[1] != "kB" {
				continue
			}
			if n, err := strconv.ParseInt(fields[0], 10, 64); err == nil && n >= 0 {
				rss = model.NewCounter(n * 1024)
			}
		}
	}
	return threads, rss
}

// parseIOCounters extracts syscr and syscw from the text of an io file.
//
// Both keys are optional for the same reason as above: the file's layout has
// grown over kernel versions, and a build that required every key would report
// nothing at all on an older kernel rather than the two counters it does have.
func parseIOCounters(text string) (syscr, syscw model.Counter) {
	syscr, syscw = model.UnknownCounter(), model.UnknownCounter()
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		switch key {
		case "syscr":
			if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && n >= 0 {
				syscr = model.NewCounter(n)
			}
		case "syscw":
			if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && n >= 0 {
				syscw = model.NewCounter(n)
			}
		}
	}
	return syscr, syscw
}
