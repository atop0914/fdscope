package model

import (
	"fmt"
	"sort"
)

// CounterName identifies one process-level reading that /proc exposes beside the
// descriptor table.
//
// The names are the ones an operator would type into a shell (`syscw`, `Threads`
// in /proc/status), not a private vocabulary, so a reader can go and check the
// number the report quotes.
type CounterName string

const (
	// CounterThreads is the live thread count from /proc/<pid>/status Threads.
	CounterThreads CounterName = "threads"
	// CounterSyscallsRead is syscr from /proc/<pid>/io: read(2) calls made.
	CounterSyscallsRead CounterName = "syscr"
	// CounterSyscallsWrite is syscw from /proc/<pid>/io: write(2) calls made.
	CounterSyscallsWrite CounterName = "syscw"
	// CounterRSS is VmRSS from /proc/<pid>/status, in bytes.
	CounterRSS CounterName = "rss"
)

// Counter is one process-level reading taken alongside a snapshot.
//
// Known is a field rather than a sentinel because zero is a real answer for every
// counter here: a process that has not written anything has syscw 0, and a report
// that printed that as "unreadable" - or the other way round - would be wrong in
// the direction that gets believed. /proc/<pid>/io is unreadable for another
// user's process without CAP_SYS_PTRACE and VmRSS is absent for a kernel thread,
// so unknown is a state that actually happens in the field, not a defensive
// leftover.
type Counter struct {
	// Value is the reading. It is meaningless when Known is false.
	Value int64
	// Known reports whether the reading was actually taken.
	Known bool
}

// NewCounter returns a reading the kernel answered.
func NewCounter(v int64) Counter { return Counter{Value: v, Known: true} }

// UnknownCounter returns a reading that could not be taken.
func UnknownCounter() Counter { return Counter{} }

// String renders a reading for human output, where "unknown" must not look like
// a zero.
func (c Counter) String() string {
	if !c.Known {
		return "unknown"
	}
	return fmt.Sprintf("%d", c.Value)
}

// ProcessCounters is the set of process-level readings taken with one snapshot.
//
// It is a struct of named fields rather than a map so that a counter cannot be
// silently dropped by a typo in a string key, and so that "which counters exist"
// is answerable by reading the type instead of the documentation.
type ProcessCounters struct {
	Threads       Counter
	SyscallsRead  Counter
	SyscallsWrite Counter
	RSSBytes      Counter
}

// Get returns the named counter, or an unknown reading for a name this build does
// not carry. Returning unknown rather than zero keeps an unrecognised name from
// arriving in a report as a confident zero.
func (p ProcessCounters) Get(name CounterName) Counter {
	switch name {
	case CounterThreads:
		return p.Threads
	case CounterSyscallsRead:
		return p.SyscallsRead
	case CounterSyscallsWrite:
		return p.SyscallsWrite
	case CounterRSS:
		return p.RSSBytes
	}
	return UnknownCounter()
}

// Names lists the counters this build records, in the fixed order reports and
// tests iterate them.
//
// Sorted by name rather than by struct order so that output does not depend on
// the order fields happen to be declared in.
func (p ProcessCounters) Names() []CounterName {
	return []CounterName{CounterRSS, CounterSyscallsRead, CounterSyscallsWrite, CounterThreads}
}

// CounterSeries is one counter's readings across a window, one value per sample.
//
// Known is carried per sample rather than as a single flag for the whole series:
// a counter can be readable at one sample and not the next (the process may drop
// privileges, or /proc/<pid>/io may be denied while status is not), and collapsing
// that into "the series is fine" would fill the gap with a zero the kernel never
// reported.
type CounterSeries struct {
	// Counter names the reading.
	Counter CounterName
	// Values holds one reading per sample, oldest first.
	Values []int64
	// Known reports, per sample, whether Values is a real reading.
	Known []bool
}

// SortedCounters sorts counter names for deterministic output.
func SortedCounters(names []CounterName) []CounterName {
	out := append([]CounterName(nil), names...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
