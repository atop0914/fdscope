// Package stackpair is the third and weakest attribution layer: it pairs the
// descriptors a check found still open with the goroutines that appeared while
// the checked code ran.
//
// # Why this is the weakest of the three layers
//
// /proc records no owner for a descriptor, and runtime.Stack records no history
// either: it is a photograph of the goroutines alive at one instant. Two
// photographs - one taken before the code ran, one after it returned - can only
// support one sentence: "these goroutines did not exist before and they exist
// now". They cannot say which of them opened a descriptor, when, or whether the
// descriptor and the goroutine have anything to do with each other beyond
// sharing a moment.
//
// So L3 is a hint about where to start reading, and every sentence it emits
// says so. L1 restates what the fingerprint already says (a fact about the
// resource). L2 observes co-occurrence across a window. L3 observes
// co-existence across two instants: the least evidence of the three, and the
// only one that can name a function.
//
// # What it is good for anyway
//
// A leaked descriptor is usually still held by a goroutine that is still alive:
// a connection nobody closed, a worker parked with its file open, a test that
// spawned a reader and never joined it. "12 goroutines, all in
// cache.(*Loader).refresh, created by cache.New" turns a bare count into a place
// to start reading, which is the whole purpose of a leak report.
//
// # Two comparison methods, and why the fallback is honest
//
// Goroutine ids are monotonic and never reused inside a process, so "the id is
// present after and absent before" is a precise definition of a goroutine that
// appeared. It depends on parsing a header, which is text; when a header cannot
// be parsed the comparison degrades to counting stack texts. That fallback has a
// known false positive - a goroutine that existed before but whose stack moved
// by a single line reads as new, because a stack photograph carries no identity
// - so the report always names the method it used. A reader's trust should
// depend on which one it was.
//
// # What it must never do
//
// Attribute. No grouping here says a goroutine holds a descriptor, let alone
// opened one. The runtime's own bookkeeping goroutines (the sweeper, the
// scavenger) appear and disappear for reasons that have nothing to do with the
// code under test; listing them would put the scheduler in a report about a
// leak, so they are counted and excluded, out loud.
package stackpair

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Capture sizes. A dump of a few thousand goroutines is a few hundred KB; the
// initial buffer is generous so that a normal run takes one allocation, and the
// cap exists so that a runaway process fails loudly instead of eating memory.
const (
	initialDumpBytes = 1 << 20
	maxDumpBytes     = 32 << 20
)

// ErrTruncated means the goroutine dump did not fit in the buffer.
//
// It is an error rather than a short capture because a truncated dump is a
// random sample of the goroutine set and would silently make "these goroutines
// appeared" a statement about whichever ones happened to fit.
var ErrTruncated = errors.New("fdscope: goroutine dump was truncated")

// Frame is one call frame, normalised for comparison.
//
// Function keeps the full import path so that two same-named methods of
// different types stay apart; File keeps the full path for the same reason,
// even though only the base name is ever printed.
type Frame struct {
	Function string
	File     string
	Line     int
}

// Goroutine is one goroutine from a capture.
type Goroutine struct {
	// ID is the runtime's identifier, or 0 when the header could not be parsed.
	ID int64
	// Frames are the goroutine's own call chain, topmost first. The creation
	// chain is not part of it: creation sites are recorded in CreatedBy and are
	// deliberately excluded from the fingerprint, so that goroutines started from
	// different places but sitting in the same function still merge into one row.
	Frames []Frame
	// CreatedBy is the "created by <fn>" line, without its goroutine number.
	CreatedBy string
}

// Capture is the goroutine set at one instant.
type Capture struct {
	// At is when the dump was taken. It is shown to a reader and never used for
	// arithmetic: this process builds no series out of it, and the wall clock on
	// a container is free to step.
	At         time.Time
	Goroutines []Goroutine
	// Unparsed counts headers whose id could not be read; any of them forces the
	// fingerprint comparison.
	Unparsed int
	// Malformed counts blocks that produced no usable frame and were dropped.
	Malformed int
}

// CaptureGoroutines photographs this process's goroutines.
func CaptureGoroutines() (Capture, error) { return captureGoroutines(maxDumpBytes) }

// captureGoroutines takes the dump with a bounded buffer.
//
// The bound is a parameter rather than a constant so that the truncation path
// can be exercised by a test: a branch that refuses to conclude is worth more
// than any other branch here, and an untestable one would rot.
func captureGoroutines(limit int) (Capture, error) {
	size := initialDumpBytes
	if limit < size {
		size = limit
	}
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < size {
			return Parse(string(buf[:n]), time.Now()), nil
		}
		if size >= limit {
			// n == len(buf) means the dump was cut off. Parsing it would describe
			// a subset of the process while reading like a description of it.
			return Capture{At: time.Now()}, fmt.Errorf("%w: more than %d bytes of goroutine stacks, "+
				"so the goroutine set is only partly visible", ErrTruncated, limit)
		}
		size *= 2
		if size > limit {
			size = limit
		}
	}
}

// Parse reads runtime.Stack(all=true) output.
//
// It is exported inside the module so that the layer can be tested against
// fixtures: the interesting cases - argument values that differ between two
// goroutines on the same path, an unparsable header, a runtime-only worker - are
// hard to produce on demand with real goroutines and trivial to write down.
func Parse(text string, at time.Time) Capture {
	c := Capture{At: at}
	var cur *Goroutine
	frameIdx := -1
	// The creation site is followed by its own file:line line, which belongs to
	// the creation site and not to the last frame of the stack. Attributing it to
	// that frame silently rewrites the call site of every goroutine to the one
	// place it was created from.
	inCreatedBy := false

	flush := func() {
		if cur == nil {
			return
		}
		if len(cur.Frames) == 0 {
			c.Malformed++
		} else {
			c.Goroutines = append(c.Goroutines, *cur)
		}
		cur, frameIdx, inCreatedBy = nil, -1, false
	}

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "goroutine "):
			flush()
			id := headerID(line)
			g := Goroutine{ID: id}
			if id == 0 {
				c.Unparsed++
			}
			cur, frameIdx = &g, -1
		case cur == nil:
			// Text before any header is not a dump this package understands.
			c.Malformed++
		case strings.HasPrefix(line, "created by "):
			cur.CreatedBy = createdBy(line)
			inCreatedBy = true
		case raw[0] == '\t':
			if inCreatedBy {
				inCreatedBy = false
				continue
			}
			if frameIdx >= 0 && frameIdx < len(cur.Frames) {
				cur.Frames[frameIdx].File, cur.Frames[frameIdx].Line = fileLine(line)
			}
		default:
			cur.Frames = append(cur.Frames, Frame{Function: functionName(line)})
			frameIdx = len(cur.Frames) - 1
			inCreatedBy = false
		}
	}
	flush()
	return c
}

// headerID reads the number out of "goroutine 12 [chan receive]:".
func headerID(line string) int64 {
	rest := strings.TrimPrefix(line, "goroutine ")
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// createdBy strips the prefix and the goroutine number from a creation line.
//
// The number is dropped on purpose: it identifies a goroutine inside one dump
// and nothing outside it, so keeping it would make two identical creation sites
// compare unequal.
func createdBy(line string) string {
	s := strings.TrimPrefix(line, "created by ")
	if i := strings.LastIndex(s, " in goroutine "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// functionName drops the argument values from a frame's function line.
//
// The last parenthesised group is the argument list; a method's receiver is
// printed earlier, as in "net.(*conn).Close(0xc000010018)", which is why this
// trims at the last "(" and not the first.
func functionName(line string) string {
	name := line
	if i := strings.LastIndexByte(name, '('); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

// fileLine splits "\t/tmp/x_test.go:31 +0x25" into path and line.
func fileLine(line string) (string, int) {
	s := strings.TrimSpace(line)
	if i := strings.LastIndex(s, " +0x"); i >= 0 {
		// Instruction offsets move with every rebuild and say nothing about
		// identity, so they are not part of a fingerprint.
		s = s[:i]
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return s, 0
	}
	return s[:i], n
}

// fingerprint is the merge key: the frames, with argument values and offsets
// already gone.
func fingerprint(frames []Frame) string {
	var b strings.Builder
	for _, f := range frames {
		b.WriteString(f.Function)
		b.WriteByte(0x1f)
		b.WriteString(f.File)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(f.Line))
		b.WriteByte('\n')
	}
	return b.String()
}

// Method names how the two captures were compared.
type Method string

const (
	// MethodGoroutineID is the precise comparison: ids are never reused.
	MethodGoroutineID Method = "goroutine id"
	// MethodStackText is the fallback, with its documented false positive.
	MethodStackText Method = "stack text"
)

// Group is one distinct stack, with how many new goroutines were sitting in it.
type Group struct {
	// Count is how many goroutines shared this stack.
	Count int
	// Frames is the stack, topmost first.
	Frames []Frame
	// Fingerprint is the merge key, kept so a caller can key on it.
	Fingerprint string
	// CreatedBy is set only when every goroutine in the group was created from
	// the same place; otherwise empty, because naming one of several would be a
	// claim the data does not support.
	CreatedBy string
}

// Focus is the frame worth printing: the first one that is not inside the Go
// runtime.
//
// A blocked goroutine's stack begins in runtime.gopark, so the topmost frame is
// almost always the scheduler's; what a reader wants is the function that
// parked, which is the first frame of their own code.
func (g Group) Focus() Frame {
	for _, f := range g.Frames {
		if !isRuntimeFrame(f) {
			return f
		}
	}
	if len(g.Frames) > 0 {
		return g.Frames[0]
	}
	return Frame{}
}

// Report is the L3 block.
type Report struct {
	// Before and After are the goroutine counts at the two captures, and New how
	// many goroutines the comparison found that were not in the first one.
	New    int
	Before int
	After  int
	// Method names the comparison actually used.
	Method Method
	// Groups holds the distinct stacks, most populous first.
	Groups []Group
	// Filtered counts new goroutines that were entirely inside the Go runtime and
	// are therefore not listed. It is reported rather than silently dropped: a
	// reader is entitled to know that the runtime was busy while the check ran.
	Filtered int
	// Notes explains the cases that produced nothing to show.
	Notes []string
	// At is when the second capture was taken.
	At time.Time
}

// Diff relates the goroutines that exist now to the goroutines that existed
// before the checked code ran.
func Diff(before, after Capture) Report {
	rep := Report{Before: len(before.Goroutines), After: len(after.Goroutines), At: after.At}

	switch {
	case rep.Before == 0:
		// Without a first photograph every goroutine looks new, which would turn
		// the whole process into a suspect.
		rep.Notes = append(rep.Notes, "the first capture held no goroutines at all, so every "+
			"goroutine would look new; nothing is paired against a baseline that was never taken")
		return rep
	case rep.After == 0:
		rep.Notes = append(rep.Notes, "the second capture held no goroutines at all, so there is "+
			"nothing to pair the open descriptors with")
		return rep
	}

	fresh := rep.fresh(before, after)

	byFingerprint := make(map[string]*Group, len(fresh))
	order := make([]string, 0, len(fresh))
	created := make(map[string]map[string]int, len(fresh))
	for _, g := range fresh {
		fp := fingerprint(g.Frames)
		grp, ok := byFingerprint[fp]
		if !ok {
			grp = &Group{Frames: g.Frames, Fingerprint: fp}
			byFingerprint[fp] = grp
			order = append(order, fp)
			created[fp] = make(map[string]int, 1)
		}
		grp.Count++
		if g.CreatedBy != "" {
			created[fp][g.CreatedBy]++
		}
	}

	rep.New = len(fresh)
	for _, fp := range order {
		grp := byFingerprint[fp]
		if runtimeOnly(grp.Frames) {
			// The sweeper and the scavenger start on their own schedule. Listing
			// them would attribute a leak to the scheduler, which is the kind of
			// confident wrong answer this project exists to avoid.
			rep.Filtered += grp.Count
			continue
		}
		if sites := created[fp]; len(sites) == 1 {
			for site := range sites {
				grp.CreatedBy = site
			}
		}
		rep.Groups = append(rep.Groups, *grp)
	}

	sort.Slice(rep.Groups, func(i, j int) bool {
		if rep.Groups[i].Count != rep.Groups[j].Count {
			return rep.Groups[i].Count > rep.Groups[j].Count
		}
		return rep.Groups[i].Fingerprint < rep.Groups[j].Fingerprint
	})

	if len(rep.Groups) == 0 && rep.Filtered == 0 {
		rep.Notes = append(rep.Notes, "no goroutine appeared while the checked code ran, so there "+
			"is nothing to pair the open descriptors with")
	}
	return rep
}

// fresh picks the goroutines that were not in the first capture.
func (r *Report) fresh(before, after Capture) []Goroutine {
	if before.Unparsed == 0 && after.Unparsed == 0 && allHaveIDs(before) && allHaveIDs(after) {
		r.Method = MethodGoroutineID
		seen := make(map[int64]struct{}, len(before.Goroutines))
		for _, g := range before.Goroutines {
			seen[g.ID] = struct{}{}
		}
		fresh := make([]Goroutine, 0, len(after.Goroutines))
		for _, g := range after.Goroutines {
			if _, ok := seen[g.ID]; !ok {
				fresh = append(fresh, g)
			}
		}
		return fresh
	}

	r.Method = MethodStackText
	r.Notes = append(r.Notes, "the goroutine headers could not all be read, so the captures were "+
		"compared by stack text; a goroutine that existed before but whose stack moved by a single "+
		"line therefore counts as new")
	// Multiset difference: how many more goroutines sit in each stack than before.
	remaining := make(map[string]int, len(before.Goroutines))
	for _, g := range before.Goroutines {
		remaining[fingerprint(g.Frames)]++
	}
	fresh := make([]Goroutine, 0, len(after.Goroutines))
	for _, g := range after.Goroutines {
		fp := fingerprint(g.Frames)
		if remaining[fp] > 0 {
			remaining[fp]--
			continue
		}
		fresh = append(fresh, g)
	}
	return fresh
}

// allHaveIDs reports whether every goroutine carries a parsed id.
func allHaveIDs(c Capture) bool {
	for _, g := range c.Goroutines {
		if g.ID == 0 {
			return false
		}
	}
	return true
}

// isRuntimeFrame reports whether a frame belongs to the Go runtime itself.
func isRuntimeFrame(f Frame) bool {
	if f.File != "" {
		return strings.Contains(f.File, "/src/runtime/")
	}
	return strings.HasPrefix(f.Function, "runtime.")
}

// runtimeOnly reports whether a whole stack is inside the runtime.
func runtimeOnly(frames []Frame) bool {
	if len(frames) == 0 {
		return false
	}
	for _, f := range frames {
		if !isRuntimeFrame(f) {
			return false
		}
	}
	return true
}

// Messages renders the block as sentences, one per line, each labelled.
//
// The label is repeated on every line because these lines arrive in a test log
// one at a time, where a heading three lines up is no longer visible.
func (r Report) Messages() []string {
	out := make([]string, 0, len(r.Groups)+len(r.Notes)+3)
	if len(r.Groups) > 0 {
		out = append(out, r.header())
		for _, g := range r.Groups {
			out = append(out, g.sentence())
		}
	}
	if r.Filtered > 0 {
		out = append(out, fmt.Sprintf("%d goroutine(s) appeared entirely inside the Go runtime - its "+
			"own workers, which start on their own schedule - and are not listed: naming them would "+
			"put the scheduler into a report about the checked code", r.Filtered))
	}
	out = append(out, r.Notes...)
	for i := range out {
		out[i] = "L3 sampling: " + out[i]
	}
	return out
}

// header states what was compared, and what a photograph cannot show.
func (r Report) header() string {
	return fmt.Sprintf("%d goroutine(s) appeared while the checked code ran (the process held %d "+
		"before and %d after); compared by %s. This is a photograph of two instants, not the moment "+
		"each descriptor was opened", r.New, r.Before, r.After, r.Method)
}

// sentence describes one group.
func (g Group) sentence() string {
	f := g.Focus()
	site := f.Function
	if f.File != "" {
		site = fmt.Sprintf("%s (%s:%d)", f.Function, path.Base(f.File), f.Line)
	}
	s := fmt.Sprintf("%d goroutine(s) sitting in %s", g.Count, site)
	if g.CreatedBy != "" {
		s += ", created by " + g.CreatedBy
	}
	return s + "; one line per distinct stack, not one per goroutine"
}
