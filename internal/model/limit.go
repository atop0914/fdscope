package model

import "fmt"

// LimitState says what /proc actually answered about a resource limit.
//
// The three states exist because "0" was doing three jobs at once. In
// /proc/<pid>/limits the open-file limit can be a number, the literal
// "unlimited", or absent because the file could not be read - and a parser that
// folds all three into 0 makes every headroom calculation subtract from zero.
// The visible symptom was a report saying a process with a 1 MiB limit had
// already crossed it, or one saying a limit of 0 was "far away".
//
// The failure is asymmetric, which is why this is a type rather than a comment:
// treating unlimited as 0 invents a leak risk that does not exist, and treating
// an unreadable limit as unlimited hides the one that does.
type LimitState string

const (
	// LimitKnown means a finite soft limit was read.
	LimitKnown LimitState = "known"
	// LimitUnlimited means the kernel reported "unlimited": no EMFILE is
	// reachable by opening descriptors.
	LimitUnlimited LimitState = "unlimited"
	// LimitUnknown means the limit could not be determined. It is neither
	// unlimited nor zero, and no headroom maths may be done with it.
	LimitUnknown LimitState = "unknown"
)

// OpenLimit is the RLIMIT_NOFILE pair for one process.
//
// Soft is the value the kernel enforces; Hard is the ceiling Soft can be raised
// to without privileges. Both are meaningful only in the state that produced
// them: Soft is ignored unless State is LimitKnown, and Hard is 0 when the hard
// limit was unlimited or unreadable.
type OpenLimit struct {
	State LimitState
	Soft  int
	Hard  int
}

// KnownLimit returns a finite soft limit with no hard limit recorded.
func KnownLimit(soft int) OpenLimit {
	if soft <= 0 {
		// A limit of zero is not a usable number: it is what a failed parse
		// looks like. Reporting it as "known" would put a 0 into a subtraction.
		return UnknownLimit()
	}
	return OpenLimit{State: LimitKnown, Soft: soft}
}

// KnownLimitPair returns both columns as /proc reported them.
func KnownLimitPair(soft, hard int) OpenLimit {
	l := KnownLimit(soft)
	if l.Known() && hard >= soft {
		l.Hard = hard
	}
	return l
}

// UnlimitedLimit returns the limit state where EMFILE is unreachable.
func UnlimitedLimit() OpenLimit { return OpenLimit{State: LimitUnlimited} }

// UnknownLimit returns the state where nothing is known about the limit.
func UnknownLimit() OpenLimit { return OpenLimit{State: LimitUnknown} }

// Normalized returns the limit with every field consistent with its state.
//
// It is the guard against the zero value and against a hand-built struct: a
// "known" limit without a positive number becomes unknown, a hard limit below
// the soft one is dropped rather than printed, and the unlimited state sheds the
// numbers it cannot have.
func (l OpenLimit) Normalized() OpenLimit {
	switch l.StateOrUnknown() {
	case LimitKnown:
		if l.Soft <= 0 {
			return UnknownLimit()
		}
		n := l
		if n.Hard < n.Soft {
			n.Hard = 0
		}
		return n
	case LimitUnlimited:
		return UnlimitedLimit()
	}
	return UnknownLimit()
}

// LimitOf rebuilds an OpenLimit from a state and a number, degrading anything
// inconsistent to unknown.
//
// It exists for carriers that keep the state and the number in separate wire
// fields, so that the reconstruction cannot invent a limit the kernel never
// reported.
func LimitOf(state LimitState, soft int) OpenLimit {
	return OpenLimit{State: state, Soft: soft}.Normalized()
}

// StateOrUnknown normalises the zero value to LimitUnknown.
//
// The zero value of OpenLimit has an empty State, and an empty state must never
// be read as "known" or as "unlimited": both would be an answer the operating
// system did not give.
func (l OpenLimit) StateOrUnknown() LimitState {
	switch l.State {
	case LimitKnown, LimitUnlimited:
		return l.State
	}
	return LimitUnknown
}

// Known reports whether Soft is a usable finite number.
func (l OpenLimit) Known() bool {
	return l.StateOrUnknown() == LimitKnown && l.Soft > 0
}

// Unlimited reports whether the kernel said "unlimited".
func (l OpenLimit) Unlimited() bool { return l.StateOrUnknown() == LimitUnlimited }

// Unknown reports whether the limit could not be determined.
func (l OpenLimit) Unknown() bool { return l.StateOrUnknown() == LimitUnknown }

// Remaining is how many descriptors are left before the soft limit is reached.
// The second result is false when the limit is not a finite number, which is the
// case where a caller must not do headroom maths at all.
func (l OpenLimit) Remaining(used int) (int, bool) {
	if !l.Known() {
		return 0, false
	}
	return l.Soft - used, true
}

// Describe renders the limit on its own, for messages that need to name it.
func (l OpenLimit) Describe() string {
	switch l.StateOrUnknown() {
	case LimitKnown:
		return fmt.Sprintf("%d", l.Soft)
	case LimitUnlimited:
		return "unlimited"
	}
	return "unknown"
}
