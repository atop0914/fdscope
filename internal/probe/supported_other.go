//go:build !linux

package probe

// IsSupported reports whether this build can read Linux /proc descriptor state.
//
// fdscope is a Linux-only tool. There is deliberately no fallback
// implementation for other platforms: an empty result would be
// indistinguishable from "the process holds no descriptors", and every leak
// check built on top of it would silently pass. Callers get ErrNotLinux with
// an explanation instead of a plausible-looking zero.
func IsSupported() bool { return false }
