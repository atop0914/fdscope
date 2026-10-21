//go:build linux

package probe

import "os"

// IsSupported reports whether this build can read Linux /proc descriptor state.
//
// Build-tag gating is the load-bearing part: on non-Linux platforms the
// identical function returns false and every entry point fails loudly instead
// of handing back an empty snapshot. An empty snapshot would make every leak
// check pass, which is the single most dangerous possible behaviour for an
// auditing tool.
func IsSupported() bool {
	// The build tag already guarantees Linux; verify the mount actually exists
	// so a chroot or a hardened container without /proc is caught here rather
	// than deep inside a snapshot call.
	st, err := os.Stat(ProcRoot)
	if err != nil {
		return false
	}
	return st.IsDir()
}
