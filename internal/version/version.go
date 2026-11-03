// Package version holds build metadata injected at link time.
//
// The variables are set by the Makefile via -ldflags "-X ...". They keep their
// defaults for `go run` and for `go test`, so callers never need to check for
// emptiness before printing.
//
// A binary installed with `go install module@version` never runs that Makefile,
// so the linker-injected values are absent - but the go command does record the
// module version in the build info. String falls back to it, because a released
// binary that reports "dev" sends the next bug report to the wrong commit. That
// is not hypothetical: the first thing checked after publishing v1.0.0 was
// `go install ...@v1.0.0`, and it printed "fdscope dev (unknown, unknown)".
package version

import (
	"runtime/debug"
	"strings"
)

var (
	// Version is the release version, normally derived from git describe.
	Version = "dev"
	// GitCommit is the abbreviated commit the binary was built from.
	GitCommit = "unknown"
	// BuildDate is the UTC build timestamp in RFC3339 form.
	BuildDate = "unknown"
)

// unknown is the placeholder for a field the build did not supply. It is a
// distinct value rather than an empty string so that "nobody set this" and
// "somebody set this to nothing" cannot be confused.
const unknown = "unknown"

// String renders the build identity.
func String() string {
	v, c, d := resolve(Version, GitCommit, BuildDate, buildInfo())
	return format(v, c, d)
}

func buildInfo() *debug.BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return bi
}

// resolve fills in the fields the linker left alone, from the module version and
// the VCS stamp that `go install` and `go build` record in the binary.
//
// Injection always wins: a binary built by the Makefile carries the version its
// Makefile chose, and the module version recorded at build time is not a better
// answer to "what was this built from".
func resolve(v, c, d string, bi *debug.BuildInfo) (string, string, string) {
	if bi == nil {
		return v, c, d
	}
	if v == "dev" && isReleaseVersion(bi.Main.Version) {
		v = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			// A forty-character hash is the full form; the abbreviated one is
			// what every other message about a commit uses.
			if c == unknown && len(s.Value) >= 7 {
				c = s.Value[:7]
			}
		case "vcs.time":
			if d == unknown && s.Value != "" {
				d = s.Value
			}
		}
	}
	return v, c, d
}

// isReleaseVersion reports whether a module version names a real version rather
// than the placeholder the toolchain writes for a module built from its own
// working directory.
func isReleaseVersion(v string) bool {
	return v != "" && v != "(devel)"
}

// format joins what is known, and drops what is not.
//
// "v1.0.0 (unknown, unknown)" reads like a bug in the formatter; "v1.0.0" reads
// like what it is - a release whose build carried no VCS stamp. The version on
// its own is still the answer to the question a user is actually asking.
func format(v, c, d string) string {
	parts := make([]string, 0, 2)
	if c != unknown {
		parts = append(parts, c)
	}
	if d != unknown {
		parts = append(parts, d)
	}
	if len(parts) == 0 {
		return v
	}
	return v + " (" + strings.Join(parts, ", ") + ")"
}
