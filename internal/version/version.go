// Package version holds build metadata injected at link time.
//
// The variables are set by the Makefile via -ldflags "-X ...". They keep their
// defaults for `go run` and for `go test`, so callers never need to check for
// emptiness before printing.
package version

// Version is the release version, normally derived from git describe.
var Version = "dev"

// GitCommit is the abbreviated commit the binary was built from.
var GitCommit = "unknown"

// BuildDate is the UTC build timestamp in RFC3339 form.
var BuildDate = "unknown"

// String renders the build identity.
func String() string {
	return Version + " (" + GitCommit + ", " + BuildDate + ")"
}
