package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestStringCarriesEveryField(t *testing.T) {
	oldVer, oldCommit, oldDate := Version, GitCommit, BuildDate
	t.Cleanup(func() { Version, GitCommit, BuildDate = oldVer, oldCommit, oldDate })
	Version, GitCommit, BuildDate = "v1.2.3", "deadbee", "2026-01-02T03:04:05Z"

	const want = "v1.2.3 (deadbee, 2026-01-02T03:04:05Z)"
	if got := String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

// TestGoInstallFallback is the regression for the shape that v1.0.0 shipped and
// then disproved: a binary built by `go install module@version` has none of the
// linker-injected values, only the module version in its build info, and it
// reported "dev (unknown, unknown)".
func TestGoInstallFallback(t *testing.T) {
	// Exactly what `go install github.com/atop0914/fdscope/cmd/fdscope@v1.0.1`
	// produces: a main module with a real version and no VCS stamp, because the
	// build ran from the module cache rather than a checkout.
	bi := &debug.BuildInfo{Main: debug.Module{Path: "github.com/atop0914/fdscope", Version: "v1.0.1"}}

	v, c, d := resolve("dev", unknown, unknown, bi)
	if v != "v1.0.1" {
		t.Fatalf("version = %q, want the module version v1.0.1", v)
	}
	if c != unknown || d != unknown {
		t.Fatalf("commit/date = %q/%q, want them left unknown: nothing stamped them", c, d)
	}
	if got := format(v, c, d); got != "v1.0.1" {
		t.Fatalf("format = %q, want %q - an unknown field must be dropped, not printed", got, "v1.0.1")
	}
}

// TestInjectedVersionWins is the reverse: the fallback must not overwrite what
// the Makefile injected, or a locally built binary would claim to be whatever
// release the module cache happens to hold.
func TestInjectedVersionWins(t *testing.T) {
	bi := &debug.BuildInfo{Main: debug.Module{Version: "v1.0.1"}}
	v, _, _ := resolve("v9.9.9-local", unknown, unknown, bi)
	if v != "v9.9.9-local" {
		t.Fatalf("version = %q, want the injected v9.9.9-local", v)
	}
}

func TestDevVersionIsNotTakenFromModuleDevel(t *testing.T) {
	// "(devel)" is what the toolchain writes for a module built from its own
	// working directory. Reporting it would be worse than reporting "dev".
	bi := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}
	if v, _, _ := resolve("dev", unknown, unknown, bi); v != "dev" {
		t.Fatalf("version = %q, want dev", v)
	}
	if v, _, _ := resolve("dev", unknown, unknown, &debug.BuildInfo{}); v != "dev" {
		t.Fatalf("version with empty build info = %q, want dev", v)
	}
}

func TestVCSStampFillsOnlyWhatIsMissing(t *testing.T) {
	const full = "0123456789abcdef0123456789abcdef01234567"
	bi := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.0.1"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: full},
			{Key: "vcs.time", Value: "2026-11-03T12:00:00Z"},
		},
	}
	v, c, d := resolve("dev", unknown, unknown, bi)
	if c != full[:7] {
		t.Fatalf("commit = %q, want the abbreviated %q", c, full[:7])
	}
	if d != "2026-11-03T12:00:00Z" {
		t.Fatalf("date = %q, want the stamped time", d)
	}
	if got, want := format(v, c, d), "v1.0.1 ("+full[:7]+", 2026-11-03T12:00:00Z)"; got != want {
		t.Fatalf("format = %q, want %q", got, want)
	}

	// An injected commit is already abbreviated; the VCS stamp must not replace
	// it with the same fact in a longer form.
	if _, c2, _ := resolve("v1.0.1", "abc1234", "2026-01-01T00:00:00Z", bi); c2 != "abc1234" {
		t.Fatalf("commit = %q, want the injected abc1234", c2)
	}
}

func TestFormatDropsUnknownFields(t *testing.T) {
	cases := []struct {
		name    string
		v, c, d string
		want    string
	}{
		{"all known", "v1.0.0", "abc1234", "2026-11-03T12:00:00Z", "v1.0.0 (abc1234, 2026-11-03T12:00:00Z)"},
		{"no stamp", "v1.0.0", unknown, unknown, "v1.0.0"},
		{"commit only", "v1.0.0", "abc1234", unknown, "v1.0.0 (abc1234)"},
		{"date only", "v1.0.0", unknown, "2026-11-03T12:00:00Z", "v1.0.0 (2026-11-03T12:00:00Z)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := format(tc.v, tc.c, tc.d); got != tc.want {
				t.Fatalf("format = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStringNeverRendersEmptyFields(t *testing.T) {
	// Injection is absent under `go test` and `go run`, and whatever the build
	// info holds must not turn into an empty pair of parentheses: that reads like
	// a formatting bug rather than "no build metadata".
	got := String()
	if got == "" {
		t.Fatal("String() is empty")
	}
	for _, bad := range []string{"()", "(, ", ", )", "( ,", ", ,"} {
		if strings.Contains(got, bad) {
			t.Fatalf("String() = %q contains %q: a field was left empty", got, bad)
		}
	}
	if !strings.HasPrefix(got, "dev") {
		t.Fatalf("String() = %q, want the dev default when nothing was injected", got)
	}
}
