package version

import (
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

func TestStringNeverRendersEmptyFields(t *testing.T) {
	// Injection is absent under `go test` and `go run`, and a build that silently
	// lost its ldflags must still say something a reader can interpret. An empty
	// pair of parentheses looks like a formatting bug rather than "no build
	// metadata", and a bare "dev" with no separator hides that the commit and
	// date were never set at all.
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
