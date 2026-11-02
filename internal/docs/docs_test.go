package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture builds a throwaway documentation tree and returns its root.
//
// Every case below starts from the same clean tree and breaks exactly one thing,
// so that a failure says which rule stopped working rather than "the checker
// found something".
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	if files == nil {
		files = map[string]string{}
	}
	root := t.TempDir()
	base := map[string]string{
		"README.md": `# fdscope

| Document | Read it when |
|---|---|
| [docs/design.md](docs/design.md) | you want the reasoning |
| [docs/corpus.md](docs/corpus.md) | you want the evidence |

See [the design](docs/design.md#the-shape) for ` + "`internal/probe`" + ` and
` + "`pkg/fdscope.LeakCheck`" + `.
`,
		"docs/design.md":          "# Design\n\nBack to [corpus](corpus.md), and the probe lives in `internal/probe/probe.go`.\n",
		"docs/corpus.md":          "# Corpus\n\nSee [design](design.md).\n",
		"internal/probe/probe.go": "package probe\n",
		"pkg/fdscope/fdscope.go":  "package fdscope\n",
	}
	merged := make(map[string]string, len(base)+len(files))
	for name, content := range base {
		merged[name] = content
	}
	// The caller's files win: every case below breaks exactly one thing about the
	// clean tree, and a fixture that overwrote the breakage would test nothing.
	for name, content := range files {
		merged[name] = content
	}
	for name, content := range merged {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

func checkOrFail(t *testing.T, root string) []Problem {
	t.Helper()
	problems, err := Check(root)
	if err != nil {
		t.Fatalf("Check(%s) returned an error: %v", root, err)
	}
	return problems
}

// wantProblem asserts that exactly one problem was reported and that it contains
// every fragment, which is how these tests say "this rule fired, and it fired for
// the reason it exists" rather than "something happened".
func wantProblem(t *testing.T, problems []Problem, fragments ...string) {
	t.Helper()
	if len(problems) != 1 {
		t.Fatalf("got %d problems, want exactly 1: %v", len(problems), problems)
	}
	got := problems[0].String()
	for _, want := range fragments {
		if !strings.Contains(got, want) {
			t.Fatalf("problem %q does not mention %q", got, want)
		}
	}
}

func TestCleanTreeHasNoProblems(t *testing.T) {
	root := fixture(t, nil)
	if problems := checkOrFail(t, root); len(problems) != 0 {
		t.Fatalf("clean tree reported problems: %v", problems)
	}
}

func TestDeadLinkIsReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"README.md": "# fdscope\n\n| [docs/design.md](docs/design.md) | x |\n| [docs/corpus.md](docs/corpus.md) | y |\n\n" +
			"Read [the roadmap](docs/roadmap.md) next.\n",
	})
	// docs/roadmap.md is linked but never written: the exact rot this catches.
	wantProblem(t, checkOrFail(t, root), "README.md:6", "docs/roadmap.md", "does not exist")
}

func TestDeadLinkFromADocIsReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/design.md": "# Design\n\nSee [the corpus](corpus.md) and [the old notes](notes/2019.md).\n",
	})
	wantProblem(t, checkOrFail(t, root), "docs/design.md:3", "notes/2019.md")
}

func TestUnlinkedPageIsReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/internals.md": "# Internals\n\nNobody links here.\n",
	})
	wantProblem(t, checkOrFail(t, root), "README.md:1", "docs/internals.md", "no entry point")
}

func TestMissingCodeSpanPathIsReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/design.md": "# Design\n\nThe reader is in `internal/reader/scanner.go`.\n",
	})
	wantProblem(t, checkOrFail(t, root), "docs/design.md:3", "internal/reader/scanner.go", "does not exist")
}

func TestLinkOutsideTheRepositoryIsReported(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/design.md": "# Design\n\nSee [the licence](../../LICENCE).\n",
	})
	wantProblem(t, checkOrFail(t, root), "docs/design.md:3", "outside the repository")
}

func TestReferenceStyleLinkIsChecked(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/design.md": "# Design\n\nSee [the corpus][corpus].\n\n[corpus]: gone.md\n",
	})
	wantProblem(t, checkOrFail(t, root), "docs/design.md:5", "gone.md")
}

// TestSymbolAndFenceAreNotPaths is the reverse direction, and the reason it is
// its own test: a checker that reports everything is as useless as one that
// reports nothing, and these are the two shapes that look like paths and are not.
func TestSymbolAndFenceAreNotPaths(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/design.md": "# Design\n\n" +
			"Symbol suffix: `pkg/fdscope.LeakCheck` and `internal/probe.Probe`.\n\n" +
			"```console\n" +
			"$ ls internal/gone/from/the/transcript\n" +
			"see [also](../nowhere.md)\n" +
			"```\n",
	})
	if problems := checkOrFail(t, root); len(problems) != 0 {
		t.Fatalf("clean shapes reported as problems: %v", problems)
	}
}

// TestCheckerCannotRunIsAnError pins the fail-open bug in place: a checker that
// returns "no problems" when it could read nothing would report every tree as
// clean, and the suite that calls it would pass forever.
func TestCheckerCannotRunIsAnError(t *testing.T) {
	t.Run("no README", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "docs"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "docs", "a.md"), []byte("# A\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root); err == nil {
			t.Fatal("Check on a tree with no README returned no error")
		}
	})

	t.Run("no docs", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# fdscope\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root); err == nil {
			t.Fatal("Check on a tree with no docs directory returned no error")
		}
	})

	t.Run("empty docs", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# fdscope\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "docs"), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root); err == nil {
			t.Fatal("Check on a tree with no Markdown under docs returned no error")
		}
	})
}

// TestThisRepositoryPasses is the gate itself. Everything above proves the
// checker works; this proves the documentation does.
func TestThisRepositoryPasses(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "go.mod")); statErr != nil {
		t.Fatalf("%s does not look like the repository root: %v", root, statErr)
	}
	problems, err := Check(root)
	if err != nil {
		t.Fatalf("Check(%s): %v", root, err)
	}
	if len(problems) != 0 {
		lines := make([]string, 0, len(problems))
		for _, p := range problems {
			lines = append(lines, "  "+p.String())
		}
		t.Fatalf("documentation has %d unresolvable reference(s):\n%s",
			len(problems), strings.Join(lines, "\n"))
	}
}

// TestGlobMustMatchSomething covers the one path shape that cannot be stat'ed. A
// wildcard is how prose names a family of files, and a family that was renamed
// away fails more quietly than a single dead path: nobody clicks a wildcard, so
// nothing tells the reader it stopped meaning anything.
func TestGlobMustMatchSomething(t *testing.T) {
	t.Run("matches", func(t *testing.T) {
		root := fixture(t, map[string]string{
			"docs/design.md":                "# Design\n\nThe platform files are `internal/probe/probe_*.go`.\n",
			"internal/probe/probe_linux.go": "package probe\n",
		})
		if problems := checkOrFail(t, root); len(problems) != 0 {
			t.Fatalf("a wildcard that matches reported a problem: %v", problems)
		}
	})

	t.Run("matches nothing", func(t *testing.T) {
		root := fixture(t, map[string]string{
			"docs/design.md": "# Design\n\nThe platform files are `internal/probe/gone_*.go`.\n",
		})
		wantProblem(t, checkOrFail(t, root), "docs/design.md:3", "gone_*.go")
	})
}

// TestLineNumbersPointAtTheReference guards the one thing a report is useless
// without: a line number a reader can jump to. The fixture puts the reference on
// a known line and the assertion names it.
func TestLineNumbersPointAtTheReference(t *testing.T) {
	root := fixture(t, map[string]string{
		"docs/design.md": "# Design\n\nline three\nline four\nlast line names `internal/nowhere/x.go`\n",
	})
	problems := checkOrFail(t, root)
	if len(problems) != 1 {
		t.Fatalf("got %d problems, want 1: %v", len(problems), problems)
	}
	if problems[0].Line != 5 {
		t.Fatalf("problem reported on line %d, want 5: %v", problems[0].Line, problems[0])
	}
}
