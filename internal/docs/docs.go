// Package docs checks that the documentation's own references resolve.
//
// Documentation rots silently. A moved file leaves behind a link that still
// looks like a link, and a renamed package leaves behind a code span that still
// looks like a package. No Go test notices either, because prose is not
// compiled - the first reader to find out is the one who clicked.
//
// This package makes the prose an input to the suite. It walks the Markdown this
// repository ships and reports every reference that points at nothing. There are
// three rules, each one a claim a reader would otherwise have to verify by hand:
//
//	links    every relative link resolves to a path that exists
//	paths    every `internal/...`, `cmd/...`, `pkg/...`, `testdata/...`,
//	         `docs/...`, `examples/...` or `.github/...` code span exists
//	entry    every docs/*.md is linked from the README
//
// The third rule is the one that keeps documentation findable rather than merely
// correct: a page nobody links to is a page nobody reads, no matter how accurate
// it is.
//
// Two deliberate exclusions, both of which would otherwise make the checker cry
// wolf about text that is fine:
//
//   - Fenced code blocks are skipped. A fence is a transcript - command output, a
//     shell session, a report - not a set of references. Paths inside one name
//     files that the example invented, and demanding they exist would be a demand
//     that the examples be wrong.
//   - A code span that names a Go symbol (`pkg/fdscope.LeakCheck`) is checked as
//     far as the package and no further. The symbol is not a path, and resolving
//     it would mean compiling the prose.
//
// Anything outside this repository belongs in a link, not a bare path: a code
// span is understood to name a file here, so `internal/x/y.go` from another
// project is indistinguishable from a dead reference. That is a feature - it
// forces upstream citations to be clickable.
package docs

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Problem is one unresolvable reference.
type Problem struct {
	// File is the Markdown file the reference appears in, relative to the
	// repository root with forward slashes.
	File string
	// Line is 1-based.
	Line int
	// Reason says what was wrong, in terms of the text that was written and
	// what it should have pointed at.
	Reason string
}

func (p Problem) String() string {
	return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Reason)
}

// repoRoots are the top-level directories a code span may name. The prefix is
// used to decide whether a span is a claim about this repository at all: a span
// holding `/proc/self/fd` or `socket:[123]` is a fact about Linux, and one
// holding `uber-go/goleak` is another project.
var repoRoots = []string{
	".github/",
	"cmd/",
	"docs/",
	"examples/",
	"internal/",
	"pkg/",
	"testdata/",
}

// Check resolves every reference in the repository's Markdown.
//
// It returns the problems found, sorted so that two runs over the same tree
// produce the same output: a checker whose findings move around cannot be
// compared with yesterday's run, and "it used to say five things" is the only
// useful question to ask of it.
//
// An error means the checker could not do its job - no README, no docs directory
// - and is distinct from a problem, which means it did its job and found
// something. The distinction matters: a checker that fails open (returning no
// problems because it could not read anything) reports a clean tree for every
// tree, and the test that calls it would pass forever.
func Check(root string) ([]Problem, error) {
	readmePath := filepath.Join(root, "README.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		return nil, fmt.Errorf("read README: %w", err)
	}

	docsDir := filepath.Join(root, "docs")
	entries, err := os.ReadDir(docsDir)
	if err != nil {
		return nil, fmt.Errorf("read docs directory: %w", err)
	}
	var pages []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			pages = append(pages, "docs/"+e.Name())
		}
	}
	sort.Strings(pages)
	if len(pages) == 0 {
		return nil, fmt.Errorf("no Markdown files under docs: there is nothing to check")
	}

	files := append([]string{"README.md"}, pages...)
	problems := make([]Problem, 0, len(files))
	linkedFromReadme := make(map[string]bool, len(pages))

	// The README is read from disk already; the rest one at a time so a read
	// error names the file that failed instead of the whole run.
	contents := map[string]string{"README.md": string(readme)}
	for _, rel := range pages {
		b, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", rel, readErr)
		}
		contents[rel] = string(b)
	}

	for _, rel := range files {
		// Fences are blanked out before anything is parsed, so that a code block
		// cannot contribute a link or a span. Blanking rather than deleting keeps
		// every byte offset - and therefore every line number - intact.
		masked := maskFences(contents[rel])

		for _, found := range links(masked) {
			if skipTarget(found.target) {
				continue
			}
			resolved, reason := resolve(rel, found.target)
			if reason != "" {
				problems = append(problems, Problem{File: rel, Line: lineAt(masked, found.offset), Reason: reason})
				continue
			}
			if rel == "README.md" {
				linkedFromReadme[resolved] = true
			}
			if !exists(root, resolved) {
				problems = append(problems, Problem{
					File:   rel,
					Line:   lineAt(masked, found.offset),
					Reason: fmt.Sprintf("link %q points at %s, which does not exist", found.target, resolved),
				})
			}
		}

		for _, span := range codeSpans(masked) {
			p, ok := pathToken(span)
			if !ok {
				continue
			}
			if !exists(root, p) {
				problems = append(problems, Problem{
					File:   rel,
					Line:   lineAt(masked, span.offset),
					Reason: fmt.Sprintf("code span `%s` names a path that does not exist", span.text),
				})
			}
		}
	}

	for _, page := range pages {
		if !linkedFromReadme[page] {
			problems = append(problems, Problem{
				File:   "README.md",
				Line:   1,
				Reason: fmt.Sprintf("%s is not linked from the README: a document with no entry point is not published", page),
			})
		}
	}

	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		if problems[i].Line != problems[j].Line {
			return problems[i].Line < problems[j].Line
		}
		return problems[i].Reason < problems[j].Reason
	})
	return problems, nil
}

// fenceMarker is the set of characters that open a fence. Both styles count,
// because a document that uses ~~~ for one block and ``` for the next is still
// a document with two transcripts in it.
// maskFences replaces fenced code blocks with spaces, one byte for one, so that
// offsets and line numbers still describe the original file.
func maskFences(s string) string {
	lines := strings.Split(s, "\n")
	open := ""
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		switch {
		case open == "" && (strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")):
			open = trimmed[:3]
			lines[i] = strings.Repeat(" ", len(ln))
		case open != "":
			if strings.HasPrefix(trimmed, open) {
				open = ""
			}
			lines[i] = strings.Repeat(" ", len(ln))
		}
	}
	return strings.Join(lines, "\n")
}

// target is one link destination, with the offset it was found at.
type target struct {
	target string
	offset int
}

// inlineLink matches [text](destination) and ![alt](destination). The optional
// title is consumed so that its words are not mistaken for a path.
var inlineLink = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// referenceLink matches a link definition line: [label]: destination.
var referenceLink = regexp.MustCompile(`(?m)^ {0,3}\[[^\]]+\]:\s*(\S+)`)

// links returns every link destination in the file.
//
// Reference-style definitions are included because they are how a long document
// keeps its links readable, and a stale one is exactly as dead as an inline one.
func links(s string) []target {
	var out []target
	for _, m := range inlineLink.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, target{target: s[m[2]:m[3]], offset: m[0]})
	}
	for _, m := range referenceLink.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, target{target: s[m[2]:m[3]], offset: m[0]})
	}
	return out
}

// codeSpan is one inline `...` span and where it started.
type codeSpan struct {
	text   string
	offset int
}

// inlineCode matches a single-line inline code span. Spans never contain a
// newline, and requiring that keeps an unmatched backtick from swallowing the
// rest of the document.
var inlineCode = regexp.MustCompile("`([^`\n]+)`")

func codeSpans(s string) []codeSpan {
	matches := inlineCode.FindAllStringSubmatchIndex(s, -1)
	out := make([]codeSpan, 0, len(matches))
	for _, m := range matches {
		out = append(out, codeSpan{text: s[m[2]:m[3]], offset: m[0]})
	}
	return out
}

// skipTarget reports whether a destination is not this repository's business:
// an absolute URL, a mail link, an in-page anchor, or nothing at all.
func skipTarget(t string) bool {
	switch {
	case t == "",
		strings.HasPrefix(t, "#"),
		strings.HasPrefix(t, "http://"),
		strings.HasPrefix(t, "https://"),
		strings.HasPrefix(t, "mailto:"):
		return true
	}
	return false
}

// resolve turns a link destination into a root-relative slash path, or returns a
// reason why it cannot be one.
//
// Query strings and fragments are dropped: "#l2-attribution" names a place
// inside a page, and the page is what has to exist.
func resolve(fromFile, dest string) (string, string) {
	t := dest
	if i := strings.IndexAny(t, "#?"); i >= 0 {
		t = t[:i]
	}
	if unescaped, err := url.PathUnescape(t); err == nil {
		t = unescaped
	}
	t = strings.TrimPrefix(t, "./")
	if t == "" {
		// The destination was only a fragment or a query, which names no file.
		return "", ""
	}
	joined := path.Clean(path.Join(path.Dir(fromFile), t))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", fmt.Sprintf("link %q points outside the repository", dest)
	}
	return joined, ""
}

// pathToken reports whether a code span names a path in this repository, and if
// so which one.
//
// The Go-symbol case is the only rewrite: `pkg/fdscope.LeakCheck` names the
// package `pkg/fdscope` plus a symbol. Only an uppercase suffix is stripped, so
// that a file name keeps its extension - `internal/model/model.go` must not
// become `internal/model/model`.
func pathToken(span codeSpan) (string, bool) {
	s := strings.TrimSpace(span.text)
	if s == "" || strings.ContainsAny(s, " \t") || strings.Contains(s, "://") {
		return "", false
	}
	if i := strings.LastIndexByte(s, '.'); i >= 0 && i+1 < len(s) {
		if c := s[i+1]; c >= 'A' && c <= 'Z' {
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, "/")
	for _, root := range repoRoots {
		if strings.HasPrefix(s, root) {
			return s, true
		}
	}
	return "", false
}

// exists reports whether rel exists under root, as a file or a directory. Both
// count: `internal/probe` names a package and `docs/design.md` names a file, and
// the reader of either expects to be able to open it.
//
// A pattern (`internal/probe/supported_*.go`) must match at least one file. That
// is not a leniency: prose names a family of files when the family is the point,
// and a family that has been renamed away is exactly as dead as a single dead
// path - it just fails more quietly, because nobody clicks a wildcard.
func exists(root, rel string) bool {
	full := filepath.Join(root, filepath.FromSlash(rel))
	if strings.ContainsAny(rel, "*?[") {
		matches, err := filepath.Glob(full)
		return err == nil && len(matches) > 0
	}
	_, err := os.Stat(full)
	return err == nil
}

// lineAt returns the 1-based line number of a byte offset.
func lineAt(s string, offset int) int {
	if offset > len(s) {
		offset = len(s)
	}
	return 1 + strings.Count(s[:offset], "\n")
}
