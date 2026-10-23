// Package cli implements the fdscope command line: argument parsing, output
// rendering and exit-code policy.
//
// The package is split out of main so that every branch - including error
// paths and exit codes - is reachable from tests without spawning a process.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/probe"
)

// errLeakFound signals that an audit judged a leak present. It is a sentinel so
// that main can map it to a distinct exit code without string matching.
var errLeakFound = errors.New("leak detected")

// ExitLeakFound is the exit code used when an audit finds a leak. CI matches on
// this value, so it must stay stable across releases.
const ExitLeakFound = 2

const usage = `fdscope - audit file descriptor usage of a Linux process

Usage:
  fdscope snapshot <pid> [--json] [--top N]
  fdscope diff <pid> [--interval D] [--count N] [--json]
  fdscope watch <pid> [--interval D] [--samples N] [--keep N] [--json]
  fdscope version

snapshot:
  Capture the current descriptor set of <pid>, grouped by normalised
  fingerprint. The table shows how many descriptors share each resource, which
  is the first thing to look at when a count is suspiciously high.

watch:
  Sample <pid> repeatedly and report the shape of each series: rising, falling or
  flat, plus whether the resource rose to a peak and fell back. "Rising and
  staying" is what leaks; "rising and coming back" is work being done, and two
  snapshots cannot tell them apart.
`

// Run dispatches a subcommand. args excludes the program name.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		if _, err := fmt.Fprint(stderr, usage); err != nil {
			return err
		}
		return errors.New("no command given")
	}

	switch args[0] {
	case "snapshot":
		return runSnapshot(args[1:], stdout, stderr)
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "watch":
		return runWatch(args[1:], stdout, stderr)
	case "version":
		_, err := fmt.Fprintln(stdout, "fdscope "+Version)
		return err
	case "-h", "--help", "help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	default:
		if _, err := fmt.Fprint(stderr, usage); err != nil {
			return err
		}
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// ExitCode maps an error to a process exit code.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, errLeakFound) {
		return ExitLeakFound
	}
	return 1
}

// Version is the reported build version. It is overridden at link time by the
// Makefile and falls back to "dev" for `go run`.
var Version = "dev"

func runSnapshot(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	top := fs.Int("top", 0, "limit output to the N largest fingerprint groups (0 = all)")
	keepDir := fs.Bool("keep-dir", true, "keep directory components in fingerprints")
	stripRotation := fs.Bool("strip-rotation", true, "merge rotated log files into one fingerprint")

	// Accept the pid in any position relative to the flags. Go's flag package
	// stops parsing at the first non-flag argument, so "snapshot 1 --top 10"
	// would otherwise leave "--top 10" unconsumed and silently ignored - the
	// user sees full output and assumes the flag does not work.
	args, positionals := splitFlags(args, fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	positionals = append(positionals, fs.Args()...)
	if len(positionals) != 1 {
		return fmt.Errorf("snapshot requires exactly one pid, got %d", len(positionals))
	}
	pid, err := strconv.Atoi(positionals[0])
	if err != nil {
		return fmt.Errorf("invalid pid %q: %w", positionals[0], err)
	}
	if *top < 0 {
		return errors.New("--top must be >= 0")
	}

	p := probe.NewProbe()
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		p.Normalizer.HomeDir = home
	}
	p.Normalizer.KeepDir = *keepDir
	p.Normalizer.StripRotation = *stripRotation

	snap, err := p.Snapshot(pid)
	if err != nil {
		return err
	}

	if *asJSON {
		return writeSnapshotJSON(stdout, snap, *top)
	}
	return writeSnapshotTable(stdout, snap, *top)
}

// snapshotReport is the JSON shape of a snapshot.
//
// It is a separate type rather than marshalling model.Snapshot directly so that
// the wire format stays stable when internal fields are refactored. The
// timestamp is rendered as RFC3339 because CI logs are read by humans.
type snapshotReport struct {
	PID        int                      `json:"pid"`
	Taken      string                   `json:"taken"`
	Total      int                      `json:"total"`
	Unreadable int                      `json:"unreadable"`
	Complete   bool                     `json:"complete"`
	Headroom   model.Headroom           `json:"headroom"`
	ByKind     map[string]int           `json:"by_kind"`
	Groups     []model.FingerprintCount `json:"groups"`
}

func buildReport(snap model.Snapshot, top int) snapshotReport {
	rows := snap.SortedFingerprints()
	if top > 0 && len(rows) > top {
		// Copy before truncating: rows may share backing storage with the
		// snapshot and callers below still need the full slice's ordering.
		rows = rows[:top]
	}
	byKind := map[string]int{}
	for k, v := range snap.CountByKind() {
		byKind[string(k)] = v
	}
	return snapshotReport{
		PID:        snap.PID,
		Taken:      time.Unix(0, snap.Taken).Format(time.RFC3339Nano),
		Total:      snap.Len(),
		Unreadable: snap.Unreadable,
		Complete:   snap.Complete(),
		Headroom:   model.Headroom{PID: snap.PID, Used: snap.Len(), Limit: snap.OpenLimit},
		ByKind:     byKind,
		Groups:     rows,
	}
}

func writeSnapshotJSON(w io.Writer, snap model.Snapshot, top int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(buildReport(snap, top))
}

func writeSnapshotTable(w io.Writer, snap model.Snapshot, top int) error {
	rep := buildReport(snap, top)

	// Render into a buffer and hand the caller one write. A consumer that stops
	// reading early must not decide how much of the report gets built.
	buf := &errBuffer{}
	if err := renderSnapshotTable(buf, rep, top); err != nil {
		return err
	}
	return buf.flushTo(w)
}

func renderSnapshotTable(w io.Writer, rep snapshotReport, top int) error {
	// Every write is checked. A renderer that ignores write errors prints a
	// truncated report and exits 0 - the caller then diffs a partial table
	// against a baseline and draws the wrong conclusion. Writing to a closed
	// pipe is the common way this happens (`fdscope snapshot 1 | head`).
	if _, err := fmt.Fprintf(w, "pid %d  total %d open  %s\n", rep.PID, rep.Total, rep.Headroom); err != nil {
		return err
	}
	if !rep.Complete {
		// Never let a partial read look like a real total: a caller comparing
		// this number against a baseline would see a phantom drop.
		if _, err := fmt.Fprintf(w, "warning: %d descriptor entries were unreadable; the total is a lower bound\n", rep.Unreadable); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "observed %s\n\n", rep.Taken); err != nil {
		return err
	}

	kinds := make([]string, 0, len(rep.ByKind))
	for k := range rep.ByKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if _, err := fmt.Fprintf(w, "  %-12s %d\n", k, rep.ByKind[k]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "COUNT\tKIND\tRESOURCE"); err != nil {
		return err
	}
	for _, row := range rep.Groups {
		label := row.Fingerprint
		if row.Deleted {
			// Deleted descriptors hold disk that `du` will never show, so they
			// get an explicit marker rather than relying on the prefix alone.
			label += "  [deleted, space not freed]"
		}
		if _, err := fmt.Fprintf(tw, "%d\t%s\t%s\n", row.Count, row.Kind, label); err != nil {
			return err
		}
	}

	if top > 0 && len(rep.Groups) == top {
		if _, err := fmt.Fprintf(tw, "\n(limited to top %d groups)\n", top); err != nil {
			return err
		}
	}
	// Flush is where buffered write errors actually surface, so it must be the
	// last thing checked.
	return tw.Flush()
}

// splitFlags separates flag arguments from positional ones so that a pid may
// appear before, between or after flags.
//
// The flag package stops at the first non-flag argument, which silently ignores
// every flag that follows it. Rather than documenting a surprising restriction,
// fdscope reorders the arguments so the intuitive form "snapshot <pid> --json"
// behaves identically to "snapshot --json <pid>".
//
// A leading "--" terminates flag parsing for the remainder, matching the
// convention of the standard library.
func splitFlags(args []string, fs *flag.FlagSet) (flagArgs, positionals []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			return flagArgs, positionals
		}
		if len(arg) < 2 || arg[0] != '-' {
			positionals = append(positionals, arg)
			continue
		}

		flagArgs = append(flagArgs, arg)

		// A flag declared as taking a value consumes the next argument when it
		// was not written in --name=value form.
		if indexByte(arg, '=') >= 0 {
			continue
		}
		name := arg
		for len(name) > 0 && name[0] == '-' {
			name = name[1:]
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, isBool := f.Value.(interface{ IsBoolFlag() bool }); isBool && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return flagArgs, positionals
}

// indexByte avoids importing strings just for one lookup in this hot path.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
