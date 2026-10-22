package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/atop0914/fdscope/internal/diff"
	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/probe"
)

func runDiff(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	interval := fs.Duration("interval", time.Second, "delay between the two samples")
	count := fs.Int("count", 2, "how many samples to take (at least 2)")
	keepDir := fs.Bool("keep-dir", true, "keep directory components in fingerprints")
	stripRotation := fs.Bool("strip-rotation", true, "merge rotated log files into one fingerprint")

	args, positionals := splitFlags(args, fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	positionals = append(positionals, fs.Args()...)
	if len(positionals) != 1 {
		return fmt.Errorf("diff requires exactly one pid, got %d", len(positionals))
	}
	pid, err := strconv.Atoi(positionals[0])
	if err != nil {
		return fmt.Errorf("invalid pid %q: %w", positionals[0], err)
	}
	// A single sample has nothing to compare against, and reporting an empty
	// diff for it would read as "nothing changed" - a confident and wrong answer.
	if *count < 2 {
		return fmt.Errorf("--count must be at least 2 for a diff, got %d", *count)
	}
	if *interval < 0 {
		return errors.New("--interval must not be negative")
	}

	p := probe.NewProbe()
	if home, homeErr := os.UserHomeDir(); homeErr == nil {
		p.Normalizer.HomeDir = home
	}
	p.Normalizer.KeepDir = *keepDir
	p.Normalizer.StripRotation = *stripRotation

	pair, err := p.SnapshotsOf(pid, *count, *interval)
	if err != nil {
		return err
	}

	d, err := diff.Compare(pair.Before, pair.After, pair.BeforeStart, pair.AfterStart)
	if err != nil {
		return explainDiffError(err, pid)
	}

	if *asJSON {
		return writeDiffJSON(stdout, d, buildDeletedReport(pair.After))
	}
	return writeDiffTable(stdout, d, buildDeletedReport(pair.After))
}

// explainDiffError turns the diff package's sentinels into messages that name
// what actually happened. "process restarted" and "snapshot incomplete" are
// both cases where returning an empty diff would look like good news.
func explainDiffError(err error, pid int) error {
	switch {
	case errors.Is(err, diff.ErrProcessRestarted):
		return fmt.Errorf("process %d exited or was replaced between the two samples; "+
			"no diff can be computed across two different processes", pid)
	case errors.Is(err, diff.ErrIncompleteSnapshot):
		return fmt.Errorf("%w for pid %d; a descriptor that cannot be read is "+
			"indistinguishable from one that was closed, so no diff is reported", err, pid)
	default:
		return err
	}
}

// deletedReport is the deleted-file section of a diff report.
//
// usable is false when the snapshot was partial: a deleted file whose
// descriptors could not be read would silently drop out of the list, and
// "we could not check" must never be rendered as "there is nothing".
type deletedReport struct {
	Files  []diff.DeletedFile `json:"files"`
	Usable bool               `json:"usable"`
	Reason string             `json:"reason,omitempty"`
}

func buildDeletedReport(s model.Snapshot) deletedReport {
	if !s.Complete() {
		return deletedReport{
			Files:  []diff.DeletedFile{},
			Usable: false,
			Reason: fmt.Sprintf("%d descriptor entries were unreadable", s.Unreadable),
		}
	}
	return deletedReport{Files: diff.DeletedFiles(s), Usable: true}
}

// diffReport is the JSON shape of a diff. It is a dedicated type so the wire
// format does not follow internal refactors.
type diffReport struct {
	PID          int            `json:"pid"`
	Before       string         `json:"before"`
	After        string         `json:"after"`
	BeforeTotal  int            `json:"before_total"`
	AfterTotal   int            `json:"after_total"`
	NetChange    int            `json:"net_change"`
	Headroom     model.Headroom `json:"headroom"`
	Changes      []diff.Change  `json:"changes"`
	Changed      []diff.Change  `json:"changed"`
	Added        []diff.Change  `json:"added"`
	Removed      []diff.Change  `json:"removed"`
	DeletedFiles deletedReport  `json:"deleted_files"`
	Notes        []string       `json:"notes,omitempty"`
}

func buildDiffReport(d diff.Diff, deleted deletedReport) diffReport {
	changes := d.Changes
	if changes == nil {
		changes = []diff.Change{}
	}
	added, removed := d.Added(), d.Removed()
	if added == nil {
		added = []diff.Change{}
	}
	if removed == nil {
		removed = []diff.Change{}
	}
	var notes []string
	if d.NetDescriptorChange() == 0 && !d.Unchanged() {
		// The totals agree while the resources moved. Say so explicitly:
		// anyone eyeballing "total unchanged" would otherwise stop here.
		notes = append(notes, "descriptor total is unchanged but resources moved (descriptor numbers were reused)")
	}
	if d.BeforeLimit != d.AfterLimit {
		notes = append(notes, fmt.Sprintf("open-file limit changed from %d to %d while sampling", d.BeforeLimit, d.AfterLimit))
	}
	return diffReport{
		PID:         d.PID,
		Before:      time.Unix(0, d.BeforeTaken).Format(time.RFC3339Nano),
		After:       time.Unix(0, d.AfterTaken).Format(time.RFC3339Nano),
		BeforeTotal: d.BeforeTotal,
		AfterTotal:  d.AfterTotal,
		NetChange:   d.NetDescriptorChange(),
		Headroom:    model.Headroom{PID: d.PID, Used: d.AfterTotal, Limit: d.AfterLimit},
		Changes:     changes,
		// Changed mirrors Changes; it exists because "changes" is easy to
		// confuse with "changed resources only" when reading a report, and a
		// field that names the direction explicitly is worth the duplication.
		Changed:      changes,
		Added:        added,
		Removed:      removed,
		DeletedFiles: deleted,
		Notes:        notes,
	}
}

func writeDiffJSON(w io.Writer, d diff.Diff, deleted deletedReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(buildDiffReport(d, deleted))
}

func writeDiffTable(w io.Writer, d diff.Diff, deleted deletedReport) error {
	rep := buildDiffReport(d, deleted)

	// The whole report is rendered into a buffer and handed to the caller in
	// one write. Writing straight to the caller means a consumer that stops
	// reading (a closed pipe, `| head`) determines how much of the report is
	// built, so a late section can end up missing for reasons that have
	// nothing to do with the process being audited.
	buf := &errBuffer{}
	if err := renderDiffTable(buf, rep); err != nil {
		return err
	}
	return buf.flushTo(w)
}

func renderDiffTable(w io.Writer, rep diffReport) error {
	span := durationBetween(rep.Before, rep.After)

	// Every write is checked: a renderer that ignores write errors prints a
	// truncated report and exits 0, which tells CI the audit completed.
	if _, err := fmt.Fprintf(w, "pid %d  %d -> %d open (%+d)  %s\n",
		rep.PID, rep.BeforeTotal, rep.AfterTotal, rep.NetChange, rep.Headroom); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "sampled %s .. %s (%s)\n", rep.Before, rep.After, span); err != nil {
		return err
	}
	for _, note := range rep.Notes {
		if _, err := fmt.Fprintf(w, "note: %s\n", note); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if len(rep.Changes) == 0 {
		// "no change" is a result, not an absence of output: a caller reading
		// an empty report cannot tell it apart from a failed run.
		if _, err := fmt.Fprintln(w, "no fingerprint changed count between the two samples"); err != nil {
			return err
		}
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "DELTA\tBEFORE\tAFTER\tKIND\tRESOURCE"); err != nil {
			return err
		}
		for _, c := range rep.Changes {
			label := c.Fingerprint
			if c.Deleted && c.After > 0 {
				label += "  [deleted, space not freed]"
			}
			if _, err := fmt.Fprintf(tw, "%+d\t%d\t%d\t%s\t%s\n", c.Delta, c.Before, c.After, c.Kind, label); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	return renderDeletedFiles(w, rep.DeletedFiles)
}

func renderDeletedFiles(w io.Writer, rep deletedReport) error {
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if !rep.Usable {
		// Never report an empty list when the check could not run: "0 deleted
		// files" and "we could not look" lead to opposite conclusions.
		_, err := fmt.Fprintf(w, "deleted files: unknown (%s)\n", rep.Reason)
		return err
	}
	if len(rep.Files) == 0 {
		_, err := fmt.Fprintln(w, "deleted files: none open")
		return err
	}

	// The size caveat is printed every time, not just in the docs. This list
	// is routinely read as "this is how much disk is lost", which it is not:
	// the files have no directory entry, so their size cannot be read here.
	if _, err := fmt.Fprintln(w, "deleted files still open (paths are gone from the filesystem; sizes are not available):"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "FDS\tWRITABLE\tPATH"); err != nil {
		return err
	}
	for _, f := range rep.Files {
		marker := ""
		if !f.HoldsDiskSpace() {
			// A read-only held deleted file pins an inode, not its blocks.
			marker = "  [read-only: blocks likely already freed]"
		}
		if _, err := fmt.Fprintf(tw, "%d\t%d\t%s%s\n", f.OpenCount, f.WritableOpenCount, f.Path, marker); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// durationBetween renders the sampling span from the RFC3339 timestamps already
// in the report, so the table and the JSON can never disagree about the span.
func durationBetween(before, after string) string {
	b, errB := time.Parse(time.RFC3339Nano, before)
	a, errA := time.Parse(time.RFC3339Nano, after)
	if errB != nil || errA != nil {
		return "unknown span"
	}
	return a.Sub(b).Round(time.Millisecond).String()
}

// errBuffer accumulates a rendered report and remembers the first write error.
//
// It exists so the caller sees a single write, and so a render failure is
// reported even when the underlying writer would have accepted the bytes.
type errBuffer struct {
	buf []byte
	err error
}

func (b *errBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// flushTo performs the single write to the real destination.
func (b *errBuffer) flushTo(w io.Writer) error {
	if b.err != nil {
		return b.err
	}
	_, err := w.Write(b.buf)
	return err
}
