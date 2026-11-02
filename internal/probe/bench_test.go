package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/atop0914/fdscope/internal/model"
)

// benchTargets are the four shapes a real fd directory mixes, cycled through the
// synthetic tree so that the normaliser is not handed one easy path a thousand
// times. Rotation is included on purpose: it is the only rule that runs a regular
// expression, so leaving it out would measure a snapshot of a process that holds
// no logs - the one kind of process this tool is not for.
var benchTargets = []string{
	"/var/log/worker/app.log",
	"/tmp/scratch-0000 (deleted)",
	"socket:[987654]",
	"anon_inode:[eventpoll]",
}

// buildFakeProc writes a /proc/<pid> tree with n descriptors under root.
//
// The tree is built rather than read from the live /proc because the cost being
// measured is the parse - readdir, readlink, fdinfo, limits, counters - and a real
// process would hand each run a different mix. The files are the real ones the
// parser reads, in the real formats, so a change to any of those formats shows up
// as a failed premise rather than as a suspiciously fast number.
func buildFakeProc(tb testing.TB, root string, pid, n int) {
	tb.Helper()
	pidDir := filepath.Join(root, itoa(pid))
	fdDir := filepath.Join(pidDir, "fd")
	infoDir := filepath.Join(pidDir, "fdinfo")
	for _, dir := range []string{fdDir, infoDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			tb.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	for i := 0; i < n; i++ {
		name := itoa(i)
		target := benchTargets[i%len(benchTargets)]
		if err := os.Symlink(target, filepath.Join(fdDir, name)); err != nil {
			tb.Fatalf("symlink %s: %v", name, err)
		}
		info := fmt.Sprintf("pos:\t%d\nflags:\t0100002\nmnt_id:\t25\nino:\t%d\n", i*4096, i+1)
		if err := os.WriteFile(filepath.Join(infoDir, name), []byte(info), 0o644); err != nil {
			tb.Fatalf("fdinfo %s: %v", name, err)
		}
	}

	// The live-state files Snapshot reads before and after the walk. Their
	// contents are the kernel's formats, including the start time in field 22
	// that distinguishes this process instance from the next one to get the pid.
	files := map[string]string{
		"stat":   fmt.Sprintf("%d (worker) S 1 %d %d 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 0 0", pid, pid, pid),
		"status": "Name:\tworker\nState:\tS (sleeping)\nThreads:\t8\nVmRSS:\t   20480 kB\n",
		"limits": "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 1048576              files\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(pidDir, name), []byte(content), 0o644); err != nil {
			tb.Fatalf("write %s: %v", name, err)
		}
	}
}

// BenchmarkSnapshot measures one full sample of one process, which is the unit of
// cost in `watch`: the sampler pays it once per interval, and everything the
// report says is derived from a sequence of them.
//
// Two sizes, because the cost is expected to be linear in the descriptor count and
// a superlinear result would mean the sort or the preallocation had regressed -
// a 10000-descriptor process is ordinary on a busy server, and sampling it must
// stay well inside the sampling interval.
func BenchmarkSnapshot(b *testing.B) {
	const pid = 4242

	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("%d-descriptors", n), func(b *testing.B) {
			root := b.TempDir()
			buildFakeProc(b, root, pid, n)
			p := NewProbe()
			p.ProcRoot = root

			// Premise, in three parts: every entry was parsed, nothing was
			// unreadable, and the normaliser actually ran over the mix. Without
			// the third, a tree of uniform targets would still produce the right
			// count while measuring a fraction of the work.
			snap, err := p.Snapshot(pid)
			if err != nil {
				b.Fatalf("premise: Snapshot: %v", err)
			}
			if snap.Len() != n {
				b.Fatalf("premise: parsed %d descriptors, wrote %d", snap.Len(), n)
			}
			if !snap.Complete() {
				b.Fatalf("premise: %d descriptors were unreadable", snap.Unreadable)
			}
			kinds := make(map[model.FDKind]int)
			for _, d := range snap.Descriptors {
				kinds[d.Kind]++
			}
			if kinds[model.KindSocket] == 0 || kinds[model.KindDeleted] == 0 || kinds[model.KindAnonInode] == 0 {
				b.Fatalf("premise: the tree did not exercise every kind: %v", kinds)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.Snapshot(pid); err != nil {
					b.Fatalf("Snapshot: %v", err)
				}
			}
		})
	}
}
