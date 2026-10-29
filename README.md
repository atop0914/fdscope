# fdscope

Audit file descriptor usage of a Linux process — and find out **which resource**
is accumulating, not just how many descriptors exist.

```console
$ fdscope snapshot 1 --top 8
pid 1  total 168 open  168/1048576 open (0.0%), 1048408 remaining
observed 2026-10-22T02:47:25+08:00

  anon_inode   100
  device       6
  file         8
  pipe         1
  socket       53

COUNT  KIND        RESOURCE
74     anon_inode  anon_inode:pidfd
53     socket      socket
15     anon_inode  anon_inode:bpf-prog
5      anon_inode  anon_inode:inotify
3      device      /dev/null
```

## The problem

`too many open files` is one of the most common ways a long-running Go service
falls over. Go does not reclaim descriptors on GC — an `os.File`, `net.Conn` or
`os.Pipe` stays open until something calls `Close`. When the limit is reached,
the symptoms point everywhere except the cause:

- the HTTP server cannot accept connections
- writing a log file fails
- the database pool cannot connect
- **the disk fills up**, because a deleted file still held open never releases its blocks

The tools at hand report a number and stop there:

| Tool | Answers | Does **not** answer |
|------|---------|---------------------|
| `lsof -p` | what is open now | which one is *new*; who opened it |
| `/proc/<pid>/fd` | a count | growth rate; whether it is a leak |
| `pprof` goroutine | which goroutines are stuck | which descriptors they hold |
| `pprof` heap | memory | **descriptors are not in the heap** |
| [`uber-go/goleak`](https://github.com/uber-go/goleak) | goroutine leaks | anything about descriptors |

fdscope's contribution is **fingerprints**: grouping descriptors by a stable,
normalised identity so that a leak appears as *one growing row* instead of
thousands of unrelated ones.

## Why fingerprints

Raw `/proc` link targets cannot be compared:

```
socket:[12345]              ← the inode changes on every reconnect
/var/log/app.log.2026-10-22 ← every rotation looks like a new file
/tmp/scratch (deleted)      ← a live file and a deleted one look similar
```

fdscope normalises these into fingerprints that stay stable:

| Raw target | Fingerprint |
|-----------|-------------|
| `socket:[12345]` | `socket` |
| `pipe:[777]` | `pipe` |
| `/var/log/app.log.2026-10-22` | `file:/var/log/app.log` |
| `/tmp/scratch (deleted)` | `deleted:/tmp/scratch` |
| `anon_inode:[eventpoll]` | `anon_inode:eventpoll` |

The rules are deliberately conservative: they merge what is virtually always
one resource, and keep apart what is genuinely different. A live and a deleted
file of the same name stay separate, because "this file is gone but its space
is still held" is an action item.

## Install

```console
go install github.com/atop0914/fdscope/cmd/fdscope@latest
```

Or build from source:

```console
git clone https://github.com/atop0914/fdscope
cd fdscope && make build     # -> bin/fdscope
```

## Usage

```console
fdscope snapshot <pid>              # grouped table: what is open now
fdscope snapshot <pid> --json       # machine-readable
fdscope snapshot <pid> --top 10     # largest groups only
fdscope snapshot <pid> --keep-dir=false   # collapse directories (sharded stores)

fdscope diff <pid>                  # what changed across two samples
fdscope diff <pid> --interval 5s --count 3
fdscope diff <pid> --json           # for CI

fdscope watch <pid>                 # the shape of each series over time
fdscope watch <pid> --interval 500ms --samples 60
fdscope watch <pid> --samples 200 --keep 60   # bounded retention
fdscope watch <pid> --json          # for CI
fdscope watch <pid> --judge         # decide whether it is a leak; exit 2 if so
fdscope watch <pid> --judge --json --series   # + the totals the verdict used

fdscope check <pid>                 # one window, one verdict: the CI gate
fdscope check <pid> --json          # + the series and the thresholds applied
fdscope check <pid> --min-growth 50 --min-rate 1   # for a large process
fdscope check <pid> --attr-rules rules.json        # + your own resource classes
```

`watch` answers the question neither of the others can: **is it rising and
staying, or rising and coming back?** A batch job and a leak produce the same two
numbers when sampled at the peak and at the end; only the shape between them
tells them apart.

```console
$ fdscope watch 4242 --interval 500ms --samples 12
pid 4242  12 samples over 5.511s  total rising 4 -> 8
total descriptors: 4 -> 8 (min 4, max 8)

TREND  FIRST  LAST  MIN  MAX  REBOUND     KIND     RESOURCE
flat   2      2     2    2    -           pipe     pipe
flat   0      1     0    1    -           file     file:~/.cache/app/wal-1.log
flat   0      1     0    1    -           file     file:~/.cache/app/wal-2.log

no resource rose and then fell back within the window
```

The same run against a batch job ends differently:

```console
total: first=3 last=3 min=3 max=13 peak_at=3 trend=flat rebound=True (13->3)

10 resource(s) rose and then fell back (self-healing, not a leak):
PEAK  LOW  DROP  RESOURCE
13    3    10    (total)
```

### `--judge`: from shape to verdict

`watch` on its own will not say "leak", because a rising series is also a pool
warming up, a batch job in flight and a directory walk. `--judge` opts into the
conclusion, and the conclusion has to carry its numbers:

```console
$ fdscope watch 4242 --judge --samples 30
verdict: LEAK
window: 30 samples over 3569ms

process total: LEAK (confidence medium)
  reason: grew 51 descriptors (283%) to 69 over 3.4s and did not fall back; 4027 descriptors below the limit of 4096: crossed in about 2.5m at 14.8/s
  WINDOW     30 samples / 3569ms  (warmup excluded: 1)
  BASELINE   18                   rise measured from here
  GROWTH     51                   (floor 10, reached 510% of it)
  RATE       14.799/s             (floor 0.050/s)
  COVERAGE   17/28 gaps grew      still climbing at window end: true
  MONOTONIC  true                 peak is at the end of the window
  HEADROOM   4027 left of 4096    EMFILE in about 2.5m at 14.8/s
  PROJECTION rate from 29 samples over 3.4s at 14.799/s  confidence medium
```

The headroom line is the answer to "how urgent is this", and it has three shapes
because the kernel has three answers. A finite limit gets a countdown; `unlimited`
says EMFILE is unreachable; an unreadable limit says exactly that and claims
nothing. A countdown is only printed when something is actually rising — a flat
window has no rate, and a rate invented out of no growth would be a prediction
dressed as a measurement.

Five criteria must all hold: monotonicity, an absolute growth floor, a rate
floor, a warm-up baseline, and coverage of the window. Each excludes a specific
false positive, and each is printed so a reader can disagree with the tool using
the tool's own numbers.

Exit codes: `0` no leak, `2` leak, `1` the run itself failed. `2` is what CI
branches on. `--series` adds the per-sample totals, which is what makes a
verdict reproducible offline rather than an opinion about a run nobody can
re-examine.

### Attribution: which *class* of resource is growing

A verdict names fingerprints, and twenty fingerprints is not an answer to "what
is leaking". Every leaked series is labelled with the class its fingerprint
already proves — and the leak is summed up by class, with the share of the growth
each one accounts for:

```console
$ fdscope check 4242 --json | jq '.attribution'   # rows trimmed to fit here
[
  { "category": "log file", "rule": "log-file", "matched": true,
    "confidence": "high", "growth": 38, "fingerprints": 1, "coverage": 0.5 },
  { "category": "socket", "rule": "socket", "matched": true,
    "confidence": "high", "growth": 38, "fingerprints": 1, "coverage": 0.5 }
]
```

The same run in the table prints one line per leaked series
(`attribution: log file [log-file, L1 high]` plus the evidence sentence) and
closes with the breakdown above.

This is **L1 attribution**: it restates the fingerprint and stops there. `/proc`
does not record who opened a descriptor, so no L1 sentence may say "opened by",
and a class that no rule covers is reported as `no rule matched` with its share
of the growth rather than left blank — an unexplained quarter of a leak is the
part a reader most needs to see.

Configured rules add your own classes on top of the built-in ones, and win over
them:

```console
$ fdscope check 4242 --attr-rules rules.json
```

A rule file is strictly parsed: unknown fields, unknown kinds, a rule with no
predicate, an empty rule list — each is an error naming the line it is on.
Sitting on a typo would turn "I added a rule and nothing changed" into a mystery.
See [docs/attr.md](docs/attr.md) for the built-in rule table, why the specificity
ladder is ordered as it is, and the two rules deliberately not implemented
(directory descriptors and open flags are not in the fingerprint).

Three things it deliberately refuses to do:

- **It does not conclude "leak" unless asked.** A rising series can still be a
  warm-up or a slow batch, so the verdict is opt-in and never volunteered.
- **It does not sample a zombie.** A dead-but-unreaped process keeps its `/proc`
  entry with an *empty* fd directory. Reading that as a sample would report every
  descriptor as released at the moment the process died - the exact inverse of a
  leak. It is an error instead.
- **It never discards collected samples.** If the process dies at sample 40 of
  60, the 40 already taken are printed and then the exit code is non-zero.

`diff` compares **fingerprints, not descriptor numbers**. Numbers are recycled
the moment a descriptor closes, so a close followed by an open usually lands on
the same number and the two samples look identical. That swap is exactly what a
leak hunter needs to see:

```console
$ fdscope diff 4242 --interval 2s
pid 4242  183 -> 188 open (+5)  188/1024 open (18.4%), 836 remaining
sampled 2026-10-22T21:11:23+08:00 .. 2026-10-22T21:11:25+08:00 (2.001s)

DELTA  BEFORE  AFTER  KIND  RESOURCE
+3     2       5      file  file:/var/log/app.log
+2     0       2      file  file:/tmp/scratch.bin

deleted files still open (paths are gone from the filesystem; sizes are not available):
FDS  WRITABLE  PATH
1    1         /tmp/upload.part
```

Two answers it deliberately refuses to give:

- **No size for deleted files.** The path no longer exists, so its size cannot be
  read. Only the count of descriptors is reported.
- **No diff across a restart.** A pid is unique only among live processes; if the
  start time from `/proc/<pid>/stat` changed, the diff is an error rather than a
  comparison of two unrelated processes.

Exit codes are part of the contract because CI branches on them:

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | usage or runtime error — including "could not judge" |
| 2 | an audit found a leak (`check`, `watch --judge`) |

### `check`: one window, one verdict, for a gate

`watch --judge` reaches the same verdict, but it is the wrong shape for CI: the
caller has to parse a table, and it will happily render a conclusion from a window
that was cut short. `check` is the same judgement behind a contract.

```console
$ fdscope check 4242
pid 4242  check  interval 100ms
thresholds: rise >= 5 and >= 10% of baseline, rate >= 0.050/s, high confidence from 5000ms
totals: 7 9 11 13 15 17 19 21

verdict: LEAK
window: 8 samples over 704ms

process total: LEAK (confidence medium)
  reason: grew 12 descriptors (133%) to 21 over 0.6s and did not fall back
  ...

1 resource(s) judged a leak:
file:/tmp/app/queue: LEAK (confidence medium)
  ...
```

| Code | When |
|------|------|
| 0 | judged, no leak |
| 2 | judged, a leak |
| 1 | **not judged at all**: no such process, the process died mid-window, or a window too short to separate a warming pool from a leak |

The third code is the point of the command. A gate that answered "no leak" when it
measured nothing would pass every job whose target happened to break — and it would
do so silently, in the calm direction, which is the direction nobody checks.

Defaults are 25 samples 200ms apart, a five second window; `--min-growth`,
`--min-growth-ratio`, `--min-rate` and `--min-window` override the thresholds for
processes too large or too small for the defaults. `--json` echoes the thresholds
*as applied* and always includes the per-sample totals, so a CI job keeps a
document whose verdict can be re-derived rather than taken on faith.

The same document carries `headroom` (`limit`, `limit_state`, `unlimited`,
`limit_known`, `limit_hard`) and `projection` (`state`, `rate_per_second`,
`rate_samples`, `rate_seconds`, `eta_seconds`, `confidence`, `note`). `eta_seconds`
being absent is meaningful: `state` says whether the limit is `unlimited`, could
not be read, is already crossed, or simply is not rising. An ETA of `0` never
means "now".

```yaml
- name: descriptor leak gate
  run: |
    ./fdscope check "$PID" --json > fdcheck.json
    # exit 2 fails the job (a leak), and so must exit 1 (nothing was measured)
```

## As a library

Reading a snapshot:

```go
import "github.com/atop0914/fdscope/pkg/fdscope"

snap, err := fdscope.NewProbe().Snapshot(os.Getpid())
if err != nil {
    return err
}
for _, row := range snap.SortedFingerprints() {
    fmt.Println(row.Count, row.Fingerprint)
}
```

Asking whether a running process is leaking, without a command line:

```go
res, err := fdscope.CheckPID(pid, fdscope.DefaultCheckOptions()) // 25 samples × 200ms
if err != nil {
    // could not measure - this is *not* "no leak". A missing pid, a process
    // that died mid-window and a window too short to judge all land here.
    return err
}
if res.Leaking() {
    log.Printf("%s", fdscope.Summarize(res.Report))
}
for _, v := range res.Report.Leaks() {
    log.Printf("%s: %s", v.Fingerprint, v.Reason)
}
```

Asserting that a piece of test code released what it opened — goleak's shape:

```go
func TestQueueDrain(t *testing.T) {
    fdscope.LeakCheck(t, func() {
        q := openQueue(t)
        drain(q)
        q.Close()
    })
}
```

Two different questions, on purpose. `CheckPID` watches growth over a window and
answers "is this process leaking" — a claim about time, resting on the shape of a
series. `LeakCheck` compares the descriptor table before and after the call and
answers "did this code leave anything behind" — the operation has finished, so
there is nothing in flight to confuse a leak with, and no window is needed. The
"two points are not enough" rule that rules out diff-based *leak* judgement does
not apply once the work is over.

`LeakCheck` options: `WithSettle` (how long to keep sampling for lazily released
descriptors, default 50ms), `WithTolerance` (how much per-resource growth to
ignore, default 0), `WithIgnoredFingerprints` (name the harness's own descriptors
instead of loosening the check for everything).

On a platform without `/proc`, `LeakCheck` **reports a failure** and `CheckPID`
returns `ErrNotLinux`: a green test would otherwise claim nothing leaked when in
fact nothing was looked at.

See [`examples/snapshot`](examples/snapshot/main.go).

## Design rules

These are decisions, not defaults, and they are the reason the tool can be
trusted:

- **Linux only, and openly so.** Reading `/proc` is the whole mechanism. On
  other platforms every entry point returns `ErrNotLinux`. There is
  intentionally **no fallback**: an empty snapshot is indistinguishable from
  "this process holds no descriptors", so every leak check built on it would
  silently pass. A tool that cannot see must say so.
- **Zero third-party dependencies.** Only the standard library, enforced by a
  CI gate. fdscope must be `go install`-able anywhere.
- **Read-only, unprivileged.** It reads `/proc` and never `ptrace`s. Sampling a
  process must not change the process.
- **No invented attribution.** `/proc` does not record who opened a descriptor.
  fdscope reports what it can prove and marks the rest as correlation: L1 names
  the *class* of a resource (restating the fingerprint), L2 and L3 may only
  report correlation and must say so in the output.
- **Partial snapshots are labelled.** A descriptor that cannot be resolved
  increments `Unreadable`; the total is then reported as a lower bound rather
  than a fact.

## Documentation

| Document | Read it when |
|----------|--------------|
| [docs/design.md](docs/design.md) | you want the reasoning behind fingerprints and the limits of `/proc` |
| [docs/proc.md](docs/proc.md) | you need to know exactly which `/proc` fields are used and what they mean |
| [docs/attr.md](docs/attr.md) | you want the attribution rule table, the specificity ladder, or the two rules deliberately not implemented |
| [docs/roadmap.md](docs/roadmap.md) | you want to know what is deliberately not built yet |

## Status

Day 7 of 12. `snapshot`, `diff`, `watch`, `watch --judge`, `check`, the EMFILE
projection and L1 attribution are working, and the verdict is reachable as a
library (`CheckPID`, `LeakCheck`). L2 (timing correlation) and L3 (test-time
goroutine pairing) are not built yet. See the roadmap for the exact boundary —
this file does not claim features that do not exist.
