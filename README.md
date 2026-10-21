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
fdscope snapshot <pid>              # grouped table
fdscope snapshot <pid> --json       # machine-readable
fdscope snapshot <pid> --top 10     # largest groups only
fdscope snapshot <pid> --keep-dir=false   # collapse directories (sharded stores)
```

Exit codes are part of the contract because CI branches on them:

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | usage or runtime error |
| 2 | an audit found a leak |

## As a library

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
  fdscope reports what it can prove and marks the rest as correlation.
- **Partial snapshots are labelled.** A descriptor that cannot be resolved
  increments `Unreadable`; the total is then reported as a lower bound rather
  than a fact.

## Documentation

| Document | Read it when |
|----------|--------------|
| [docs/design.md](docs/design.md) | you want the reasoning behind fingerprints and the limits of `/proc` |
| [docs/proc.md](docs/proc.md) | you need to know exactly which `/proc` fields are used and what they mean |
| [docs/roadmap.md](docs/roadmap.md) | you want to know what is deliberately not built yet |

## Status

Early. `snapshot` works today; time-series leak detection and attribution are
in progress. See the roadmap for the exact boundary — this file does not claim
features that do not exist.
