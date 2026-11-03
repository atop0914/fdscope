# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0.0] - 2026-11-03

First release. Linux only, standard library only, no privileges.

The question this tool answers is **which resource is accumulating, and when did
it start** — not how many descriptors exist right now. The existing tools report
a number and stop; at that point the interesting part has not started.

### Added

- `snapshot <pid>` — the current descriptor set, grouped by normalised
  fingerprint, with `--json`, `--top N`, and `--keep-dir=false` to collapse
  sharded stores that would otherwise be one row per log file.
- `diff <pid>` — what changed across two samples, including descriptors whose
  file was unlinked while still held. That is how a disk fills up while every
  `df` in sight blames nothing.
- `watch <pid>` — the shape of each series over time: rising, falling, flat, and
  whether it rose to a peak and fell back. *Rising and staying* is a leak;
  *rising and coming back* is work being done, and two snapshots cannot tell
  them apart.
- `watch --judge` — the verdict, with the numbers behind it, and an exit code
  for CI (2 on a leak). Opt-in, because a rising series is also a pool warming
  up and a batch job in flight.
- `check <pid>` — one window, one verdict, for a CI gate: exit 0 clean, 2 leak,
  **1 when it could not judge at all** — no such process, the process died
  mid-window, or a window too short to separate a warming pool from a leak. A
  gate that answered "no leak" when it measured nothing would pass every job
  whose target happened to break.
- Descriptor limit and EMFILE projection. The soft limit's three states (finite,
  unlimited, unknown) are kept apart, the headroom is reported, and an ETA at the
  observed rate carries its sample count, window and confidence — or says "far
  from the limit" instead of printing a number in years.
- L1 attribution: fingerprint to resource class through a rule table, extensible
  with your own JSON rules (`--attr-rules`), with a stable specificity ladder.
- L2 correlation: process counters at the moment the growth started. Labelled
  **correlation**, never causation, and the forbidden-word list is enforced by a
  test rather than by good intentions.
- L3 stack pairing: during a test, pair descriptor deltas with goroutine stacks
  and name the frames that are new. Library only — stacks are visible from
  inside the process, so this cannot be a command on someone else's pid without
  ptrace, which this project does not do.
- A library API shaped like `goleak`'s usage: `CheckPID` for a live process,
  `LeakCheck` around a function, `WithStacks()` to add L3.

### Verification

- The verdict was checked against **three real descriptor lifecycle defects**
  from a production project, rewritten as fixtures that reproduce the shape of
  each defect. One of them kills the process mid-window; that case must fail the
  check, and does.
- The documentation is checked the way the code is: every relative link, every
  repository path written in a code span, and every page's entry point from the
  README is resolved by a test — and that checker is itself tested against
  deliberately broken input, because a checker that fails open reports a clean
  tree for every tree.
- Gates run before tagging: `gofmt`, `go vet`, the full suite with **zero
  skips**, the same suite under `-race`, `golangci-lint` at the version CI uses,
  and a five-target cross-compile with a darwin type-check that includes test
  files. The pass/skip/fail counts at release time are recorded in the project
  log; they are deliberately not repeated here, because a count in a changelog
  starts expiring with the next commit.

### Known boundaries

Read these before trusting a verdict. All three are properties of the data
source, not gaps to be filled later.

1. **Linux only.** Every fact comes from `/proc`. On any other platform the
   package reports `IsSupported() == false` and returns an explicit error. There
   is deliberately no "empty snapshot" fallback: an empty snapshot is
   indistinguishable from a process with no descriptors, so every leak check
   built on top of it would pass silently, and that is worse than refusing.
2. **`/proc` does not record who opened a descriptor.** Attribution therefore
   comes in three strengths and each one says which it is: L1 names the resource
   class (provable), L2 relates growth to a time window of counters
   (correlation), L3 pairs stacks with descriptor deltas during a test
   (sampling). Nothing here claims to name the function that leaked.
3. **Sampling, not tracing.** A descriptor opened and closed between two samples
   is never seen, so "no change observed" means only that. Counters the kernel
   does not provide — `syscr`/`syscw` without `CONFIG_TASK_IO_ACCOUNTING` — are
   reported as unknown, never as zero: zero is a fact, and filling it in would
   exclude exactly the activity one is looking for.

### Dependencies

None. `go.mod` declares no requirements and imports nothing outside the standard
library. This is a promise rather than a preference: the tool has to be
installable into any environment with `go install`, and it should not be able to
rot because something it depended on did.
