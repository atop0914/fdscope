package model

import "testing"

// BenchmarkFingerprint measures the normaliser, which every other layer stands on:
// a snapshot is just a list until the targets are folded into fingerprints, and a
// report is a group-by over the result. So this is the cost of one descriptor.
//
// There is no assertion of a number here, only of the premise: each sub-benchmark
// states the fingerprint and kind it expects, and fails to build the benchmark if
// the rule it is named after is not the rule that ran. A benchmark of the wrong
// code path produces a number that looks like evidence and is not.
func BenchmarkFingerprint(b *testing.B) {
	cases := []struct {
		name   string
		target string
		want   string
		kind   FDKind
	}{
		{"plain path", "/var/log/app.log", "file:/var/log/app.log", KindFile},
		// The rotation rule is the expensive one: it runs a regular expression
		// over the path, and every log-holding process pays it on every sample.
		{"rotated log", "/var/log/app.log.2026-10-22", "file:/var/log/app.log", KindFile},
		{"socket", "socket:[987654]", "socket", KindSocket},
		{"deleted file", "/tmp/scratch (deleted)", "deleted:/tmp/scratch", KindDeleted},
		{"anon inode", "anon_inode:[eventpoll]", "anon_inode:eventpoll", KindAnonInode},
		// Re-normalising a fingerprint is the path report code takes when it
		// re-groups rows, and it is meant to be the cheap one.
		{"already normalised", "file:/var/log/app.log", "file:/var/log/app.log", KindFile},
	}

	n := DefaultNormalizer()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			got, kind := n.Fingerprint(tc.target)
			if got != tc.want || kind != tc.kind {
				b.Fatalf("premise: Fingerprint(%q) = (%q, %q), want (%q, %q)",
					tc.target, got, kind, tc.want, tc.kind)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n.Fingerprint(tc.target)
			}
		})
	}
}
