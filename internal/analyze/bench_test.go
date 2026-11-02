package analyze

import (
	"fmt"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/timeline"
)

const (
	// benchSamples and benchPeriod describe a window that is long enough to be
	// judged and short enough to keep the benchmark about the verdict rather than
	// about memory: 40 samples over four seconds.
	benchSamples = 40
	benchPeriod  = 100 * time.Millisecond
)

// leakSeries builds n series that all leak, one fingerprint each.
//
// The shape matters more than the count. A steady climb of one descriptor per
// sample is the shape the five criteria are hardest on - it has to clear the
// absolute floor, the ratio floor, the rate floor, monotonicity and continuity -
// so the benchmark measures the full verdict rather than an early return. A flat
// or falling series would exit after two comparisons and the number would be a
// measurement of the guard clauses.
func leakSeries(n int) []timeline.Series {
	out := make([]timeline.Series, n)
	for k := range out {
		counts := make([]int, benchSamples)
		for i := range counts {
			counts[i] = 20 + i
		}
		out[k] = timeline.Series{
			Fingerprint: fmt.Sprintf("file:/var/log/worker-%06d.log", k),
			Counts:      counts,
		}
	}
	return out
}

// BenchmarkJudgeSeries measures the verdict as the number of fingerprints grows.
//
// This is the number that decides whether the tool is usable on a loaded process:
// `watch --judge` runs one verdict per fingerprint per window, and a process with
// ten thousand descriptors is ordinary. The scaling is reported instead of a single
// figure because the interesting question is whether the cost per verdict stays
// flat - the work per series is independent of how many there are, so a rising
// per-verdict cost would mean shared state had crept in.
func BenchmarkJudgeSeries(b *testing.B) {
	opts := DefaultLeakOptions()

	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("%d-fingerprints", n), func(b *testing.B) {
			series := leakSeries(n)

			// Premise: every series must actually be convicted, or the benchmark
			// is timing the rejection path. Asserted on the first and the last so
			// that a builder bug at either end of the range is caught.
			for _, idx := range []int{0, n - 1} {
				v, err := JudgeSeries(series[idx], benchPeriod, opts)
				if err != nil {
					b.Fatalf("premise: JudgeSeries(%d): %v", idx, err)
				}
				if !v.Leak {
					b.Fatalf("premise: series %d was not judged a leak: %s", idx, v.Reason)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, s := range series {
					if _, err := JudgeSeries(s, benchPeriod, opts); err != nil {
						b.Fatalf("JudgeSeries: %v", err)
					}
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/verdict")
		})
	}
}
