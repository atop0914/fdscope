package analyze

import (
	"math"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atop0914/fdscope/internal/model"
	"github.com/atop0914/fdscope/internal/timeline"
)

// TestProjectThreeLimitStates is the acceptance test for the first half of Day 6:
// the same series must produce three different answers depending on what the
// kernel said about the limit, and only one of them contains an ETA.
func TestProjectThreeLimitStates(t *testing.T) {
	counts := ramp(100, 40, 20) // 100 -> 140 over 20 samples
	period := 100 * time.Millisecond

	t.Run("finite limit projects", func(t *testing.T) {
		p, err := Project(counts, period, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.State != Projected {
			t.Fatalf("state = %q, want %q", p.State, Projected)
		}
		if p.ETASeconds <= 0 {
			t.Fatalf("ETASeconds = %v, want a positive number", p.ETASeconds)
		}
		// The ETA must follow from the numbers the projection carries, or it is
		// not reproducible from its own report.
		wantETA := float64(p.Remaining) / p.RatePerSecond
		if math.Abs(p.ETASeconds-wantETA) > 1e-6 {
			t.Errorf("ETASeconds = %v, but remaining/rate = %v", p.ETASeconds, wantETA)
		}
		// 40 descriptors over 1.9s is 21.05/s; the limit is 4096 so the ETA is
		// ~187s. The rate must come from the *period*, not from a per-sample
		// step - that unit error is what printed a six-digit second count.
		if diff := math.Abs(p.RatePerSecond - 40.0/1.9); diff > 1e-9 {
			t.Errorf("RatePerSecond = %v, want %v", p.RatePerSecond, 40.0/1.9)
		}
	})

	t.Run("unlimited never projects", func(t *testing.T) {
		p, err := Project(counts, period, model.UnlimitedLimit())
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.State != ProjectionUnlimited {
			t.Fatalf("state = %q, want %q", p.State, ProjectionUnlimited)
		}
		if p.ETASeconds != 0 {
			t.Errorf("ETASeconds = %v for an unlimited limit; there is nothing to count down to", p.ETASeconds)
		}
		if p.Remaining != 0 || p.Limit != 0 {
			t.Errorf("remaining/limit = %d/%d for unlimited, want 0/0", p.Remaining, p.Limit)
		}
		if !strings.Contains(p.Describe(), "unlimited") {
			t.Errorf("Describe() = %q, want the word unlimited", p.Describe())
		}
	})

	t.Run("unknown limit never projects", func(t *testing.T) {
		p, err := Project(counts, period, model.UnknownLimit())
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.State != ProjectionLimitUnknown {
			t.Fatalf("state = %q, want %q", p.State, ProjectionLimitUnknown)
		}
		if p.ETASeconds != 0 {
			t.Errorf("ETASeconds = %v with an unreadable limit", p.ETASeconds)
		}
		// The two "no ETA" states must not read the same: this one must say the
		// limit could not be read, not that it is unlimited.
		if strings.Contains(p.Describe(), "unlimited") {
			t.Errorf("Describe() = %q conflates unreadable with unlimited", p.Describe())
		}
		if !strings.Contains(p.Describe(), "could not be read") {
			t.Errorf("Describe() = %q, want it to name the unreadable limit", p.Describe())
		}
	})
}

// TestProjectRefusesToInventAnETA covers the cases where a number would be worse
// than silence.
func TestProjectRefusesToInventAnETA(t *testing.T) {
	period := 100 * time.Millisecond

	t.Run("flat series", func(t *testing.T) {
		p, err := Project([]int{50, 50, 50, 50, 50}, period, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.State != ProjectionNoGrowth {
			t.Fatalf("state = %q, want %q", p.State, ProjectionNoGrowth)
		}
		if p.ETASeconds != 0 {
			t.Errorf("ETASeconds = %v for a flat series; a non-leak must not be given a countdown", p.ETASeconds)
		}
	})

	t.Run("single sample", func(t *testing.T) {
		p, err := Project([]int{50}, period, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.ETASeconds != 0 {
			t.Errorf("ETASeconds = %v from one sample: there is no interval to fit a rate to", p.ETASeconds)
		}
		if !strings.Contains(p.Note, "single sample") {
			t.Errorf("Note = %q, want it to say only one sample was available", p.Note)
		}
	})

	t.Run("already at the limit", func(t *testing.T) {
		p, err := Project([]int{60, 64, 65, 70}, period, model.KnownLimit(64))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.State != ProjectionAtLimit {
			t.Fatalf("state = %q, want %q", p.State, ProjectionAtLimit)
		}
		if p.Remaining != -6 {
			t.Errorf("Remaining = %d, want -6 (the count is past a lowered limit)", p.Remaining)
		}
		if p.ETASeconds != 0 {
			t.Errorf("ETASeconds = %v; being past the limit is not a future event", p.ETASeconds)
		}
	})

	t.Run("empty series", func(t *testing.T) {
		p, err := Project(nil, period, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.State != ProjectionNoGrowth || p.ETASeconds != 0 {
			t.Errorf("state/eta = %q/%v for an empty series", p.State, p.ETASeconds)
		}
	})
}

// TestProjectNegativePeriodIsRejected: a negative period is a caller bug, and it
// would otherwise produce a negative rate and a negative ETA that reads as "the
// limit was crossed in the past".
func TestProjectNegativePeriodIsRejected(t *testing.T) {
	if _, err := Project([]int{1, 2}, -time.Second, model.KnownLimit(10)); err == nil {
		t.Fatal("a negative sample period was accepted")
	}
}

// TestProjectConfidenceFollowsItsBasis: an ETA fitted to four points is reported,
// but not at high confidence. The basis is part of the claim.
func TestProjectConfidenceFollowsItsBasis(t *testing.T) {
	t.Run("four samples is low", func(t *testing.T) {
		p, err := Project(ramp(10, 4, 4), 100*time.Millisecond, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.Confidence != ConfidenceLow {
			t.Errorf("confidence = %q, want low for 4 samples", p.Confidence)
		}
		if p.ETASeconds == 0 {
			t.Error("a low-confidence projection must still be reported: it is the honest order of magnitude")
		}
	})

	t.Run("short window is medium", func(t *testing.T) {
		p, err := Project(ramp(10, 20, 6), 100*time.Millisecond, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.Confidence != ConfidenceMedium {
			t.Errorf("confidence = %q, want medium for a 0.5s window", p.Confidence)
		}
	})

	t.Run("long window with many samples is high", func(t *testing.T) {
		p, err := Project(ramp(10, 20, 20), 500*time.Millisecond, model.KnownLimit(4096))
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if p.Confidence != ConfidenceHigh {
			t.Errorf("confidence = %q, want high for 20 samples over 9.5s", p.Confidence)
		}
	})
}

// sixDigitSeconds matches a duration printed as five digits or more of seconds -
// the shape of "crossed in about 524278s", which is the bug this round fixes.
var sixDigitSeconds = regexp.MustCompile(`\b\d{5,}s\b`)

// TestHumanETANeverPrintsSixDigitSeconds is a wording test with teeth: the
// number was always arithmetically right, so no value assertion would have
// caught it.
func TestHumanETANeverPrintsSixDigitSeconds(t *testing.T) {
	cases := []struct {
		seconds float64
		want    string
	}{
		{0.4, "1s"},
		{45, "45s"},
		{59.4, "59s"},
		{90, "2m"},
		{3599, "60m"},
		{3600, "1.0h"},
		{36000, "10.0h"},
		{86400, "1.0 days"},
		{524278, "6.1 days"}, // the exact figure the old code printed as 524278s
		{86400 * 29, "29.0 days"},
		{86400 * 90, "over a month"},
		{86400 * 3650, "over a month"},
	}
	for _, tc := range cases {
		got := humanETA(tc.seconds)
		if got != tc.want {
			t.Errorf("humanETA(%v) = %q, want %q", tc.seconds, got, tc.want)
		}
		if sixDigitSeconds.MatchString(got) {
			t.Errorf("humanETA(%v) = %q contains a six-digit second count", tc.seconds, got)
		}
	}
}

// TestLeakReasonIsReadable checks the sentence a user actually sees, on the
// numbers that used to produce the unreadable one.
func TestLeakReasonIsReadable(t *testing.T) {
	// A container-sized limit: 1 MiB, 20 descriptors of growth over 2s. The old
	// code printed "crossed in about 104855s" here.
	tl := seriesOf(t, map[string][]int{"socket": ramp(100, 20, 20)}, 100*time.Millisecond)
	v := judgeOne(t, tl, "socket", LeakOptions{Limit: model.KnownLimit(1048576)})
	if !v.Leak {
		t.Fatalf("the series did not leak: %s", v.Reason)
	}
	if sixDigitSeconds.MatchString(v.Reason) {
		t.Errorf("reason = %q still contains a six-digit second count", v.Reason)
	}
	if !strings.Contains(v.Reason, "days") {
		t.Errorf("reason = %q, want the ETA expressed in days", v.Reason)
	}
	if v.Projection.ETASeconds <= 0 {
		t.Errorf("Projection.ETASeconds = %v, want a positive number", v.Projection.ETASeconds)
	}
}

// TestNoLeakVerdictCarriesNoETA is the reverse assertion: a series that is
// rising but below the growth floor must not be given a countdown, because the
// verdict already declined to call it a leak.
func TestNoLeakVerdictCarriesNoETA(t *testing.T) {
	// 3 descriptors of growth in a 300-descriptor process fails the ratio floor.
	tl := seriesOf(t, map[string][]int{"socket": ramp(300, 3, 20)}, 100*time.Millisecond)
	v := judgeOne(t, tl, "socket", LeakOptions{Limit: model.KnownLimit(4096)})
	if v.Leak {
		t.Fatalf("the series leaked, so this test proves nothing: %s", v.Reason)
	}
	if v.Projection.ETASeconds != 0 {
		t.Errorf("a no-leak verdict carries ETASeconds = %v", v.Projection.ETASeconds)
	}
	if v.Projection.State != ProjectionNoGrowth {
		t.Errorf("projection state = %q, want %q", v.Projection.State, ProjectionNoGrowth)
	}
	// The limit itself is still reported: "not leaking" is not "unlimited".
	if v.Projection.Limit != 4096 {
		t.Errorf("projection limit = %d, want 4096 even without a leak", v.Projection.Limit)
	}
}

// TestUnlimitedLimitIsNeverAnEmergency: with an unlimited limit there is no
// headroom to run out of, so the verdict must not read as urgent even when the
// count is enormous.
func TestUnlimitedLimitIsNeverAnEmergency(t *testing.T) {
	tl := seriesOf(t, map[string][]int{"socket": ramp(100000, 20000, 20)}, 100*time.Millisecond)
	v := judgeOne(t, tl, "socket", LeakOptions{Limit: model.UnlimitedLimit()})
	if !v.Leak {
		t.Fatalf("the series should still be convicted as a leak: %s", v.Reason)
	}
	if v.Projection.State != ProjectionUnlimited {
		t.Fatalf("projection state = %q, want %q", v.Projection.State, ProjectionUnlimited)
	}
	if strings.Contains(v.Reason, "EMFILE is imminent") {
		t.Errorf("reason = %q claims EMFILE with an unlimited limit", v.Reason)
	}
	if v.Evidence.Remaining != 0 || v.Evidence.Limit != 0 {
		t.Errorf("evidence limit/remaining = %d/%d for an unlimited limit, want 0/0",
			v.Evidence.Limit, v.Evidence.Remaining)
	}
}

// TestConstantlyFilledProcessKeepsItsLimitState: the after-the-fact leak path in
// Judge rebuilds the total verdict, and it must not lose the projection while
// doing so.
func TestConstantlyFilledProcessKeepsItsLimitState(t *testing.T) {
	tl := seriesOf(t, map[string][]int{"socket": ramp(500, 0, 10)}, 100*time.Millisecond)
	rep, err := Judge(tl, LeakOptions{Limit: model.KnownLimit(600)})
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if !rep.Total.Leak {
		t.Fatalf("a constant 500 of a 600 limit was not convicted: %s", rep.Total.Reason)
	}
	if rep.Total.Projection.Limit != 600 {
		t.Errorf("projection limit = %d, want 600 to survive the rewrite", rep.Total.Projection.Limit)
	}
	if rep.Total.Projection.ETASeconds != 0 {
		t.Errorf("ETASeconds = %v; the rise predates the window, so there is no rate",
			rep.Total.Projection.ETASeconds)
	}
}

// TestJudgeTakesTheLimitFromTheTimeline proves the wiring: a timeline whose
// samples carry the limit must produce a projection even when the caller passes
// none, because forgetting the option is the default way to lose the headroom.
func TestJudgeTakesTheLimitFromTheTimeline(t *testing.T) {
	tl, err := timeline.New(4242, 20)
	if err != nil {
		t.Fatalf("timeline.New: %v", err)
	}
	base := time.Now().UnixNano()
	for i, c := range ramp(100, 40, 20) {
		if err := tl.Add(timeline.Sample{
			Taken:  base + int64(i)*int64(100*time.Millisecond),
			Total:  c,
			Counts: map[string]int{"socket": c},
			Limit:  model.KnownLimit(2048),
		}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	rep, err := Judge(tl, LeakOptions{})
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if rep.Total.Projection.Limit != 2048 {
		t.Fatalf("projection limit = %d, want 2048 read from the timeline", rep.Total.Projection.Limit)
	}
	if rep.Total.Projection.ETASeconds <= 0 {
		t.Errorf("ETASeconds = %v, want a positive number", rep.Total.Projection.ETASeconds)
	}
	if !strings.Contains(rep.Total.Reason, "below the limit of 2048") {
		t.Errorf("reason = %q, want it to name the limit", rep.Total.Reason)
	}
}
