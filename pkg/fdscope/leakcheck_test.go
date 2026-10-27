package fdscope

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a TestingT that remembers what was reported, so the assertion can
// be asserted on. The tests below need both directions - the leak must be caught
// and the clean case must not be - and a test cannot express "this call must
// fail" through the real *testing.T.
type recorder struct {
	msgs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

func (r *recorder) report() string { return strings.Join(r.msgs, "\n") }

// TestLeakCheckCatchesFilesItDidNotClose is the positive case: descriptors that
// are really opened and really left open must be reported, and the report must
// name the resource rather than just a count.
func TestLeakCheckCatchesFilesItDidNotClose(t *testing.T) {
	var held []*os.File
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()

	rec := &recorder{}
	LeakCheck(rec, func() {
		for i := 0; i < 5; i++ {
			f, err := os.Open("/dev/null")
			if err != nil {
				t.Fatalf("opening /dev/null: %v", err)
			}
			held = append(held, f)
		}
	})

	if len(rec.msgs) == 0 {
		t.Fatalf("opened 5 descriptors and kept them: nothing was reported (held %d)", len(held))
	}
	if !strings.Contains(rec.report(), "/dev/null") {
		t.Fatalf("the report does not name the resource that stayed open:\n%s", rec.report())
	}
	if !strings.Contains(rec.report(), "5") {
		t.Fatalf("the report does not give the number of descriptors:\n%s", rec.report())
	}
}

// TestLeakCheckClearsCodeThatReleasedEverything is the reverse assertion, and the
// one that matters for adoption: code that opens and closes must be silent. A
// checker that cries wolf on correct code is deleted from the suite within a
// week, and rightly so.
func TestLeakCheckClearsCodeThatReleasedEverything(t *testing.T) {
	rec := &recorder{}
	LeakCheck(rec, func() {
		for i := 0; i < 5; i++ {
			f, err := os.Open("/dev/null")
			if err != nil {
				t.Fatalf("opening /dev/null: %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("closing /dev/null: %v", err)
			}
		}
	})

	if len(rec.msgs) > 0 {
		t.Fatalf("closing every descriptor was reported as a leak:\n%s", rec.report())
	}
}

// TestLeakCheckWaitsForALazyRelease covers the settle window. "Closed" is not
// always synchronous - a goroutine closes on its way out, a pooled connection is
// reaped a moment later - and convicting on the first look would flag all of it.
func TestLeakCheckWaitsForALazyRelease(t *testing.T) {
	var wg sync.WaitGroup
	rec := &recorder{}

	LeakCheck(rec, func() {
		f, err := os.Open("/dev/null")
		if err != nil {
			t.Fatalf("opening /dev/null: %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Millisecond)
			_ = f.Close()
		}()
	}, WithSettle(80*time.Millisecond))
	wg.Wait()

	if len(rec.msgs) > 0 {
		t.Fatalf("a descriptor released 5ms after the call returned was reported as a leak:\n%s", rec.report())
	}
}

// TestLeakCheckHonoursIgnoredFingerprints covers the escape hatch. The test
// harness opens descriptors the code under test is not responsible for, and the
// honest fix is to name them - not to loosen the check for everything.
func TestLeakCheckHonoursIgnoredFingerprints(t *testing.T) {
	var held []*os.File
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()

	openThree := func() {
		for i := 0; i < 3; i++ {
			f, err := os.Open("/dev/null")
			if err != nil {
				t.Fatalf("opening /dev/null: %v", err)
			}
			held = append(held, f)
		}
	}

	// The same descriptors without the ignore list must be reported, or the
	// silence below would only prove that nothing was being compared.
	withoutIgnore := &recorder{}
	LeakCheck(withoutIgnore, openThree)
	if len(withoutIgnore.msgs) == 0 {
		t.Fatal("three descriptors left open were not reported at all: the ignore test below would be vacuous")
	}

	withIgnore := &recorder{}
	LeakCheck(withIgnore, openThree, WithIgnoredFingerprints("/dev/"))
	if len(withIgnore.msgs) > 0 {
		t.Fatalf("an ignored background resource was reported anyway:\n%s", withIgnore.report())
	}
}

// TestLeakCheckFailsInsteadOfPassingWhenItCannotMeasure covers the platform rule.
//
// Two things are asserted, and the second is easy to get wrong: the check must
// report a failure, and the code under test must still have run. A checker that
// quietly skipped the body would produce a green test that verified nothing.
func TestLeakCheckFailsInsteadOfPassingWhenItCannotMeasure(t *testing.T) {
	restore := supported
	supported = func() bool { return false }
	defer func() { supported = restore }()

	ran := false
	rec := &recorder{}
	LeakCheck(rec, func() { ran = true })

	if !ran {
		t.Fatal("the checked function did not run on an unsupported platform: a skipped body is a test " +
			"that verifies nothing")
	}
	if len(rec.msgs) == 0 {
		t.Fatal("an unsupported platform produced no failure: a green result would claim a measurement " +
			"that never happened")
	}
	if !strings.Contains(rec.report(), "only supports Linux") {
		t.Fatalf("the failure does not explain why nothing was measured:\n%s", rec.report())
	}
}
