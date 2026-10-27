//go:build !linux

package fdscope

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// On a platform without /proc every entry point must decline, and the assertion
// wrapper must fail rather than pass.
//
// This file only compiles off Linux, which is also the only place the real gate
// returns false. The identical rules are exercised on Linux in check_test.go with
// the gate replaced, so they do not depend on someone running the suite on a Mac -
// but this file is what proves the real gate, rather than a stubbed one, is wired
// to these entry points.

func TestPlatformWithoutProcIsRefusedEverywhere(t *testing.T) {
	if IsSupported() {
		t.Fatal("IsSupported reported true on a platform without /proc")
	}

	if _, err := CheckPID(os.Getpid(), DefaultCheckOptions()); !errors.Is(err, ErrNotLinux) {
		t.Fatalf("CheckPID returned %v, want ErrNotLinux", err)
	}

	ran := false
	rec := &recorder{}
	LeakCheck(rec, func() { ran = true })
	if !ran {
		t.Fatal("the checked function did not run: a skipped body is a test that verifies nothing")
	}
	if len(rec.msgs) == 0 {
		t.Fatal("LeakCheck passed on a platform where it could not measure anything")
	}
	if !strings.Contains(rec.report(), "only supports Linux") {
		t.Fatalf("the failure does not explain why nothing was measured:\n%s", rec.report())
	}
}
