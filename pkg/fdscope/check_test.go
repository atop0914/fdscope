package fdscope

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests drive CheckPID against this process, which is the only process a
// test can make leak and observe at the same time. The leak is real: descriptors
// are opened with os.Open and never closed until the assertion is over, so the
// series the verdict rests on is a kernel fact rather than a constructed slice.
//
// A hand-built timeline would prove the wiring works and nothing about the claim,
// and the claim is the feature.

// fastCheckOptions is the default check squeezed into a window a test can afford.
//
// The growth floor is lowered with it: the default floor of ten descriptors
// exists so a small process is not convicted by proportion, and a 300ms window
// cannot be driven to ten opens without turning the test into a benchmark. The
// criteria themselves are untouched - what is shortened is the window, not the
// judgement.
func fastCheckOptions() CheckOptions {
	opts := DefaultCheckOptions()
	opts.Interval = 20 * time.Millisecond
	opts.Samples = 15
	opts.Leak.MinGrowth = 5
	return opts
}

// TestCheckPIDConvictsThisProcessWhileItLeaks is the positive case: descriptors
// that are opened and held must be judged a leak, and the series the verdict was
// computed on must show the rise it claims.
func TestCheckPIDConvictsThisProcessWhileItLeaks(t *testing.T) {
	stop := make(chan struct{})
	opened := make(chan []*os.File, 1)

	go func() {
		var held []*os.File
		for {
			select {
			case <-stop:
				opened <- held
				return
			default:
			}
			f, err := os.Open("/dev/null")
			if err != nil {
				// Handing back what was opened keeps the assertion below honest
				// about how much of the leak the fixture actually produced.
				opened <- held
				return
			}
			held = append(held, f)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	res, checkErr := CheckPID(os.Getpid(), fastCheckOptions())
	close(stop)
	held := <-opened
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()

	if checkErr != nil {
		t.Fatalf("checking a process that was opening descriptors returned %v", checkErr)
	}
	// The premise, asserted rather than assumed: a fixture that opened fewer than
	// the growth floor would leave the verdict correct for the wrong reason.
	if len(held) < 5 {
		t.Fatalf("the fixture opened only %d descriptors, below the growth floor of 5: it did not create "+
			"the leak it tests (totals: %v)", len(held), res.Totals)
	}
	if !res.Leaking() {
		t.Fatalf("a process that opened %d descriptors and closed none was cleared; totals: %v\ntotal verdict: %+v",
			len(held), res.Totals, res.Report.Total)
	}
	if !res.Report.Total.Leak {
		t.Fatalf("the leak was attributed to a single resource but not to the process total: %+v", res.Report.Total)
	}

	// The evidence must be in the report, not just the conclusion: the growth the
	// verdict names has to match the rise the retained series actually shows.
	if first, last := res.Totals[0], res.Totals[len(res.Totals)-1]; last-first < 5 {
		t.Fatalf("the verdict claims a leak but the recorded series rose %d -> %d: the numbers and the "+
			"conclusion disagree (totals: %v)", first, last, res.Totals)
	}
	if res.Report.Total.Evidence.Growth < 5 {
		t.Fatalf("verdict growth = %d, want at least the floor of 5: %+v",
			res.Report.Total.Evidence.Growth, res.Report.Total.Evidence)
	}
}

// TestCheckPIDClearsAQuietProcess is the reverse assertion. It is the one that
// decides whether the tool is usable: a process holding a stable set of
// descriptors must not be convicted, however many it holds.
func TestCheckPIDClearsAQuietProcess(t *testing.T) {
	opts := DefaultCheckOptions()
	opts.Interval = 20 * time.Millisecond
	opts.Samples = 12

	res, err := CheckPID(os.Getpid(), opts)
	if err != nil {
		t.Fatalf("checking an idle process returned %v", err)
	}
	if res.Leaking() {
		t.Fatalf("a process that opened nothing during the window was convicted: total %+v, resources %+v",
			res.Report.Total, res.Report.Series)
	}
	if len(res.Totals) != 12 {
		t.Fatalf("recorded %d samples, want 12: the window the verdict rests on is not the window asked for",
			len(res.Totals))
	}
}

// TestCheckPIDRefusesAShortWindowInsteadOfPassing proves the refusal edge: three
// samples cannot separate a warming pool from a leak, and answering "no leak"
// there would be the calm-direction lie. The refusal must be an error, because a
// gate that treats "I could not tell" as a pass is worse than no gate.
func TestCheckPIDRefusesAShortWindowInsteadOfPassing(t *testing.T) {
	opts := DefaultCheckOptions()
	opts.Interval = 10 * time.Millisecond
	opts.Samples = 3

	_, err := CheckPID(os.Getpid(), opts)
	if err == nil {
		t.Fatal("a three-sample window returned a verdict; it cannot support one")
	}
	if !strings.Contains(err.Error(), "not enough samples") {
		t.Fatalf("error = %v, want it to name the reason (not enough samples)", err)
	}
}

// TestCheckPIDFailsOnAMissingProcess keeps "no such process" out of the "no leak"
// bucket. The two are different answers to different questions, and a CI job
// branching on the exit code must be able to tell them apart.
func TestCheckPIDFailsOnAMissingProcess(t *testing.T) {
	opts := fastCheckOptions()
	_, err := CheckPID(4194304, opts)
	if err == nil {
		t.Fatal("checking a pid that does not exist returned a verdict")
	}
	if !errors.Is(err, ErrNoSuchProcess) {
		t.Fatalf("error = %v, want it to wrap ErrNoSuchProcess", err)
	}
}

// TestCheckPIDRefusesOnAnUnsupportedPlatform covers the branch that can only be
// reached on a platform without /proc: the refusal itself.
//
// It is exercised here with the gate replaced rather than left to run only on
// macOS, because a safety rule that no test ever executes is a rule nobody has
// verified - and this one is the difference between "could not check" and a
// silent pass on every descriptor in the process.
func TestCheckPIDRefusesOnAnUnsupportedPlatform(t *testing.T) {
	restore := supported
	supported = func() bool { return false }
	defer func() { supported = restore }()

	_, err := CheckPID(os.Getpid(), DefaultCheckOptions())
	if !errors.Is(err, ErrNotLinux) {
		t.Fatalf("error = %v, want ErrNotLinux", err)
	}
}
