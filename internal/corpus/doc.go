// Package corpus holds the regression suite that judges real programs instead of
// synthetic counts.
//
// Everything in fdscope so far was tested against shapes its own author invented,
// and invented shapes drift towards what the tool already recognises. The
// programs under testdata/corpus are pattern rewrites of descriptor lifecycle
// defects found in a real project (see docs/corpus.md); this package builds them,
// runs them, and asks the library for a verdict.
//
// The suite is Linux-only for the obvious reason, and it lives in its own package
// so that a failure here reads as "the corpus regressed", not as a stray failure
// inside the analyser's own tests.
package corpus
