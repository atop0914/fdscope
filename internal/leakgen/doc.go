// Package leakgen opens real file descriptors on purpose, at a configurable
// rate, so that a leak verdict can be exercised against something that actually
// holds descriptors instead of two synthetic counts.
//
// It exists because of a lesson this project keeps relearning: a detector tested
// only against hand-written number sequences is a detector that agrees with its
// author's model of the kernel, not with the kernel. Every case built on this
// package has to earn its verdict from /proc.
//
// It is a fixture helper, not part of fdscope's surface: nothing in cmd/ or pkg/
// imports it, and a test in this package fails the build if that ever changes.
// The implementation is Linux-only for the same reason the rest of the tool is.
package leakgen
