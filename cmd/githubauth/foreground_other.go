//go:build !darwin && !linux

package main

// inForeground reports false where there is no process group to ask, so a
// signal is always passed on. On Windows the Go runtime cannot pass it on, and
// a console's Ctrl-C reaches every process attached to it instead.
func inForeground(int) bool { return false }
