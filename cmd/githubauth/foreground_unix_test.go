//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestForegroundOfNonTerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	// /dev/null is a character device, which is what fooled a stat-based check.
	if foregroundOf(f.Fd(), syscall.Getpgrp()) {
		t.Error("foregroundOf(/dev/null) = true, want false: it is no terminal")
	}
}

// TestInForegroundWithoutTerminal runs the probe in a new session, which has
// no controlling terminal, as under a supervisor: no Ctrl-C can reach the
// child there, so a SIGINT must be passed on.
func TestInForegroundWithoutTerminal(t *testing.T) {
	if os.Getenv("GITHUBAUTH_FOREGROUND_PROBE") != "" {
		if inForeground(os.Getpid()) {
			os.Exit(3)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestInForegroundWithoutTerminal$")
	cmd.Env = append(os.Environ(), "GITHUBAUTH_FOREGROUND_PROBE=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("inForeground() in a session without a terminal = true or failed: %v %s", err, strings.TrimSpace(string(out)))
	}
}
