package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/oauth2"
)

// execTokenEnv is where --exec puts the credential. GITHUB_TOKEN is what the
// Actions toolkit and most GitHub tooling read. gh reads GH_TOKEN first, so an
// exported one would otherwise run gh as the caller rather than as the App.
var execTokenEnv = []string{"GITHUB_TOKEN", "GH_TOKEN"}

// execEnterpriseEnv is what gh reads for an Enterprise Server host. Both are
// always cleared, and set only for an --enterprise-url credential, so gh never
// sends one minted for a single host to whichever enterprise host it targets.
var execEnterpriseEnv = []string{"GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// runWithToken runs argv with the credential in its environment and writes
// nothing to stdout itself. The token never reaches a terminal, a log, or an
// agent's transcript.
//
// The child's exit status becomes githubauth's, so --exec is transparent to
// whatever inspects the result.
func runWithToken(argv []string, tok *oauth2.Token, enterprise bool, stdin io.Reader, stdout, stderr io.Writer) error {
	all := append(slices.Clone(execTokenEnv), execEnterpriseEnv...)
	keys := execTokenEnv
	if enterprise {
		keys = all
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = environWithout(os.Environ(), all...)
	for _, key := range keys {
		cmd.Env = append(cmd.Env, key+"="+tok.AccessToken)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr

	// Ctrl-C already reaches the child through the terminal's process group, so
	// SIGINT is only held to keep githubauth alive until the child exits. A
	// SIGTERM is usually sent to githubauth alone, and is passed on so the
	// child does not outlive it with the credential in its environment.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	// The credential was minted, so a command that cannot start is the
	// invocation to fix, not something to retry.
	if err := cmd.Start(); err != nil {
		return usagef("running %s: %v", argv[0], err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig == syscall.SIGTERM {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	if err == nil {
		return nil
	}

	// An exit status is the child's answer, not a failure of ours, so it is
	// passed through rather than classified.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		// Killed by a signal: exit as a shell would, 128 plus its number.
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitStatus(128 + int(ws.Signal()))
		}
		if code := ee.ExitCode(); code >= 0 {
			return exitStatus(code)
		}
	}
	return fmt.Errorf("running %s: %w", argv[0], err)
}

// environWithout drops keys from env so the token cannot be shadowed by one
// the caller already exported.
func environWithout(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(keys, name) {
			out = append(out, kv)
		}
	}
	return out
}
