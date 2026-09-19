package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/oauth2"
)

// execTokenEnv is where --exec puts the credential. GITHUB_TOKEN is what gh,
// the Actions toolkit, and most GitHub tooling already read, so the wrapped
// command usually needs no change.
const execTokenEnv = "GITHUB_TOKEN"

// runWithToken runs argv with the credential in its environment and writes
// nothing to stdout itself. The token never reaches a terminal, a log, or an
// agent's transcript.
//
// The child's exit status becomes githubauth's, so --exec is transparent to
// whatever inspects the result.
func runWithToken(argv []string, tok *oauth2.Token, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(environWithout(os.Environ(), execTokenEnv), execTokenEnv+"="+tok.AccessToken)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr

	err := cmd.Run()
	if err == nil {
		return nil
	}

	// An exit status is the child's answer, not a failure of ours, so it is
	// passed through rather than classified.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return exitStatus(code)
		}
		// Killed by a signal: ExitCode is -1 and err says which.
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	return fmt.Errorf("running %s: %w", argv[0], err)
}

// environWithout drops key from env so the token cannot be shadowed by one the
// caller already exported.
func environWithout(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return out
}
