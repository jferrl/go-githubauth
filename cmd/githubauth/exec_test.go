package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestExecHelper is a helper rather than a test. The --exec cases re-run this
// binary under this name, which gives them a child process that exists on
// every platform the tests do, unlike a shell.
func TestExecHelper(t *testing.T) {
	if os.Getenv("GITHUBAUTH_EXEC_HELPER") == "" {
		t.Skip("helper process for the --exec tests")
	}

	fmt.Printf("saw=%s\n", os.Getenv(execTokenEnv))
	code, _ := strconv.Atoi(os.Getenv("GITHUBAUTH_EXEC_CODE"))
	os.Exit(code)
}

// helperArgv is the command the --exec tests run: this test binary, limited to
// the helper above.
func helperArgv() []string {
	return []string{os.Args[0], "-test.run=^TestExecHelper$"}
}

func TestRunWithToken(t *testing.T) {
	tok := &oauth2.Token{AccessToken: "ghs_secret", Expiry: time.Now().Add(time.Hour)}

	t.Run("the credential reaches the child and nothing else prints it", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "0")

		var stdout, stderr bytes.Buffer
		if err := runWithToken(helperArgv(), tok, strings.NewReader(""), &stdout, &stderr); err != nil {
			t.Fatalf("runWithToken() error = %v (stderr: %s)", err, stderr.String())
		}
		if !strings.Contains(stdout.String(), "saw=ghs_secret") {
			t.Errorf("child stdout = %q, want it to report the token in $%s", stdout.String(), execTokenEnv)
		}
	})

	t.Run("a token already in the environment is replaced", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "0")
		t.Setenv(execTokenEnv, "ghs_stale")

		var stdout, stderr bytes.Buffer
		if err := runWithToken(helperArgv(), tok, strings.NewReader(""), &stdout, &stderr); err != nil {
			t.Fatalf("runWithToken() error = %v", err)
		}
		if strings.Contains(stdout.String(), "ghs_stale") {
			t.Errorf("child stdout = %q, want the minted token to win", stdout.String())
		}
	})

	t.Run("the child's exit code is passed through", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "9")

		var stdout, stderr bytes.Buffer
		err := runWithToken(helperArgv(), tok, strings.NewReader(""), &stdout, &stderr)

		var status exitStatus
		if !errors.As(err, &status) {
			t.Fatalf("runWithToken() error = %v, want an exitStatus", err)
		}
		if int(status) != 9 {
			t.Errorf("exitStatus = %d, want 9", int(status))
		}
	})

	t.Run("a command that cannot be started is our failure, not the child's", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runWithToken([]string{"githubauth-no-such-command"}, tok, strings.NewReader(""), &stdout, &stderr)

		if err == nil {
			t.Fatal("runWithToken() = nil, want an error")
		}
		var status exitStatus
		if errors.As(err, &status) {
			t.Errorf("error is an exitStatus (%d), want a startup failure", int(status))
		}
	})
}

func TestEnvironWithout(t *testing.T) {
	t.Parallel()

	env := []string{"PATH=/bin", "GITHUB_TOKEN=stale", "GITHUB_TOKEN_EXTRA=kept", "HOME=/home/x"}
	want := []string{"PATH=/bin", "GITHUB_TOKEN_EXTRA=kept", "HOME=/home/x"}

	got := environWithout(env, "GITHUB_TOKEN")
	if len(got) != len(want) {
		t.Fatalf("environWithout() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("environWithout()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
