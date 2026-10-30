package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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

	for _, key := range append(execTokenEnv, execEnterpriseEnv...) {
		fmt.Printf("%s=%s\n", key, os.Getenv(key))
	}
	if os.Getenv("GITHUBAUTH_EXEC_SELF_TERM") != "" {
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGTERM)
	}
	if os.Getenv("GITHUBAUTH_EXEC_SLEEP") != "" {
		time.Sleep(10 * time.Second)
	}
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
		if err := runWithToken(helperArgv(), tok, false, strings.NewReader(""), &stdout, &stderr); err != nil {
			t.Fatalf("runWithToken() error = %v (stderr: %s)", err, stderr.String())
		}
		for _, key := range execTokenEnv {
			if !strings.Contains(stdout.String(), key+"=ghs_secret") {
				t.Errorf("child stdout = %q, want the token in $%s", stdout.String(), key)
			}
		}
	})

	t.Run("a token already in the environment is replaced", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "0")
		// gh reads GH_TOKEN before GITHUB_TOKEN, so a stale one there would
		// run gh as the caller.
		for _, key := range execTokenEnv {
			t.Setenv(key, "ghs_stale")
		}

		var stdout, stderr bytes.Buffer
		if err := runWithToken(helperArgv(), tok, false, strings.NewReader(""), &stdout, &stderr); err != nil {
			t.Fatalf("runWithToken() error = %v", err)
		}
		if strings.Contains(stdout.String(), "ghs_stale") {
			t.Errorf("child stdout = %q, want the minted token to win", stdout.String())
		}
	})

	t.Run("an Enterprise Server credential also reaches gh's enterprise variables", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "0")

		var stdout, stderr bytes.Buffer
		if err := runWithToken(helperArgv(), tok, true, strings.NewReader(""), &stdout, &stderr); err != nil {
			t.Fatalf("runWithToken() error = %v", err)
		}
		for _, key := range append(execTokenEnv, execEnterpriseEnv...) {
			if !strings.Contains(stdout.String(), key+"=ghs_secret") {
				t.Errorf("child stdout = %q, want the token in $%s", stdout.String(), key)
			}
		}
	})

	// A credential minted for github.com must not reach a host gh treats as
	// enterprise, and a stale enterprise token must not run gh as the caller.
	t.Run("enterprise variables are cleared for a github.com credential", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "0")
		for _, key := range execEnterpriseEnv {
			t.Setenv(key, "ghs_stale")
		}

		var stdout, stderr bytes.Buffer
		if err := runWithToken(helperArgv(), tok, false, strings.NewReader(""), &stdout, &stderr); err != nil {
			t.Fatalf("runWithToken() error = %v", err)
		}
		for _, key := range execEnterpriseEnv {
			if !strings.Contains(stdout.String(), key+"=\n") {
				t.Errorf("child stdout = %q, want $%s empty", stdout.String(), key)
			}
		}
	})

	t.Run("the child's exit code is passed through", func(t *testing.T) {
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_CODE", "9")

		var stdout, stderr bytes.Buffer
		err := runWithToken(helperArgv(), tok, false, strings.NewReader(""), &stdout, &stderr)

		var status exitStatus
		if !errors.As(err, &status) {
			t.Fatalf("runWithToken() error = %v, want an exitStatus", err)
		}
		if int(status) != 9 {
			t.Errorf("exitStatus = %d, want 9", int(status))
		}
	})

	t.Run("a command that cannot be started is an invocation to fix", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := runWithToken([]string{"githubauth-no-such-command"}, tok, false, strings.NewReader(""), &stdout, &stderr)

		var ue usageError
		if !errors.As(err, &ue) {
			t.Errorf("runWithToken() error = %v, want a usageError", err)
		}
	})

	t.Run("a child killed by a signal exits 128 plus its number", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no signals on windows")
		}
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_SELF_TERM", "1")
		t.Setenv("GITHUBAUTH_EXEC_SLEEP", "1")

		var stdout, stderr bytes.Buffer
		err := runWithToken(helperArgv(), tok, false, strings.NewReader(""), &stdout, &stderr)

		var status exitStatus
		if !errors.As(err, &status) || int(status) != 128+int(syscall.SIGTERM) {
			t.Errorf("runWithToken() error = %v, want exitStatus %d", err, 128+int(syscall.SIGTERM))
		}
	})

	// A SIGTERM sent to githubauth alone would otherwise leave the child
	// running with the credential in its environment.
	t.Run("SIGTERM is forwarded to the child", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("no signals on windows")
		}
		t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
		t.Setenv("GITHUBAUTH_EXEC_SLEEP", "1")

		go func() {
			time.Sleep(500 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGTERM)
		}()

		start := time.Now()
		var stdout, stderr bytes.Buffer
		err := runWithToken(helperArgv(), tok, false, strings.NewReader(""), &stdout, &stderr)

		var status exitStatus
		if !errors.As(err, &status) || int(status) != 128+int(syscall.SIGTERM) {
			t.Errorf("runWithToken() error = %v, want exitStatus %d", err, 128+int(syscall.SIGTERM))
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("elapsed = %v, want the child stopped by the forwarded signal", elapsed)
		}
	})
}

func TestEnvironWithout(t *testing.T) {
	t.Parallel()

	env := []string{"PATH=/bin", "GITHUB_TOKEN=stale", "GH_TOKEN=stale", "GITHUB_TOKEN_EXTRA=kept", "HOME=/home/x"}
	want := []string{"PATH=/bin", "GITHUB_TOKEN_EXTRA=kept", "HOME=/home/x"}

	got := environWithout(env, "GITHUB_TOKEN", "GH_TOKEN")
	if len(got) != len(want) {
		t.Fatalf("environWithout() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("environWithout()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
