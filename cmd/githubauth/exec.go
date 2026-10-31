package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jferrl/go-githubauth"
	"golang.org/x/oauth2"
)

// execTokenEnv is where --exec puts the credential. GITHUB_TOKEN is what the
// Actions toolkit and most GitHub tooling read. gh reads GH_TOKEN first, so an
// exported one would otherwise run gh as the caller rather than as the App.
var execTokenEnv = []string{"GITHUB_TOKEN", "GH_TOKEN"}

// execEnterpriseEnv is what gh reads for an Enterprise Server host. Both are
// always cleared, and set only for an Enterprise Server credential, so gh never
// sends one minted for a single host to whichever enterprise host it targets.
var execEnterpriseEnv = []string{"GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// runWithToken runs argv with the credential in its environment and writes
// nothing to stdout itself. The token never reaches a terminal, a log, or an
// agent's transcript. host is the instance the credential is for, as gh names
// it, or empty for github.com.
//
// The child's exit status becomes githubauth's, so --exec is transparent to
// whatever inspects the result.
func runWithToken(argv []string, tok *oauth2.Token, host string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runChild(argv, tok, host, inForeground, stdin, stdout, stderr)
}

// runChild is runWithToken with the foreground check passed in, which a test
// cannot leave to whatever terminal it happens to run under.
func runChild(argv []string, tok *oauth2.Token, host string, inFg func(pid int) bool, stdin io.Reader, stdout, stderr io.Writer) error {
	all := append(slices.Clone(execTokenEnv), execEnterpriseEnv...)
	keys := execTokenEnv
	if isEnterpriseHost(host) {
		keys = all
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	// The child gets an installation token for an hour, never the App's key,
	// which mints tokens for every installation until it is rotated.
	cmd.Env = childEnviron()
	for _, key := range keys {
		cmd.Env = append(cmd.Env, key+"="+tok.AccessToken)
	}
	// Without it gh targets github.com, where this credential is useless. A
	// GH_HOST the caller exported was checked against host before minting.
	if host != "" && os.Getenv("GH_HOST") == "" {
		cmd.Env = append(cmd.Env, "GH_HOST="+host)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr

	// A SIGTERM, or a SIGINT from a supervisor, is sent to githubauth alone,
	// and is passed on so the child does not outlive it with the credential in
	// its environment. A Ctrl-C at the keyboard reaches the child itself when
	// the child is in the terminal's foreground job, so then SIGINT is only
	// held, to keep githubauth alive until the child exits.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	// The credential was minted, so a command that cannot start is the
	// invocation to fix, not something to retry.
	if err := cmd.Start(); err != nil {
		return usagef("running %s: %w", argv[0], err)
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig == syscall.SIGTERM || !inFg(cmd.Process.Pid) {
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

// revokeTimeout keeps a stalled GitHub from holding the command's exit code back
// for the library's full minute.
const revokeTimeout = 10 * time.Second

// holdSignals keeps SIGINT and SIGTERM from killing githubauth until the
// returned func runs. Held from before the command starts until the token is
// revoked, a signal in between cannot leave the token valid. revokeTimeout
// bounds how long they stay held once the command has exited.
func holdSignals() func() {
	held := make(chan os.Signal, 1)
	signal.Notify(held, os.Interrupt, syscall.SIGTERM)
	return func() { signal.Stop(held) }
}

// revoke ends the token once the command it was minted for has exited, so a
// copy left in a child's environment or output stops working. err is the
// command's result, returned with a revocation failure added only when
// githubauth itself failed: one failure report, JSON under --agent, then
// carries both. Otherwise a failure only warns, and the exit code stays the
// command's.
func revoke(err error, tok *oauth2.Token, opts []githubauth.InstallationTokenSourceOpt, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	revokeErr := githubauth.RevokeInstallationToken(ctx, tok.AccessToken, opts...)
	// A 401 means the token is already dead: past its hour, or revoked by the
	// command itself.
	var apiErr *githubauth.APIError
	if revokeErr == nil || (errors.As(revokeErr, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized) {
		return err
	}

	revokeErr = fmt.Errorf("the token was not revoked and stays valid until %s: %w", tok.Expiry.Format(time.RFC3339), revokeErr)
	var status exitStatus
	if err != nil && !errors.As(err, &status) {
		return errors.Join(err, revokeErr)
	}
	_, _ = fmt.Fprintf(stderr, "githubauth: %v\n", revokeErr)
	return err
}

// ghHost names the instance behind an API URL the way gh does. github.com and
// data residency serve their API from an api. subdomain, Enterprise Server from
// /api/v3 on the host itself.
func ghHost(apiURL string) string {
	u, err := url.Parse(apiURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if rest, ok := strings.CutPrefix(host, "api."); ok && !isEnterpriseHost(rest) {
		host = rest
	}
	// gh honours a port in GH_HOST. Without it the credential would go to
	// whatever answers on 443 of that host. gh speaks only https, so only its
	// default can go; and a host with a port is never rewritten, since gh then
	// treats it as Enterprise Server and would not put api. back.
	if port := u.Port(); port != "" && (u.Scheme != "https" || port != "443") {
		return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	}
	// An IPv6 address needs its brackets back to be a host gh can parse.
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// isEnterpriseHost mirrors gh's own test for whether a host reads the
// enterprise variables: anything but github.com and data residency (*.ghe.com).
func isEnterpriseHost(host string) bool {
	return host != "" && host != "github.com" && !strings.HasSuffix(host, ".github.com") && !strings.HasSuffix(host, ".ghe.com")
}

// childEnviron is githubauth's environment without the App's private key or
// any token already exported, for every process githubauth starts.
func childEnviron() []string {
	// Windows ignores case in variable names, so github_app_private_key is
	// the same variable there.
	return environWithout(os.Environ(), runtime.GOOS == "windows", append(append(slices.Clone(execTokenEnv), execEnterpriseEnv...), "GITHUB_APP_PRIVATE_KEY")...)
}

// environWithout drops keys from env so the token cannot be shadowed by one
// the caller already exported. foldCase matches names ignoring case.
func environWithout(env []string, foldCase bool, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(keys, func(k string) bool { return k == name || (foldCase && strings.EqualFold(k, name)) }) {
			out = append(out, kv)
		}
	}
	return out
}
