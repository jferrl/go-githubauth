package main

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// appEnv are the variables every flag falls back to. Tests clear them so a
// developer's own shell cannot change the result.
var appEnv = []string{
	"GITHUB_APP_CLIENT_ID",
	"GITHUB_APP_ID",
	"GITHUB_APP_PRIVATE_KEY",
	"GITHUB_APP_INSTALLATION_ID",
}

func clearEnv(t *testing.T) {
	t.Helper()

	for _, key := range appEnv {
		t.Setenv(key, "")
	}

	// These tests usually run inside a coding agent, which would otherwise
	// switch the error output to JSON on stdout under them.
	t.Setenv("GITHUBAUTH_AGENT_MODE", "0")

	// The tests run in a clone of this repository, whose origin would
	// otherwise name an installation on github.com for them. GIT_DIR and
	// GIT_WORK_TREE would point git back at it from anywhere, and the
	// caller's own git config could rewrite the test remotes.
	t.Chdir(t.TempDir())
	for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE"} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

func testKeyPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// tokenHandler stands in for the installation access token endpoint, and for
// the revocation --exec sends once the command exits.
func tokenHandler(token string) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      token,
				"expires_at": time.Now().Add(time.Hour),
			})
		}))
	}
}

func statusHandler(code int) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
	}
}

// Stdout matchers, so one table can assert on a fixed token, a signed JWT
// whose bytes differ every run, and a JSON envelope.

func isEmpty(t *testing.T, got string) {
	t.Helper()

	if got != "" {
		t.Errorf("stdout = %q, want it empty", got)
	}
}

func isNotEmpty(t *testing.T, got string) {
	t.Helper()

	if got == "" {
		t.Error("stdout is empty, want output")
	}
}

func isExactly(want string) func(*testing.T, string) {
	return func(t *testing.T, got string) {
		t.Helper()

		if got != want {
			t.Errorf("stdout = %q, want %q", got, want)
		}
	}
}

func contains(want string) func(*testing.T, string) {
	return func(t *testing.T, got string) {
		t.Helper()

		if !strings.Contains(got, want) {
			t.Errorf("stdout = %q, want it to contain %q", got, want)
		}
	}
}

func isJWT(t *testing.T, got string) {
	t.Helper()

	if n := len(strings.Split(got, ".")); n != 3 {
		t.Errorf("stdout has %d JWT segments, want 3", n)
	}
}

// isJSONToken checks the --json envelope: the token, and an expiry that is in
// the future but no further out than max.
func isJSONToken(want string, max time.Duration) func(*testing.T, string) {
	return func(t *testing.T, got string) {
		t.Helper()

		var out struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal([]byte(got), &out); err != nil {
			t.Fatalf("decoding %q: %v", got, err)
		}
		if want != "" && out.Token != want {
			t.Errorf("token = %q, want %q", out.Token, want)
		}
		if d := time.Until(out.ExpiresAt); d <= 0 || d > max {
			t.Errorf("expires in %v, want a positive duration under %v", d, max)
		}
	}
}

func TestRun(t *testing.T) {
	keyPEM := testKeyPEM(t)
	keyPath := writeFile(t, "app.pem", keyPEM)
	badKeyPath := writeFile(t, "bad.pem", []byte("not a key"))

	tests := []struct {
		name        string
		args        func(serverURL string) []string
		stdin       string
		env         map[string]string
		setupServer func() *httptest.Server
		wantCode    int
		wantStdout  func(*testing.T, string)
		wantStderr  string
		quietStderr bool
	}{
		{
			name:       "no arguments print usage to stderr",
			args:       func(string) []string { return nil },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "githubauth mints",
		},
		{
			name:       "help goes to stdout",
			args:       func(string) []string { return []string{"help"} },
			wantCode:   0,
			wantStdout: contains("EXAMPLES"),
		},
		{
			name:       "--help is accepted",
			args:       func(string) []string { return []string{"--help"} },
			wantCode:   0,
			wantStdout: contains("githubauth mints"),
		},
		{
			name:       "version prints something",
			args:       func(string) []string { return []string{"version"} },
			wantCode:   0,
			wantStdout: isNotEmpty,
		},
		{
			name:       "unknown command suggests the nearest match",
			args:       func(string) []string { return []string{"toekn"} },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: `did you mean "githubauth token"?`,
		},
		{
			name:       "unrecognisable command offers help",
			args:       func(string) []string { return []string{"xyzzy"} },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: `run "githubauth help" for usage`,
		},
		{
			name:       "unknown flag is misuse",
			args:       func(string) []string { return []string{"jwt", "-nosuchflag"} },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "not defined",
		},
		{
			name: "token prints the installation token",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			setupServer: tokenHandler("ghs_installationtoken"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_installationtoken"),
		},
		{
			name: "token reads every value from the environment",
			args: func(url string) []string { return []string{"token", "--base-url", url} },
			env: map[string]string{
				"GITHUB_APP_CLIENT_ID":       "Iv1.fromenv",
				"GITHUB_APP_PRIVATE_KEY":     string(keyPEM),
				"GITHUB_APP_INSTALLATION_ID": "77",
			},
			setupServer: tokenHandler("ghs_fromenv"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_fromenv"),
		},
		{
			name: "token reads the key from stdin",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", "-", "--installation", "99", "--base-url", url}
			},
			stdin:       string(keyPEM),
			setupServer: tokenHandler("ghs_fromstdin"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_fromstdin"),
		},
		{
			name: "token scopes to repositories and emits JSON",
			args: func(url string) []string {
				return []string{
					"token", "--app-id", "42", "--key", keyPath, "--installation", "99",
					"--base-url", url, "--repos", "one, two ,", "--json",
				}
			},
			setupServer: tokenHandler("ghs_scoped"),
			wantCode:    0,
			wantStdout:  isJSONToken("ghs_scoped", 2*time.Hour),
		},
		{
			name: "token accepts a legacy app ID",
			args: func(url string) []string {
				return []string{"token", "--app-id", "42", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			setupServer: tokenHandler("ghs_legacy"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_legacy"),
		},
		{
			name: "token targets GitHub Enterprise Server",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--enterprise-url", url}
			},
			setupServer: tokenHandler("ghs_ghes"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_ghes"),
		},
		{
			name: "token refuses two identifiers",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--app-id", "42", "--key", keyPath, "--installation", "99"}
			},
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "not both",
		},
		{
			name: "token reports an API rejection",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			setupServer: statusHandler(http.StatusUnauthorized),
			wantCode:    exitCredentials,
			wantStdout:  isEmpty,
			wantStderr:  "GitHub rejected the App JWT",
		},
		{
			name: "token needs an installation ID",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath}
			},
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "missing installation ID",
		},
		{
			name: "token refuses two base URLs",
			args: func(string) []string {
				return []string{
					"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "1",
					"--base-url", "https://a.example", "--enterprise-url", "https://b.example",
				}
			},
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "not both",
		},
		{
			name:       "jwt prints a signed token",
			args:       func(string) []string { return []string{"jwt", "--client-id", "Iv1.abc", "--key", keyPath} },
			wantCode:   0,
			wantStdout: isJWT,
		},
		{
			name: "jwt honours a shorter expiry",
			args: func(string) []string {
				return []string{"jwt", "--app-id", "42", "--key", keyPath, "--expiry", "5m", "--json"}
			},
			wantCode: 0,
			// 5m less the 60s clock-drift backdate and the 30s refresh skew.
			wantStdout: isJSONToken("", 5*time.Minute),
		},
		{
			name: "jwt refuses two identifiers",
			args: func(string) []string {
				return []string{"jwt", "--client-id", "Iv1.abc", "--app-id", "42", "--key", keyPath}
			},
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "not both",
		},
		{
			name:       "jwt needs an identifier",
			args:       func(string) []string { return []string{"jwt", "--key", keyPath} },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "missing App identifier",
		},
		{
			name:       "jwt needs a key",
			args:       func(string) []string { return []string{"jwt", "--client-id", "Iv1.abc"} },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: "missing private key",
		},
		{
			name:       "a key path that resolves to nothing is misuse",
			args:       func(string) []string { return []string{"jwt", "--client-id", "Iv1.abc", "--key", "/no/such/key.pem"} },
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "reading private key",
		},
		{
			name:       "a malformed PEM is a credential failure",
			args:       func(string) []string { return []string{"jwt", "--client-id", "Iv1.abc", "--key", badKeyPath} },
			wantCode:   exitCredentials,
			wantStdout: isEmpty,
			wantStderr: "Check --key",
		},
		{
			name: "exec runs a command instead of printing the token",
			args: func(url string) []string {
				return []string{
					"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99",
					"--base-url", url, "--exec", "--", os.Args[0], "-test.run=^TestExecHelper$",
				}
			},
			env:         map[string]string{"GITHUBAUTH_EXEC_HELPER": "1", "GITHUBAUTH_EXEC_CODE": "0"},
			setupServer: tokenHandler("ghs_neverprinted"),
			wantCode:    0,
			wantStdout:  contains("GITHUB_TOKEN=ghs_neverprinted"),
		},
		{
			name: "exec points gh at the instance the token is for",
			args: func(url string) []string {
				return []string{
					"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99",
					"--base-url", url, "--exec", "--", os.Args[0], "-test.run=^TestExecHelper$",
				}
			},
			env:         map[string]string{"GITHUBAUTH_EXEC_HELPER": "1", "GITHUBAUTH_EXEC_CODE": "0", "GH_HOST": ""},
			setupServer: tokenHandler("ghs_hosted"),
			wantCode:    0,
			wantStdout:  contains("GH_HOST=127.0.0.1"),
		},
		{
			name: "exec exits as the command it ran did",
			args: func(url string) []string {
				return []string{
					"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99",
					"--base-url", url, "--exec", "--", os.Args[0], "-test.run=^TestExecHelper$",
				}
			},
			env:         map[string]string{"GITHUBAUTH_EXEC_HELPER": "1", "GITHUBAUTH_EXEC_CODE": "12"},
			setupServer: tokenHandler("ghs_failing"),
			wantCode:    12,
		},
		{
			name: "owner and installation together are misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--owner", "acme"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "set --installation or --owner, not both",
		},
		{
			name: "an owner naming a repository is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--owner", "acme/api"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `--owner "acme/api" is a repository`,
		},
		{
			name: "a dot segment is not an owner",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--owner", ".."}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `--owner ".." is not an account`,
		},
		{
			// The command never ran, so the failure is githubauth's own and its
			// one JSON report has to carry the token it left valid.
			name: "under an agent a failed revocation joins the failure report",
			args: func(url string) []string {
				return []string{
					"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99",
					"--base-url", url, "--agent", "--exec", "--", "githubauth-no-such-command",
				}
			},
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_unrevoked", "expires_at": time.Now().Add(time.Hour)})
				}))
			},
			wantCode:    exitUsage,
			wantStdout:  contains("the token was not revoked"),
			quietStderr: true,
		},
		{
			name: "an owner the App is not installed on exits as not installed",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--owner", "acme", "--base-url", url}
			},
			setupServer: statusHandler(http.StatusNotFound),
			wantCode:    exitNotFound,
			wantStdout:  isEmpty,
			wantStderr:  "Check --installation or --owner",
		},
		{
			name: "an owner prefix and --installation are misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--repos", "acme/api", "--installation", "9"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "drop --installation, or the acme/ prefix",
		},
		{
			name: "an owner prefix and a different --owner are misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--repos", "acme/api", "--owner", "other"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "--repos names repositories of acme, but --owner is other",
		},
		{
			name: "repositories of two owners are misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--repos", "acme/api,other/web"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "repositories of acme and of other",
		},
		{
			name: "an owner prefix without a repository is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--repos", "acme/"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `--repos "acme/" is neither`,
		},
		{
			name: "a path deeper than owner/repo is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--repos", "acme/api/x"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `--repos "acme/api/x" is neither`,
		},
		{
			name: "a dot owner prefix is not an account",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--repos", "../api"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `--owner ".." is not an account`,
		},
		{
			name: "keep without exec is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--keep"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "--keep applies only under --exec",
		},
		{
			name: "permissions naming none would mint every permission",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--permissions", " , "}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "--permissions names no permission",
		},
		{
			name: "a permission without a level is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--permissions", "contents"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `"contents" is not name:level`,
		},
		{
			name: "exec without a command is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--exec"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "--exec needs a command",
		},
		{
			name: "a stray argument suggests the flag that would have used it",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "gh", "pr", "list"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "pass --exec",
		},
		{
			name: "exec and json contradict each other",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--json", "--exec", "--", "true"}
			},
			// --json asked for JSON, so the refusal arrives as JSON too.
			wantCode:   exitUsage,
			wantStdout: contains("--json has nothing to format"),
		},
		{
			name: "agent mode says the credential is now in the transcript",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			env:         map[string]string{"GITHUBAUTH_AGENT_MODE": "1"},
			setupServer: tokenHandler("ghs_inthetranscript"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_inthetranscript"),
			wantStderr:  "--exec passes it to a command",
		},
		{
			name: "agent mode reports a failure as one JSON document on stdout",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			env:         map[string]string{"GITHUBAUTH_AGENT_MODE": "1"},
			setupServer: statusHandler(http.StatusNotFound),
			wantCode:    exitNotFound,
			wantStdout:  contains(`"type":"githubauth.error"`),
		},
		{
			name: "--agent=false opts out inside an agent",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url, "--agent=false"}
			},
			env:         map[string]string{"GITHUBAUTH_AGENT_MODE": "1"},
			setupServer: statusHandler(http.StatusNotFound),
			wantCode:    exitNotFound,
			wantStdout:  isEmpty,
			wantStderr:  "githubauth: GitHub API returned status 404",
		},
		{
			name:        "agent mode reports a missing command as JSON",
			args:        func(string) []string { return nil },
			env:         map[string]string{"GITHUBAUTH_AGENT_MODE": "1"},
			wantCode:    exitUsage,
			wantStdout:  contains(`"type":"githubauth.error"`),
			quietStderr: true,
		},
		{
			name:        "agent mode keeps the flag package's own message off stderr",
			args:        func(string) []string { return []string{"token", "--bogus"} },
			env:         map[string]string{"GITHUBAUTH_AGENT_MODE": "1"},
			wantCode:    exitUsage,
			wantStdout:  contains("flag provided but not defined"),
			quietStderr: true,
		},
		{
			name: "a --repos with no names is refused rather than widened to every repository",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--repos", " , "}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "--repos names no repository",
		},
		{
			name: "an unparseable --base-url is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--base-url", "%"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "must be an absolute http(s) URL",
		},
		{
			name: "an --enterprise-url without a scheme is misuse",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "9", "--enterprise-url", "github.example.com"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "must be an absolute http(s) URL",
		},
		{
			name: "an --expiry out of range is refused rather than replaced by 10m",
			args: func(string) []string {
				return []string{"jwt", "--client-id", "Iv1.abc", "--key", keyPath, "--expiry", "30s"}
			},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "--expiry 30s is out of range",
		},
		{
			name:       "a malformed environment ID is reported as malformed, not missing",
			args:       func(string) []string { return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath} },
			env:        map[string]string{"GITHUB_APP_INSTALLATION_ID": "12abc"},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `$GITHUB_APP_INSTALLATION_ID="12abc" is not a number`,
		},
		{
			name: "a malformed $GITHUB_APP_ID is ignored when --client-id names the App",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			env:         map[string]string{"GITHUB_APP_ID": "garbage"},
			setupServer: tokenHandler("ghs_clientidwins"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_clientidwins"),
		},
		{
			name:       "a malformed $GITHUB_APP_ID is reported when nothing else names the App",
			args:       func(string) []string { return []string{"jwt", "--key", keyPath} },
			env:        map[string]string{"GITHUB_APP_ID": "garbage"},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: `$GITHUB_APP_ID="garbage" is not a number`,
		},
		{
			name: "the flag overrides a malformed environment ID",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url}
			},
			env:         map[string]string{"GITHUB_APP_INSTALLATION_ID": "12abc"},
			setupServer: tokenHandler("ghs_flagwins"),
			wantCode:    0,
			wantStdout:  isExactly("ghs_flagwins"),
		},
		{
			name: "an explicit --installation 0 is missing, whatever the environment holds",
			args: func(string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "0"}
			},
			env:        map[string]string{"GITHUB_APP_INSTALLATION_ID": "12abc"},
			wantCode:   exitUsage,
			wantStdout: isEmpty,
			wantStderr: "missing installation ID",
		},
		{
			name: "a request GitHub rejects as invalid is not worth retrying",
			args: func(url string) []string {
				return []string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99", "--base-url", url, "--repos", "nope"}
			},
			setupServer: statusHandler(http.StatusUnprocessableEntity),
			wantCode:    exitUsage,
			wantStdout:  isEmpty,
			wantStderr:  "check --repos",
		},
		{
			name: "exec of a command that does not exist is misuse",
			args: func(url string) []string {
				return []string{
					"token", "--client-id", "Iv1.abc", "--key", keyPath, "--installation", "99",
					"--base-url", url, "--exec", "--", "githubauth-no-such-command",
				}
			},
			setupServer: tokenHandler("ghs_unused"),
			wantCode:    exitUsage,
			wantStdout:  isEmpty,
			wantStderr:  "running githubauth-no-such-command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			var serverURL string
			if tt.setupServer != nil {
				srv := tt.setupServer()
				defer srv.Close()
				serverURL = srv.URL
			}

			var stdout, stderr bytes.Buffer

			got := run(tt.args(serverURL), strings.NewReader(tt.stdin), &stdout, &stderr)
			if got != tt.wantCode {
				t.Errorf("run() = %d, want %d (stderr: %s)", got, tt.wantCode, stderr.String())
			}
			if tt.wantStdout != nil {
				tt.wantStdout(t, strings.TrimSpace(stdout.String()))
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			if tt.quietStderr && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

// TestTokenRequests checks what reaches GitHub: the installation and scope
// asked for, and the revocation --exec sends once the command exits, whatever
// it exited with.
func TestTokenRequests(t *testing.T) {
	keyPath := writeFile(t, "app.pem", testKeyPEM(t))

	tests := []struct {
		name       string
		args       []string
		code       string
		revokeWith int
		// termDuringRevoke sends githubauth a SIGTERM while the revocation is
		// in flight.
		termDuringRevoke bool
		// origin, when set, runs the test in a clone with this origin remote
		// and no installation in the environment.
		origin     func(serverURL string) string
		wantCode   int
		wantMint   string
		wantBody   string
		wantStdout string
		wantRevoke bool
		wantStderr string
	}{
		{
			name:     "the installation comes from the environment",
			wantMint: "/app/installations/99/access_tokens",
		},
		{
			name:     "an owner is looked up, ahead of the environment",
			args:     []string{"--owner", "acme"},
			wantMint: "/app/installations/123/access_tokens",
		},
		{
			name:     "an owner prefix on --repos finds the installation, ahead of the environment",
			args:     []string{"--repos", "acme/api,web"},
			wantMint: "/app/installations/123/access_tokens",
			wantBody: `{"repositories":["api","web"]}`,
		},
		{
			name:     "an owner prefix agrees with --owner",
			args:     []string{"--repos", "acme/api", "--owner", "acme"},
			wantMint: "/app/installations/123/access_tokens",
		},
		{
			name:       "json shows what GitHub granted",
			args:       []string{"--json"},
			wantStdout: `"permissions":{"metadata":"read","pull_requests":"write"},"repositories":["api"]}`,
		},
		{
			name:     "a clone's origin on the same host scopes the token to it",
			origin:   func(u string) string { return u + "/acme/api.git" },
			wantMint: "/app/installations/123/access_tokens",
			wantBody: `{"repositories":["api"]}`,
		},
		{
			name:     "a clone's origin on another host is ignored",
			origin:   func(string) string { return "git@github.com:acme/api.git" },
			wantCode: exitUsage,
		},
		{
			name:     "an --owner given empty is not nothing",
			origin:   func(u string) string { return u + "/acme/api.git" },
			args:     []string{"--owner", ""},
			wantCode: exitUsage,
		},
		{
			name:     "an installation given beats the clone's origin",
			origin:   func(u string) string { return u + "/acme/api.git" },
			args:     []string{"--installation", "99"},
			wantMint: "/app/installations/99/access_tokens",
		},
		{
			name:     "repos and permissions go in one request",
			args:     []string{"--repos", "api", "--permissions", "contents:read, pull_requests:write"},
			wantBody: `{"repositories":["api"],"permissions":{"contents":"read","pull_requests":"write"}}`,
		},
		{
			name:     "a permission newer than the library still reaches GitHub",
			args:     []string{"--permissions", "installation_repositories:write"},
			wantBody: `{"permissions":{"installation_repositories":"write"}}`,
		},
		{
			name:       "exec revokes the token when the command exits",
			args:       []string{"--exec", "--", os.Args[0], "-test.run=^TestExecHelper$"},
			code:       "0",
			wantRevoke: true,
		},
		{
			name:       "exec revokes the token when the command fails",
			args:       []string{"--exec", "--", os.Args[0], "-test.run=^TestExecHelper$"},
			code:       "9",
			wantCode:   9,
			wantRevoke: true,
		},
		{
			name:       "exec revokes a token whose command never started",
			args:       []string{"--exec", "--", "githubauth-no-such-command"},
			wantCode:   exitUsage,
			wantRevoke: true,
		},
		{
			name: "keep leaves the token valid",
			args: []string{"--exec", "--keep", "--", os.Args[0], "-test.run=^TestExecHelper$"},
			code: "0",
		},
		{
			name:             "a SIGTERM during the revocation does not stop it",
			args:             []string{"--exec", "--", os.Args[0], "-test.run=^TestExecHelper$"},
			code:             "0",
			termDuringRevoke: true,
			wantRevoke:       true,
		},
		{
			name:       "a token already dead is not reported as valid",
			args:       []string{"--exec", "--", os.Args[0], "-test.run=^TestExecHelper$"},
			code:       "0",
			revokeWith: http.StatusUnauthorized,
			wantRevoke: true,
		},
		{
			name:       "a failed revocation warns and keeps the command's exit code",
			args:       []string{"--exec", "--", os.Args[0], "-test.run=^TestExecHelper$"},
			code:       "0",
			revokeWith: http.StatusInternalServerError,
			wantRevoke: true,
			wantStderr: "the token was not revoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("GITHUBAUTH_EXEC_HELPER", "1")
			t.Setenv("GITHUBAUTH_EXEC_CODE", tt.code)

			t.Setenv("GITHUB_APP_INSTALLATION_ID", "99")
			if tt.termDuringRevoke && runtime.GOOS == "windows" {
				t.Skip("no signals on windows")
			}

			// events orders the child's use of the token against its revocation.
			var mu sync.Mutex
			var events []string
			record := func(e string) {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, e)
			}

			var mint, body, revokedWith string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/child":
					record("child used " + r.Header.Get("Authorization"))
					return
				case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
					record("revoked")
					revokedWith = r.Header.Get("Authorization")
					if tt.termDuringRevoke {
						p, _ := os.FindProcess(os.Getpid())
						_ = p.Signal(syscall.SIGTERM)
						// Signal delivery is asynchronous: let it land before
						// the revocation returns.
						time.Sleep(200 * time.Millisecond)
					}
					w.WriteHeader(cmp.Or(tt.revokeWith, http.StatusNoContent))
					return
				case r.Method == http.MethodGet && r.URL.Path == "/users/acme/installation":
					_, _ = io.WriteString(w, `{"id":123}`)
					return
				}
				b, _ := io.ReadAll(r.Body)
				mint, body = r.URL.Path, string(b)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"token":        "ghs_minted",
					"expires_at":   time.Now().Add(time.Hour),
					"permissions":  map[string]string{"metadata": "read", "pull_requests": "write"},
					"repositories": []map[string]any{{"id": 1, "name": "api", "full_name": "acme/api"}},
				})
			}))
			defer srv.Close()
			t.Setenv("GITHUBAUTH_EXEC_CALL", srv.URL+"/child")
			if tt.origin != nil {
				inClone(t, tt.origin(srv.URL))
				t.Setenv("GITHUB_APP_INSTALLATION_ID", "")
			}

			args := append([]string{"token", "--client-id", "Iv1.abc", "--key", keyPath, "--base-url", srv.URL}, tt.args...)
			var stdout, stderr bytes.Buffer
			if got := run(args, strings.NewReader(""), &stdout, &stderr); got != tt.wantCode {
				t.Errorf("run() = %d, want %d (stderr: %s)", got, tt.wantCode, stderr.String())
			}
			if tt.wantMint != "" && mint != tt.wantMint {
				t.Errorf("minted at %s, want %s", mint, tt.wantMint)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantBody != "" && body != tt.wantBody {
				t.Errorf("request body = %s, want %s", body, tt.wantBody)
			}
			if revoked := revokedWith != ""; revoked != tt.wantRevoke {
				t.Errorf("revoked = %v, want %v", revoked, tt.wantRevoke)
			}
			if tt.wantRevoke && revokedWith != "Bearer ghs_minted" {
				t.Errorf("revoked with Authorization %q, want the minted token", revokedWith)
			}
			// A command that ran used the token before it was revoked, not after.
			mu.Lock()
			got := strings.Join(events, ", ")
			mu.Unlock()
			if tt.wantRevoke && tt.code != "" && got != "child used Bearer ghs_minted, revoked" {
				t.Errorf("events = %q, want the child's use of the token before its revocation", got)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantStderr == "" && strings.Contains(stderr.String(), "not revoked") {
				t.Errorf("stderr = %q, want no revocation warning", stderr.String())
			}
		})
	}
}

// TestCommandHelp covers the per-command help. Asking for it is not a failure,
// so it exits 0 on stdout like "githubauth help", and an agent gets the help
// rather than an error document.
func TestCommandHelp(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "token",
			command: "token",
			want:    []string{"USAGE", "FLAGS", "EXAMPLES", "--installation int", "--repos string"},
		},
		{
			name:    "jwt",
			command: "jwt",
			want:    []string{"USAGE", "FLAGS", "EXAMPLES", "--expiry duration", "--client-id string"},
		},
	}

	for _, tt := range tests {
		for _, agent := range []string{"0", "1"} {
			t.Run(tt.name+"/agent="+agent, func(t *testing.T) {
				clearEnv(t)
				t.Setenv("GITHUBAUTH_AGENT_MODE", agent)

				var stdout, stderr bytes.Buffer

				if got := run([]string{tt.command, "-h"}, nil, &stdout, &stderr); got != 0 {
					t.Errorf("run() = %d, want 0", got)
				}
				if stderr.Len() != 0 {
					t.Errorf("stderr = %q, want empty", stderr.String())
				}

				help := stdout.String()
				if strings.Contains(help, "githubauth.error") {
					t.Errorf("help request reported as an error:\n%s", help)
				}
				for _, want := range tt.want {
					if !strings.Contains(help, want) {
						t.Errorf("help is missing %q:\n%s", want, help)
					}
				}
				if strings.Contains(help, "\n  -client-id") {
					t.Error("help renders single-dash flags")
				}
			})
		}
	}
}

// TestHelpNeverPrintsDefaults pins the reason printFlags exists: every flag
// falls back to an environment variable, and one of them holds the key.
func TestHelpNeverPrintsDefaults(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{name: "token", command: "token"},
		{name: "jwt", command: "jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("GITHUB_APP_PRIVATE_KEY", string(testKeyPEM(t)))
			t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.secretish")

			var stdout, stderr bytes.Buffer
			run([]string{tt.command, "-h"}, nil, &stdout, &stderr)

			out := stdout.String() + stderr.String()
			for _, leak := range []string{"BEGIN RSA PRIVATE KEY", "Iv1.secretish"} {
				if strings.Contains(out, leak) {
					t.Errorf("help output contains %q", leak)
				}
			}
		})
	}
}

func TestReadKey(t *testing.T) {
	t.Parallel()

	keyPEM := testKeyPEM(t)
	keyPath := writeFile(t, "key.pem", keyPEM)

	tests := []struct {
		name    string
		value   string
		stdin   string
		want    []byte
		wantErr string
	}{
		{name: "inline PEM passes through", value: string(keyPEM), want: keyPEM},
		{name: "dash reads stdin", value: "-", stdin: string(keyPEM), want: keyPEM},
		{name: "a path reads the file", value: keyPath, want: keyPEM},
		{name: "a missing file is reported", value: "/no/such/key.pem", wantErr: "reading private key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := readKey(tt.value, strings.NewReader(tt.stdin))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readKey() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readKey() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("readKey() returned %d bytes, want %d", len(got), len(tt.want))
			}
		})
	}
}

func TestSplitRepos(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "only spaces", in: "   ", want: nil},
		{name: "only separators", in: ",,", want: nil},
		{name: "one name", in: "one", want: []string{"one"}},
		{name: "padding and a trailing comma", in: " one , two ,", want: []string{"one", "two"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := splitRepos(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("splitRepos(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitRepos(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNearest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "transposition", in: "toekn", want: "token"},
		{name: "prefix", in: "tok", want: "token"},
		{name: "short prefix", in: "jw", want: "jwt"},
		{name: "trailing typo", in: "helpp", want: "help"},
		{name: "transposed version", in: "versoin", want: "version"},
		{name: "nothing close", in: "xyzzy", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := nearest(tt.in); got != tt.want {
				t.Errorf("nearest(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEditDistance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "identical", a: "token", b: "token", want: 0},
		{name: "one substitution", a: "takon", b: "token", want: 2},
		{name: "one insertion", a: "tokens", b: "token", want: 1},
		{name: "empty source", a: "", b: "token", want: 5},
		{name: "empty target", a: "token", b: "", want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := editDistance(tt.a, tt.b); got != tt.want {
				t.Errorf("editDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestEnvInt64(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int64
	}{
		{name: "a number", value: "42", want: 42},
		{name: "malformed is ignored", value: "not-a-number", want: 0},
		{name: "empty is zero", value: "", want: 0},
		{name: "negative", value: "-1", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUBAUTH_TEST_INT", tt.value)

			if got := envInt64("GITHUBAUTH_TEST_INT"); got != tt.want {
				t.Errorf("envInt64() = %d, want %d", got, tt.want)
			}
		})
	}
}

// errWriter fails every write, standing in for a closed pipe.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestWrite(t *testing.T) {
	t.Parallel()

	tok := &oauth2.Token{AccessToken: "ghs_x", Expiry: time.Now().Add(time.Hour)}

	tests := []struct {
		name    string
		asJSON  bool
		writer  io.Writer
		want    string
		wantErr bool
	}{
		{name: "bare token", asJSON: false, want: "ghs_x\n"},
		{name: "json envelope", asJSON: true, want: `"token":"ghs_x"`},
		{name: "bare token on a broken pipe", asJSON: false, writer: errWriter{}, wantErr: true},
		{name: "json on a broken pipe", asJSON: true, writer: errWriter{}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			w := tt.writer
			if w == nil {
				w = &buf
			}

			err := write(w, tok, tt.asJSON)
			if tt.wantErr {
				if err == nil {
					t.Fatal("write() = nil, want the writer's error")
				}
				return
			}
			if err != nil {
				t.Fatalf("write() error = %v", err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("write() wrote %q, want it to contain %q", buf.String(), tt.want)
			}
		})
	}
}

func TestUsageError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("inner")

	tests := []struct {
		name string
		err  error
		is   error
		want string
	}{
		{
			name: "unwraps to its cause",
			err:  usageError{err: fmt.Errorf("wrapped: %w", sentinel)},
			is:   sentinel,
			want: "wrapped: inner",
		},
		{
			name: "usagef formats",
			err:  usagef("set %s or %s, not both", "--a", "--b"),
			want: "set --a or --b, not both",
		},
		{
			name: "carries a flag parse error",
			err:  usageError{err: flag.ErrHelp, reported: true},
			is:   flag.ErrHelp,
			want: flag.ErrHelp.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
			if tt.is != nil && !errors.Is(tt.err, tt.is) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.is)
			}

			var ue usageError
			if !errors.As(tt.err, &ue) {
				t.Error("errors.As did not recover the usageError")
			}
		})
	}
}

// inClone runs the rest of the test in a fresh git clone whose origin is remote.
func inClone(t *testing.T, remote string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", remote}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
}

func TestParseRemote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		remote            string
		host, owner, repo string
		ok                bool
	}{
		{remote: "https://github.com/acme/api.git", host: "github.com", owner: "acme", repo: "api", ok: true},
		{remote: "https://github.com/acme/api", host: "github.com", owner: "acme", repo: "api", ok: true},
		{remote: "https://x-access-token:secret@github.com/acme/api.git", host: "github.com", owner: "acme", repo: "api", ok: true},
		{remote: "git@github.com:acme/api.git", host: "github.com", owner: "acme", repo: "api", ok: true},
		{remote: "github.com:acme/api", host: "github.com", owner: "acme", repo: "api", ok: true},
		{remote: "ssh://git@ghe.example.com:2222/acme/api.git", host: "ghe.example.com", owner: "acme", repo: "api", ok: true},
		{remote: "ssh://git@ssh.github.com:443/acme/api.git", host: "github.com", owner: "acme", repo: "api", ok: true},
		{remote: "https://octo.ghe.com/acme/api/", host: "octo.ghe.com", owner: "acme", repo: "api", ok: true},
		{remote: "https://github.com/acme"},
		{remote: "https://github.com/acme/api/tree/main"},
		{remote: "/srv/git/api.git"},
		{remote: "file:///srv/git/acme/api.git"},
		{remote: ""},
	}

	for _, tt := range tests {
		t.Run(tt.remote, func(t *testing.T) {
			t.Parallel()

			host, owner, repo, ok := parseRemote(tt.remote)
			if host != tt.host || owner != tt.owner || repo != tt.repo || ok != tt.ok {
				t.Errorf("parseRemote(%q) = %q, %q, %q, %v, want %q, %q, %q, %v",
					tt.remote, host, owner, repo, ok, tt.host, tt.owner, tt.repo, tt.ok)
			}
		})
	}
}
