package main

import (
	"bytes"
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
	"path/filepath"
	"strings"
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

// tokenHandler stands in for the installation access token endpoint.
func tokenHandler(token string) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
			wantStderr: `Did you mean "githubauth token"?`,
		},
		{
			name:       "unrecognisable command offers help",
			args:       func(string) []string { return []string{"xyzzy"} },
			wantCode:   2,
			wantStdout: isEmpty,
			wantStderr: `Run "githubauth help" for usage.`,
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
			wantCode:    1,
			wantStdout:  isEmpty,
			wantStderr:  "githubauth:",
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
			name:       "an unreadable key is a runtime failure, not misuse",
			args:       func(string) []string { return []string{"jwt", "--client-id", "Iv1.abc", "--key", "/no/such/key.pem"} },
			wantCode:   1,
			wantStdout: isEmpty,
			wantStderr: "reading private key",
		},
		{
			name:       "a malformed PEM is a runtime failure",
			args:       func(string) []string { return []string{"jwt", "--client-id", "Iv1.abc", "--key", badKeyPath} },
			wantCode:   1,
			wantStdout: isEmpty,
			wantStderr: "githubauth:",
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
		})
	}
}

// TestCommandHelp covers the per-command help, which the flag package writes
// to stderr and which exits 2 because -h is reported as a parse error.
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
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)

			var stdout, stderr bytes.Buffer

			if got := run([]string{tt.command, "-h"}, nil, &stdout, &stderr); got != 2 {
				t.Errorf("run() = %d, want 2", got)
			}

			help := stderr.String()
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
