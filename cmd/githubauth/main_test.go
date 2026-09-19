package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

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

func testKeyFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, testKeyPEM(t), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return path
}

// tokenServer stands in for the installation access token endpoint.
func tokenServer(t *testing.T, token string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      token,
			"expires_at": time.Now().Add(time.Hour),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{name: "no args prints usage", args: nil, wantCode: 2, wantErr: "githubauth mints"},
		{name: "help to stdout", args: []string{"help"}, wantCode: 0, wantOut: "githubauth mints"},
		{name: "-h to stdout", args: []string{"-h"}, wantCode: 0, wantOut: "githubauth mints"},
		{name: "unknown command", args: []string{"nope"}, wantCode: 2, wantErr: `unknown command "nope"`},
		{name: "flag error exits 2", args: []string{"jwt", "-nosuchflag"}, wantCode: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := run(tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Errorf("run() = %d, want %d", got, tt.wantCode)
			}
			if tt.wantOut != "" && !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantOut)
			}
			if tt.wantErr != "" && !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestJWTCommand(t *testing.T) {
	key := testKeyFile(t)

	t.Run("prints a signed JWT", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		if got := run([]string{"jwt", "-client-id", "Iv1.abc", "-key", key}, &stdout, &stderr); got != 0 {
			t.Fatalf("run() = %d, stderr = %s", got, stderr.String())
		}
		if parts := strings.Split(strings.TrimSpace(stdout.String()), "."); len(parts) != 3 {
			t.Errorf("got %d JWT segments, want 3", len(parts))
		}
	})

	t.Run("honours -expiry", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		if got := run([]string{"jwt", "-app-id", "42", "-key", key, "-expiry", "5m", "-json"}, &stdout, &stderr); got != 0 {
			t.Fatalf("run() = %d, stderr = %s", got, stderr.String())
		}

		var out struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("decoding output: %v", err)
		}
		// 5m less the 60s clock-drift backdate and the 30s refresh skew.
		if d := time.Until(out.ExpiresAt); d > 5*time.Minute || d < 3*time.Minute {
			t.Errorf("expiry in %v, want between 3m and 5m", d)
		}
	})
}

func TestTokenCommand(t *testing.T) {
	key := testKeyFile(t)
	srv := tokenServer(t, "ghs_installationtoken")

	t.Run("prints the installation token", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := run([]string{
			"token", "-client-id", "Iv1.abc", "-key", key,
			"-installation", "99", "-base-url", srv.URL,
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run() = %d, stderr = %s", code, stderr.String())
		}
		if got := strings.TrimSpace(stdout.String()); got != "ghs_installationtoken" {
			t.Errorf("stdout = %q, want the token", got)
		}
	})

	t.Run("scopes to repositories and emits JSON", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := run([]string{
			"token", "-app-id", "42", "-key", key,
			"-installation", "99", "-base-url", srv.URL,
			"-repos", "one, two ,", "-json",
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run() = %d, stderr = %s", code, stderr.String())
		}

		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("decoding output: %v", err)
		}
		if out.Token != "ghs_installationtoken" {
			t.Errorf("token = %q, want the token", out.Token)
		}
	})

	t.Run("reports an API failure", func(t *testing.T) {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(bad.Close)

		var stdout, stderr bytes.Buffer

		code := run([]string{
			"token", "-client-id", "Iv1.abc", "-key", key,
			"-installation", "99", "-base-url", bad.URL,
		}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("run() = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "githubauth:") {
			t.Errorf("stderr = %q, want a githubauth-prefixed error", stderr.String())
		}
	})
}

func TestArgumentErrors(t *testing.T) {
	key := testKeyFile(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "both identifiers",
			args: []string{"jwt", "-client-id", "Iv1.abc", "-app-id", "42", "-key", key},
			want: "not both",
		},
		{
			name: "no identifier",
			args: []string{"jwt", "-key", key},
			want: "missing App identifier",
		},
		{
			name: "no key",
			args: []string{"jwt", "-client-id", "Iv1.abc", "-key", ""},
			want: "missing private key",
		},
		{
			name: "no installation",
			args: []string{"token", "-client-id", "Iv1.abc", "-key", key},
			want: "missing installation ID",
		},
		{
			name: "both base URLs",
			args: []string{
				"token", "-client-id", "Iv1.abc", "-key", key, "-installation", "1",
				"-base-url", "https://a.example", "-enterprise-url", "https://b.example",
			},
			want: "not both",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := run(tt.args, &stdout, &stderr); got != 2 {
				t.Fatalf("run() = %d, want 2 for CLI misuse", got)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestUnreadableKeyExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// A path that does not resolve is an I/O failure, not CLI misuse.
	code := run([]string{"jwt", "-client-id", "Iv1.abc", "-key", "/no/such/key.pem"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "reading private key") {
		t.Errorf("stderr = %q, want it to name the failure", stderr.String())
	}
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Error("version printed nothing")
	}
}

func TestNearest(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"toekn", "token"},
		{"tok", "token"},
		{"jw", "jwt"},
		{"helpp", "help"},
		{"versoin", "version"},
		{"xyzzy", ""},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := nearest(tt.in); got != tt.want {
				t.Errorf("nearest(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUnknownCommandSuggests(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{"toekn"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `Did you mean "githubauth token"?`) {
		t.Errorf("stderr = %q, want a suggestion", stderr.String())
	}
}

func TestCommandHelpShowsExamples(t *testing.T) {
	for _, cmd := range []string{"token", "jwt"} {
		t.Run(cmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			// -h makes the flag package call fs.Usage, which writes to stderr.
			if code := run([]string{cmd, "-h"}, &stdout, &stderr); code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}

			help := stderr.String()
			for _, want := range []string{"USAGE", "FLAGS", "EXAMPLES", "--client-id string"} {
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

// Help must never echo a default, because every flag defaults to an
// environment variable and one of them holds the private key.
func TestHelpDoesNotLeakTheKey(t *testing.T) {
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(testKeyPEM(t)))

	var stdout, stderr bytes.Buffer
	run([]string{"token", "-h"}, &stdout, &stderr)

	if strings.Contains(stderr.String()+stdout.String(), "BEGIN RSA PRIVATE KEY") {
		t.Error("help output contains the private key")
	}
}

func TestReadKey(t *testing.T) {
	keyPEM := testKeyPEM(t)

	t.Run("inline PEM passes through", func(t *testing.T) {
		got, err := readKey(string(keyPEM), nil)
		if err != nil {
			t.Fatalf("readKey() error = %v", err)
		}
		if !bytes.Equal(got, keyPEM) {
			t.Error("readKey() did not return the inline PEM")
		}
	})

	t.Run("dash reads stdin", func(t *testing.T) {
		got, err := readKey("-", bytes.NewReader(keyPEM))
		if err != nil {
			t.Fatalf("readKey() error = %v", err)
		}
		if !bytes.Equal(got, keyPEM) {
			t.Error("readKey() did not return stdin")
		}
	})

	t.Run("path reads the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "k.pem")
		if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
			t.Fatalf("writing key: %v", err)
		}

		got, err := readKey(path, nil)
		if err != nil {
			t.Fatalf("readKey() error = %v", err)
		}
		if !bytes.Equal(got, keyPEM) {
			t.Error("readKey() did not return the file contents")
		}
	})
}

func TestSplitRepos(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",,", nil},
		{"one", []string{"one"}},
		{" one , two ,", []string{"one", "two"}},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
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

func TestEnvInt64(t *testing.T) {
	t.Setenv("GITHUBAUTH_TEST_INT", "42")
	if got := envInt64("GITHUBAUTH_TEST_INT"); got != 42 {
		t.Errorf("envInt64() = %d, want 42", got)
	}

	t.Setenv("GITHUBAUTH_TEST_INT", "not-a-number")
	if got := envInt64("GITHUBAUTH_TEST_INT"); got != 0 {
		t.Errorf("envInt64() = %d, want 0 for a malformed value", got)
	}
}

func TestEnvDefaults(t *testing.T) {
	t.Setenv("GITHUB_APP_CLIENT_ID", "Iv1.fromenv")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", string(testKeyPEM(t)))
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "77")

	srv := tokenServer(t, "ghs_fromenv")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"token", "-base-url", srv.URL}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, stderr = %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "ghs_fromenv" {
		t.Errorf("stdout = %q, want the token", got)
	}
}

func TestInvalidPEMExitsOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	for _, cmd := range [][]string{
		{"jwt", "-client-id", "Iv1.abc", "-key", path},
		{"token", "-client-id", "Iv1.abc", "-key", path, "-installation", "1"},
	} {
		t.Run(cmd[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := run(cmd, &stdout, &stderr); code != 1 {
				t.Fatalf("run() = %d, want 1", code)
			}
		})
	}
}

// errWriter fails every write, standing in for a closed pipe.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestWritePropagatesFailure(t *testing.T) {
	tok := &oauth2.Token{AccessToken: "ghs_x", Expiry: time.Now().Add(time.Hour)}

	for _, asJSON := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", asJSON), func(t *testing.T) {
			if err := write(errWriter{}, tok, asJSON); err == nil {
				t.Error("write() = nil, want the writer's error")
			}
		})
	}
}

func TestUsageErrorUnwraps(t *testing.T) {
	sentinel := errors.New("inner")
	err := error(usageError{err: fmt.Errorf("wrapped: %w", sentinel)})

	if !errors.Is(err, sentinel) {
		t.Error("usageError does not unwrap to its cause")
	}

	var ue usageError
	if !errors.As(err, &ue) {
		t.Error("usageError is not recoverable with errors.As")
	}
}
