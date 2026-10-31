package githubauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func Test_githubClient_withEnterpriseURL(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		wantErr     bool
		wantBaseURL string
	}{
		{
			name:        "valid URL with first subdomain",
			baseURL:     "https://api.github.example.com",
			wantErr:     false,
			wantBaseURL: "https://api.github.example.com/",
		},
		{
			name:        "valid URL with first subdomain and trailing slash",
			baseURL:     "https://api.github.example.com/",
			wantErr:     false,
			wantBaseURL: "https://api.github.example.com/",
		},
		{
			name:        "valid URL with second subdomain",
			baseURL:     "https://ghes.api.example.com",
			wantErr:     false,
			wantBaseURL: "https://ghes.api.example.com/",
		},
		{
			name:        "valid URL with second subdomain and trailing slash",
			baseURL:     "https://ghes.api.example.com/",
			wantErr:     false,
			wantBaseURL: "https://ghes.api.example.com/",
		},
		{
			name:        "valid URL with path",
			baseURL:     "https://github.example.com/api/v3",
			wantErr:     false,
			wantBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:        "valid URL with path and trailing slash",
			baseURL:     "https://github.example.com/api/v3/",
			wantErr:     false,
			wantBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:        "valid URL without path",
			baseURL:     "https://github.example.com",
			wantErr:     false,
			wantBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:        "valid URL without path but with trailing slash",
			baseURL:     "https://github.example.com/",
			wantErr:     false,
			wantBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:        "invalid URL with control characters",
			baseURL:     "ht\ntp://invalid",
			wantErr:     true,
			wantBaseURL: "",
		},
		{
			name:        "URL with spaces",
			baseURL:     "http://invalid url with spaces",
			wantErr:     true,
			wantBaseURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newGitHubClient(&http.Client{})
			err := client.withEnterpriseURL(tt.baseURL)

			if (err != nil) != tt.wantErr {
				t.Errorf("withEnterpriseURL(%q) error = %v, wantErr %v", tt.baseURL, err, tt.wantErr)
			}
			if err == nil && client.baseURL.String() != tt.wantBaseURL {
				t.Errorf("withEnterpriseURL(%q).baseURL = %q, want %q", tt.baseURL, client.baseURL, tt.wantBaseURL)
			}
		})
	}
}

func Test_githubClient_withBaseURL(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		wantErr     bool
		wantBaseURL string
	}{
		{
			name:        "GHEC data residency URL is used verbatim",
			baseURL:     "https://api.octocorp.ghe.com",
			wantErr:     false,
			wantBaseURL: "https://api.octocorp.ghe.com/",
		},
		{
			name:        "GHEC data residency URL with trailing slash",
			baseURL:     "https://api.octocorp.ghe.com/",
			wantErr:     false,
			wantBaseURL: "https://api.octocorp.ghe.com/",
		},
		{
			name:        "plain host without /api/v3 suffix appended",
			baseURL:     "https://github.example.com",
			wantErr:     false,
			wantBaseURL: "https://github.example.com/",
		},
		{
			name:        "existing path is preserved without /api/v3 munging",
			baseURL:     "https://github.example.com/api/v3",
			wantErr:     false,
			wantBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:        "httptest-style host and port used verbatim",
			baseURL:     "http://127.0.0.1:8080",
			wantErr:     false,
			wantBaseURL: "http://127.0.0.1:8080/",
		},
		{
			name:        "invalid URL with control characters",
			baseURL:     "ht\ntp://invalid",
			wantErr:     true,
			wantBaseURL: "",
		},
		{
			name:        "URL with spaces",
			baseURL:     "http://invalid url with spaces",
			wantErr:     true,
			wantBaseURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newGitHubClient(&http.Client{})
			err := client.withBaseURL(tt.baseURL)

			if (err != nil) != tt.wantErr {
				t.Errorf("withBaseURL(%q) error = %v, wantErr %v", tt.baseURL, err, tt.wantErr)
			}
			if err == nil && client.baseURL.String() != tt.wantBaseURL {
				t.Errorf("withBaseURL(%q).baseURL = %q, want %q", tt.baseURL, client.baseURL, tt.wantBaseURL)
			}
		})
	}
}

func Test_githubClient_createInstallationToken_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		setupServer    func() *httptest.Server
		opts           *InstallationTokenOptions
		wantErr        bool
		errorSubstring string
	}{
		{
			name: "options are marshaled into a successful request",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(InstallationToken{
						Token:     "test-token",
						ExpiresAt: time.Now().Add(1 * time.Hour),
					})
				}))
			},
			opts: &InstallationTokenOptions{
				Repositories: []string{"repo1"},
			},
			wantErr: false,
		},
		{
			name: "bad request - 400",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"Bad Request"}`))
				}))
			},
			opts:           nil,
			wantErr:        true,
			errorSubstring: "400",
		},
		{
			name: "unauthorized - 401",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
				}))
			},
			opts:           nil,
			wantErr:        true,
			errorSubstring: "401",
		},
		{
			name: "forbidden - 403",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
				}))
			},
			opts:           nil,
			wantErr:        true,
			errorSubstring: "403",
		},
		{
			name: "not found - 404",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				}))
			},
			opts:           nil,
			wantErr:        true,
			errorSubstring: "404",
		},
		{
			name: "invalid JSON response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{invalid json`))
				}))
			},
			opts:           nil,
			wantErr:        true,
			errorSubstring: "failed to decode response",
		},
		{
			name: "success with nil options",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(InstallationToken{
						Token:     "test-token",
						ExpiresAt: time.Now().Add(1 * time.Hour),
					})
				}))
			},
			opts:    nil,
			wantErr: false,
		},
		{
			name: "success with HTTP 200",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(InstallationToken{
						Token:     "test-token",
						ExpiresAt: time.Now().Add(1 * time.Hour),
					})
				}))
			},
			opts:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			client := newGitHubClient(&http.Client{})
			client.baseURL, _ = client.baseURL.Parse(server.URL)

			_, err := client.createInstallationToken(context.Background(), 12345, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("createInstallationToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errorSubstring != "" {
				if err == nil {
					t.Errorf("createInstallationToken() error = nil, want one containing %q", tt.errorSubstring)
				} else if !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Errorf("createInstallationToken() error = %q, want it to contain %q", err, tt.errorSubstring)
				}
			}
		})
	}
}

func TestPtr(t *testing.T) {
	t.Run("string pointer", func(t *testing.T) {
		s := "test"
		p := Ptr(s)
		if p == nil {
			t.Fatal("Ptr() returned nil")
		}
		if *p != s {
			t.Errorf("Ptr() = %v, want %v", *p, s)
		}
	})

	t.Run("int pointer", func(t *testing.T) {
		i := 42
		p := Ptr(i)
		if p == nil {
			t.Fatal("Ptr() returned nil")
		}
		if *p != i {
			t.Errorf("Ptr() = %v, want %v", *p, i)
		}
	})

	t.Run("int64 pointer", func(t *testing.T) {
		i := int64(123456)
		p := Ptr(i)
		if p == nil {
			t.Fatal("Ptr() returned nil")
		}
		if *p != i {
			t.Errorf("Ptr() = %v, want %v", *p, i)
		}
	})
}

// roundTripperFunc adapts a function to http.RoundTripper so a transport can
// fail without standing up a server.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Test_doCreateInstallationToken_RequestErrors covers the two failures of a
// single POST attempt that never produce a response: a URL net/url refuses, and
// a transport that fails the round trip. They are driven through
// doCreateInstallationToken directly because createInstallationToken builds its
// URL with url.URL.JoinPath and therefore cannot produce an unusable one.
func Test_doCreateInstallationToken_RequestErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport http.RoundTripper
		reqURL    string
		want      string
	}{
		{
			// DEL is a control character net/url rejects, so http.NewRequest
			// fails and no connection is ever attempted.
			name:   "URL carrying a control character",
			reqURL: "http://example.invalid/app/installations/1/access_tokens\x7f",
			want:   "failed to create request",
		},
		{
			name: "transport fails the round trip",
			transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("connection refused")
			}),
			reqURL: "http://example.invalid/app/installations/1/access_tokens",
			want:   "failed to execute request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := newGitHubClient(&http.Client{Transport: tt.transport})

			tok, err := c.doCreateInstallationToken(context.Background(), tt.reqURL, nil)
			if err == nil {
				t.Fatalf("doCreateInstallationToken() err = nil, want an error containing %q", tt.want)
			}
			if tok != nil {
				t.Errorf("token = %+v, want nil", tok)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// Test_createInstallationToken_EndpointURL pins the path the client POSTs to.
// The endpoint is joined onto the base with url.URL.JoinPath, so an Enterprise
// base path such as /api/v3/ has to survive rather than be resolved away the
// way a relative reference would resolve it.
func Test_createInstallationToken_EndpointURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		basePath string // appended to the httptest server URL
		wantPath string
	}{
		{
			name:     "root base path",
			basePath: "/",
			wantPath: "/app/installations/12345/access_tokens",
		},
		{
			name:     "enterprise base path",
			basePath: "/api/v3/",
			wantPath: "/api/v3/app/installations/12345/access_tokens",
		},
		{
			name:     "nested base path",
			basePath: "/gh/api/v3/",
			wantPath: "/gh/api/v3/app/installations/12345/access_tokens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotPath := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath <- r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(InstallationToken{
					Token:     "test-token",
					ExpiresAt: time.Now().Add(time.Hour),
				})
			}))
			defer server.Close()

			c := newGitHubClient(&http.Client{})
			if err := c.withBaseURL(server.URL + tt.basePath); err != nil {
				t.Fatalf("withBaseURL(%q): %v", tt.basePath, err)
			}

			if _, err := c.createInstallationToken(context.Background(), 12345, nil); err != nil {
				t.Fatalf("createInstallationToken() err = %v", err)
			}

			select {
			case got := <-gotPath:
				if got != tt.wantPath {
					t.Errorf("request path = %q, want %q", got, tt.wantPath)
				}
			default:
				t.Fatal("server received no request")
			}
		})
	}
}

// Test_createInstallationToken_SendsOptionsBody proves InstallationTokenOptions
// reach GitHub as the JSON request body, and that a nil options value sends no
// body at all rather than a JSON "null".
func Test_createInstallationToken_SendsOptionsBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     *InstallationTokenOptions
		wantBody string
	}{
		{
			name:     "nil options send no body",
			opts:     nil,
			wantBody: "",
		},
		{
			name: "options are marshaled into the body",
			opts: &InstallationTokenOptions{
				Repositories: []string{"repo1", "repo2"},
				Permissions: &InstallationPermissions{
					Contents: Ptr("read"),
					Issues:   Ptr("write"),
				},
			},
			wantBody: `{"repositories":["repo1","repo2"],"permissions":{"contents":"read","issues":"write"}}`,
		},
		{
			name: "a permission with no field is sent with the others",
			opts: &InstallationTokenOptions{
				Permissions: &InstallationPermissions{
					Contents: Ptr("read"),
					Other:    map[string]string{"installation_repositories": "write"},
				},
			},
			wantBody: `{"permissions":{"contents":"read","installation_repositories":"write"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotBody := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
				}
				gotBody <- string(b)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(InstallationToken{
					Token:     "test-token",
					ExpiresAt: time.Now().Add(time.Hour),
				})
			}))
			defer server.Close()

			client := newClientForServer(t, server)

			tok, err := client.createInstallationToken(context.Background(), 12345, tt.opts)
			if err != nil {
				t.Fatalf("createInstallationToken() err = %v", err)
			}
			if tok.Token != "test-token" {
				t.Errorf("token = %q, want %q", tok.Token, "test-token")
			}

			select {
			case got := <-gotBody:
				// Compared as JSON: key order and spacing are not the contract.
				if !sameJSON(got, tt.wantBody) {
					t.Errorf("request body = %s, want %s", got, tt.wantBody)
				}
			default:
				t.Fatal("server received no request")
			}
		})
	}
}

// throttleResponse programs one hit on throttleHandler. A response is emitted
// per call, indexed by attempt count; exceeding the list replays the last entry.
type throttleResponse struct {
	status     int
	headers    map[string]string
	body       string
	writeToken bool // serialize an InstallationToken JSON body instead of body
}

// throttleHandler answers each request with the next of responses, starting
// over once they run out, and counts the requests in attempts.
func throttleHandler(responses []throttleResponse, attempts *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		idx := int(n-1) % len(responses)
		r := responses[idx]
		for k, v := range r.headers {
			w.Header().Set(k, v)
		}
		if r.writeToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(r.status)
			_ = json.NewEncoder(w).Encode(InstallationToken{
				Token:     "test-token",
				ExpiresAt: time.Now().Add(time.Hour),
			})
			return
		}
		w.WriteHeader(r.status)
		if r.body != "" {
			_, _ = w.Write([]byte(r.body))
		}
	}
}

func newClientForServer(t *testing.T, server *httptest.Server) *githubClient {
	t.Helper()
	c := newGitHubClient(&http.Client{Timeout: 10 * time.Second})
	if err := c.withBaseURL(server.URL); err != nil {
		t.Fatalf("withBaseURL(%q) error = %v", server.URL, err)
	}
	return c
}

// recordSleeps makes c note each throttle wait instead of sleeping through it,
// so a test asserts the wait it asked for rather than the time that passed.
func recordSleeps(c *githubClient) *[]time.Duration {
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	return &waits
}

func Test_createInstallationToken_RetryOnThrottle(t *testing.T) {
	tests := []struct {
		name          string
		responses     []throttleResponse
		retryEnabled  bool
		wantAttempts  int32
		wantErr       bool
		wantRateLimit bool
		wantWaits     []time.Duration
	}{
		{
			name: "429 with Retry-After=1 retries and succeeds",
			responses: []throttleResponse{
				{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "1"}, body: `{"message":"rate limited"}`},
				{status: http.StatusCreated, writeToken: true},
			},
			retryEnabled: true,
			wantAttempts: 2,
			wantErr:      false,
			wantWaits:    []time.Duration{time.Second},
		},
		{
			name: "429 without Retry-After uses default 1s backoff",
			responses: []throttleResponse{
				{status: http.StatusTooManyRequests, body: `{"message":"rate limited"}`},
				{status: http.StatusCreated, writeToken: true},
			},
			retryEnabled: true,
			wantAttempts: 2,
			wantErr:      false,
			wantWaits:    []time.Duration{time.Second},
		},
		{
			name: "two consecutive 429s retry once then fail",
			responses: []throttleResponse{
				{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "0"}, body: `{"message":"first"}`},
				{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "0"}, body: `{"message":"second"}`},
			},
			retryEnabled:  true,
			wantAttempts:  2,
			wantErr:       true,
			wantRateLimit: true,
			wantWaits:     []time.Duration{0},
		},
		{
			name: "WithRetryOnThrottle(false) disables retry",
			responses: []throttleResponse{
				{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "0"}, body: `{"message":"no retry"}`},
				{status: http.StatusCreated, writeToken: true},
			},
			retryEnabled:  false,
			wantAttempts:  1,
			wantErr:       true,
			wantRateLimit: true,
		},
		{
			name: "403 without retry headers is not retried",
			responses: []throttleResponse{
				{status: http.StatusForbidden, body: `{"message":"forbidden"}`},
			},
			retryEnabled: true,
			wantAttempts: 1,
			wantErr:      true,
		},
		{
			name: "403 with unparseable Retry-After is not retried",
			responses: []throttleResponse{
				{status: http.StatusForbidden, headers: map[string]string{"Retry-After": "not-a-date"}, body: `{"message":"forbidden"}`},
			},
			retryEnabled: true,
			wantAttempts: 1,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(throttleHandler(tt.responses, &attempts))
			defer server.Close()

			client := newClientForServer(t, server)
			client.retryOnThrottle = tt.retryEnabled
			waits := recordSleeps(client)

			_, err := client.createInstallationToken(context.Background(), 12345, nil)

			if got := attempts.Load(); got != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", got, tt.wantAttempts)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantRateLimit && !errors.Is(err, ErrRateLimited) {
				t.Errorf("err = %v, want errors.Is(err, ErrRateLimited)", err)
			}
			if !slices.Equal(*waits, tt.wantWaits) {
				t.Errorf("waits = %v, want %v", *waits, tt.wantWaits)
			}
		})
	}
}

func Test_createInstallationToken_XRateLimitReset(t *testing.T) {
	// x-ratelimit-reset is a Unix-second epoch, computed at request time.
	// x-ratelimit-remaining is 0 because that is what marks a 403 as throttled
	// rather than terminal; see Test_createInstallationToken_403PermissionNotThrottled.
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(3*time.Second).Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(InstallationToken{
			Token:     "test-token",
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	defer server.Close()

	client := newClientForServer(t, server)
	waits := recordSleeps(client)

	tok, err := client.createInstallationToken(context.Background(), 12345, nil)

	if err != nil {
		t.Fatalf("createInstallationToken err = %v", err)
	}
	if tok == nil || tok.Token != "test-token" {
		t.Errorf("token = %+v, want Token=\"test-token\"", tok)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	// Reset is now+3s, and Unix() truncates up to 1s, so the wait is 2-3s.
	if len(*waits) != 1 || (*waits)[0] < 1500*time.Millisecond || (*waits)[0] > 3*time.Second {
		t.Errorf("waits = %v, want one wait of 2-3s, until the reset", *waits)
	}
}

// Test_throttleDelay_KeepsGitHubsFullWait pins RetryAfter to GitHub's own hint.
// Capping it told callers running their own backoff to come back long before
// GitHub would accept the request.
func Test_throttleDelay_KeepsGitHubsFullWait(t *testing.T) {
	c := newGitHubClient(&http.Client{})
	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"600"}},
	}
	d, ok := c.throttleDelay(resp, nil)
	if !ok {
		t.Fatalf("throttleDelay ok = false, want true")
	}
	if d != 600*time.Second {
		t.Errorf("delay = %v, want 10m0s", d)
	}

	resp = &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{time.Now().Add(1 * time.Hour).UTC().Format(http.TimeFormat)}},
	}
	d, ok = c.throttleDelay(resp, nil)
	if !ok {
		t.Fatalf("throttleDelay ok = false, want true")
	}
	if d < 59*time.Minute {
		t.Errorf("HTTP-date delay = %v, want about 1h", d)
	}

	// A caller may sleep on RetryAfter, so a hostile hint is capped.
	resp = &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"31536000"}},
	}
	if d, _ = c.throttleDelay(resp, nil); d != maxRetryAfter {
		t.Errorf("a year-long hint gave delay = %v, want %v", d, maxRetryAfter)
	}
}

// Test_createInstallationToken_LongWaitIsNotSleptThrough proves a hint past
// maxRetrySleep returns at once with the full wait, instead of sleeping 60s
// for a retry GitHub is bound to refuse.
func Test_createInstallationToken_LongWaitIsNotSleptThrough(t *testing.T) {
	var attempts atomic.Int32
	reset := strconv.FormatInt(time.Now().Add(40*time.Minute).Unix(), 10)
	server := httptest.NewServer(throttleHandler([]throttleResponse{
		{
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset},
			body:    `{"message":"API rate limit exceeded"}`,
		},
	}, &attempts))
	defer server.Close()

	client := newClientForServer(t, server)
	waits := recordSleeps(client)
	_, err := client.createInstallationToken(context.Background(), 12345, nil)

	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	if rle.RetryAfter < 39*time.Minute {
		t.Errorf("RetryAfter = %v, want about 40m", rle.RetryAfter)
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
	if len(*waits) != 0 {
		t.Errorf("waits = %v, want none: a wait past the cap is returned, not slept", *waits)
	}
}

func Test_createInstallationToken_ContextCancelledDuringSleep(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(throttleHandler([]throttleResponse{
		{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "30"}, body: `{"message":"rate limited"}`},
	}, &attempts))
	defer server.Close()

	client := newClientForServer(t, server)

	// Cancelled from inside the wait, so the cancellation always lands there
	// rather than before or after it, as a timer would allow.
	ctx, cancel := context.WithCancel(context.Background())
	client.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return sleepCtx(ctx, d)
	}

	_, err := client.createInstallationToken(ctx, 12345, nil)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want it to still wrap ErrRateLimited", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (no retry after cancellation)", got)
	}
}

func Test_parseRetryAfter(t *testing.T) {
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{name: "integer seconds", value: "5", want: 5 * time.Second, wantOK: true},
		{name: "integer seconds with whitespace", value: " 7 ", want: 7 * time.Second, wantOK: true},
		// Multiplied uncapped, these overflowed to a negative "retry now".
		{name: "seconds past the cap", value: "9223372036854775807", want: maxRetryAfter, wantOK: true},
		{name: "negative seconds past the cap", value: "-9223372036854775808", want: -maxRetryAfter, wantOK: true},
		{name: "zero seconds", value: "0", want: 0, wantOK: true},
		{name: "negative seconds", value: "-3", want: -3 * time.Second, wantOK: true},
		{name: "HTTP-date future", value: now.Add(10 * time.Second).Format(http.TimeFormat), want: 10 * time.Second, wantOK: true},
		{name: "HTTP-date past", value: now.Add(-10 * time.Second).Format(http.TimeFormat), want: -10 * time.Second, wantOK: true},
		{name: "unparseable reports not-ok", value: "not-a-date", want: 0, wantOK: false},
		{name: "empty reports not-ok", value: "", want: 0, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("parseRetryAfter(%q) = (%v, %v), want (%v, %v)", tt.value, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func Test_throttleDelay_NonThrottledStatus(t *testing.T) {
	c := newGitHubClient(&http.Client{})
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusBadRequest, http.StatusInternalServerError} {
		resp := &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"5"}}}
		if d, ok := c.throttleDelay(resp, nil); ok || d != 0 {
			t.Errorf("status %d: got (%v, %v), want (0, false)", status, d, ok)
		}
	}
}

func TestWithRetryOnThrottle_AffectsSource(t *testing.T) {
	// A full installationTokenSource.Token() through a throttled server shows
	// the option reaches the client.
	tests := []struct {
		name         string
		retry        bool
		wantAttempts int32
		wantErr      bool
	}{
		{name: "retry on", retry: true, wantAttempts: 2},
		{name: "retry off", retry: false, wantAttempts: 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(throttleHandler([]throttleResponse{
				{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "0"}, body: `{"message":"first"}`},
				{status: http.StatusCreated, writeToken: true},
			}, &attempts))
			defer server.Close()

			ts := NewInstallationTokenSource(42, oauth2StaticSource{accessToken: "jwt"},
				WithEnterpriseURL(server.URL),
				WithRetryOnThrottle(tt.retry),
			)
			tok, err := ts.Token()

			if tt.wantErr {
				if !errors.Is(err, ErrRateLimited) {
					t.Errorf("Token() error = %v, want errors.Is(err, ErrRateLimited)", err)
				}
			} else if err != nil || tok.AccessToken != "test-token" {
				t.Errorf("Token() = %v, %v, want test-token", tok, err)
			}
			if got := attempts.Load(); got != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", got, tt.wantAttempts)
			}
		})
	}
}

// oauth2StaticSource is a minimal oauth2.TokenSource emitting a fixed JWT so
// the installation-token POST can authenticate against the mock server.
type oauth2StaticSource struct {
	accessToken string
}

func (s oauth2StaticSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: s.accessToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

// Test_createInstallationToken_TokenFormats pins the contract that the
// installation token is carried through verbatim as an opaque string. GitHub is
// migrating installation tokens to a stateless "ghs_"-prefixed JWT that is much
// longer (~520 characters) and contains two dots, alongside the classic short
// opaque form. Neither is parsed, validated, or length-checked by this package,
// and this test exists to keep it that way.
//
// See https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header/
func Test_createInstallationToken_TokenFormats(t *testing.T) {
	// A stateless token: "ghs_" + three JWT segments, 520 characters total.
	statelessToken := "ghs_" + strings.Repeat("a", 171) + "." + strings.Repeat("b", 171) + "." + strings.Repeat("c", 172)

	tests := []struct {
		name     string
		token    string
		wantLen  int
		wantDots int
	}{
		{
			name:     "stateless JWT format",
			token:    statelessToken,
			wantLen:  520,
			wantDots: 2,
		},
		{
			name:     "stateful opaque format",
			token:    "ghs_16C7e42F292c6912E7710c838347Ae178B4a",
			wantLen:  40,
			wantDots: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Guard the fixtures themselves so a typo cannot weaken the test.
			if len(tt.token) != tt.wantLen {
				t.Fatalf("fixture length = %d, want %d", len(tt.token), tt.wantLen)
			}
			if got := strings.Count(tt.token, "."); got != tt.wantDots {
				t.Fatalf("fixture dots = %d, want %d", got, tt.wantDots)
			}

			expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"token":      tt.token,
					"expires_at": expiresAt.Format(time.RFC3339),
				})
			}))
			defer server.Close()

			ts := NewInstallationTokenSource(42, oauth2StaticSource{accessToken: "jwt"},
				WithBaseURL(server.URL),
			)

			tok, err := ts.Token()
			if err != nil {
				t.Fatalf("Token() err = %v", err)
			}

			if tok.AccessToken != tt.token {
				t.Errorf("AccessToken = %q (len %d), want %q (len %d)",
					tok.AccessToken, len(tok.AccessToken), tt.token, len(tt.token))
			}

			// Expiry must come from the expires_at field, never from the token
			// body — a stateless token is a JWT with its own exp claim, which
			// this package deliberately does not read.
			if !tok.Expiry.Equal(expiresAt) {
				t.Errorf("Expiry = %v, want %v", tok.Expiry, expiresAt)
			}
		})
	}
}

// Test_createInstallationToken_403PermissionNotThrottled pins the distinction
// between a throttled 403 and a terminal permission 403.
//
// GitHub attaches X-RateLimit-Limit / X-RateLimit-Remaining / X-RateLimit-Reset
// to essentially every authenticated REST response, including terminal failures
// such as 403 {"message":"Resource not accessible by integration"}. Those carry
// a healthy X-RateLimit-Remaining and a reset epoch up to an hour out, so the
// reset header alone must never make a 403 retryable: doing so stalls the caller
// for up to maxRetrySleep and then reports ErrRateLimited for what is really a
// permissions problem.
//
// A 403 is throttled only when Retry-After is present or X-RateLimit-Remaining
// is exactly "0". 429 keeps its existing behaviour.
func Test_createInstallationToken_403PermissionNotThrottled(t *testing.T) {
	// Computed once here; the server replays it milliseconds later.
	futureReset := strconv.FormatInt(time.Now().Add(5*time.Second).Unix(), 10)
	pastReset := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)

	tests := []struct {
		name          string
		responses     []throttleResponse
		wantAttempts  int32
		wantErr       bool
		wantRateLimit bool
	}{
		{
			name: "403 permission error with healthy remaining is terminal",
			responses: []throttleResponse{
				{
					status: http.StatusForbidden,
					headers: map[string]string{
						"X-RateLimit-Limit":     "5000",
						"X-RateLimit-Remaining": "4999",
						"X-RateLimit-Reset":     futureReset,
					},
					body: `{"message":"Resource not accessible by integration"}`,
				},
			},
			wantAttempts:  1,
			wantErr:       true,
			wantRateLimit: false,
		},
		{
			name: "403 with exhausted remaining is still throttled",
			responses: []throttleResponse{
				{
					status: http.StatusForbidden,
					headers: map[string]string{
						"X-RateLimit-Limit":     "5000",
						"X-RateLimit-Remaining": "0",
						"X-RateLimit-Reset":     pastReset,
					},
					body: `{"message":"API rate limit exceeded"}`,
				},
				{status: http.StatusCreated, writeToken: true},
			},
			wantAttempts: 2,
			wantErr:      false,
		},
		{
			name: "403 with Retry-After is still throttled",
			responses: []throttleResponse{
				{
					status:  http.StatusForbidden,
					headers: map[string]string{"Retry-After": "0"},
					body:    `{"message":"You have exceeded a secondary rate limit"}`,
				},
				{status: http.StatusCreated, writeToken: true},
			},
			wantAttempts: 2,
			wantErr:      false,
		},
		{
			name: "429 without hint headers is still throttled",
			responses: []throttleResponse{
				{status: http.StatusTooManyRequests, body: `{"message":"rate limited"}`},
				{status: http.StatusCreated, writeToken: true},
			},
			wantAttempts: 2,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(throttleHandler(tt.responses, &attempts))
			defer server.Close()

			client := newClientForServer(t, server)
			recordSleeps(client)

			_, err := client.createInstallationToken(context.Background(), 12345, nil)

			if got := attempts.Load(); got != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", got, tt.wantAttempts)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if got := errors.Is(err, ErrRateLimited); got != tt.wantRateLimit {
				t.Errorf("errors.Is(err, ErrRateLimited) = %v, want %v (err = %v)", got, tt.wantRateLimit, err)
			}
		})
	}
}

// Test_throttleDelay_403Classification pins which 403s count as rate limiting.
// GitHub attaches X-RateLimit-* headers to essentially every authenticated
// response, so header presence alone proves nothing: a permission failure
// carries a healthy budget and a reset epoch up to an hour out. What does
// distinguish a rate limit is an exhausted budget, a Retry-After, or GitHub
// saying so in the message — the last matters because a secondary rate limit
// can arrive with a healthy primary budget and no Retry-After.
func Test_throttleDelay_403Classification(t *testing.T) {
	future := strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10)

	tests := []struct {
		name      string
		headers   map[string]string
		body      string
		wantRetry bool
	}{
		{
			name:      "permission failure with healthy budget is terminal",
			headers:   map[string]string{"X-RateLimit-Remaining": "4999", "X-RateLimit-Reset": future},
			body:      `{"message":"Resource not accessible by integration"}`,
			wantRetry: false,
		},
		{
			name:      "secondary rate limit with healthy budget and no hint is throttled",
			headers:   map[string]string{"X-RateLimit-Remaining": "4321", "X-RateLimit-Reset": future},
			body:      `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`,
			wantRetry: true,
		},
		{
			name:      "exhausted budget without a reset header is still throttled",
			headers:   map[string]string{"X-RateLimit-Remaining": "0"},
			body:      `{"message":"API rate limit exceeded"}`,
			wantRetry: true,
		},
		{
			name:      "non-canonical zero budget is read numerically",
			headers:   map[string]string{"X-RateLimit-Remaining": "00", "X-RateLimit-Reset": future},
			body:      `{"message":"Forbidden"}`,
			wantRetry: true,
		},
		{
			name:      "no rate-limit headers at all is terminal",
			headers:   map[string]string{},
			body:      `{"message":"Resource not accessible by integration"}`,
			wantRetry: false,
		},
		{
			name:      "Retry-After wins regardless of budget or message",
			headers:   map[string]string{"Retry-After": "1", "X-RateLimit-Remaining": "4999"},
			body:      `{"message":"Resource not accessible by integration"}`,
			wantRetry: true,
		},
	}

	c := newGitHubClient(&http.Client{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			delay, retry := c.throttleDelay(resp, []byte(tt.body))
			if retry != tt.wantRetry {
				t.Fatalf("throttleDelay() retryable = %v, want %v", retry, tt.wantRetry)
			}
			if retry && delay <= 0 {
				t.Errorf("throttleDelay() delay = %v, want a positive wait when retryable", delay)
			}
			if !retry && delay != 0 {
				t.Errorf("throttleDelay() delay = %v, want 0 when terminal", delay)
			}
		})
	}
}

// Test_throttleDelay_HintlessRateLimit403WaitsAMinute pins the fallback for a
// 403 identified as a rate limit that carries no usable hint. GitHub's guidance
// for that case is to wait at least a minute, not the 1s used for a bare 429.
func Test_throttleDelay_HintlessRateLimit403WaitsAMinute(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
	resp.Header.Set("X-RateLimit-Remaining", "0")

	delay, retry := newGitHubClient(&http.Client{}).throttleDelay(resp, []byte(`{"message":"API rate limit exceeded"}`))
	if !retry {
		t.Fatal("throttleDelay() retryable = false, want true")
	}
	if delay != secondaryRateLimitBackoff {
		t.Errorf("delay = %v, want %v", delay, secondaryRateLimitBackoff)
	}
}

// TestRateLimitError_CarriesRetryHint covers the reason the type exists: a
// caller running its own backoff can read the wait the client already computed
// from GitHub's headers, instead of re-parsing the response it never sees.
func TestRateLimitError_CarriesRetryHint(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		headers        map[string]string
		body           string
		wantRetryAfter time.Duration
	}{
		{
			name:           "Retry-After drives the wait",
			status:         http.StatusTooManyRequests,
			headers:        map[string]string{"Retry-After": "7"},
			body:           `{"message":"Too Many Requests"}`,
			wantRetryAfter: 7 * time.Second,
		},
		{
			name:           "a bare 429 falls back to the default backoff",
			status:         http.StatusTooManyRequests,
			headers:        map[string]string{},
			body:           `{"message":"Too Many Requests"}`,
			wantRetryAfter: defaultThrottleBackoff,
		},
		{
			name:           "a hintless rate-limit 403 falls back to a minute",
			status:         http.StatusForbidden,
			headers:        map[string]string{"X-RateLimit-Remaining": "0"},
			body:           `{"message":"API rate limit exceeded"}`,
			wantRetryAfter: secondaryRateLimitBackoff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tt.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			c := newClientForServer(t, server)
			c.retryOnThrottle = false // one attempt, so the first error surfaces

			_, err := c.createInstallationToken(context.Background(), 42, nil)
			if err == nil {
				t.Fatal("createInstallationToken() err = nil, want a rate-limit error")
			}

			var rle *RateLimitError
			if !errors.As(err, &rle) {
				t.Fatalf("errors.As(*RateLimitError) = false for %T: %v", err, err)
			}
			if rle.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", rle.StatusCode, tt.status)
			}
			if rle.RetryAfter != tt.wantRetryAfter {
				t.Errorf("RetryAfter = %v, want %v", rle.RetryAfter, tt.wantRetryAfter)
			}
			if rle.Message != tt.body {
				t.Errorf("Message = %q, want %q", rle.Message, tt.body)
			}

			// The sentinel remains the documented way to branch.
			if !errors.Is(err, ErrRateLimited) {
				t.Error("errors.Is(err, ErrRateLimited) = false; the sentinel contract is broken")
			}
		})
	}
}

// TestRateLimitError_MessageFormat pins the rendered message. Callers log and
// match on it, so introducing the type must not reword it.
func TestRateLimitError_MessageFormat(t *testing.T) {
	err := &RateLimitError{
		StatusCode: http.StatusForbidden,
		RetryAfter: time.Second,
		Message:    `{"message":"API rate limit exceeded"}`,
	}

	want := `github API rate limited: GitHub API returned status 403: {"message":"API rate limit exceeded"}`
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n  %q\nwant\n  %q", got, want)
	}

	if !errors.Is(err, ErrRateLimited) {
		t.Error("errors.Is(err, ErrRateLimited) = false")
	}
}

// TestRateLimitError_NotReturnedForTerminalFailures guards the boundary: a
// permission failure or a plain 404 must not be surfaced as rate limiting.
func TestRateLimitError_NotReturnedForTerminalFailures(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers map[string]string
		body    string
	}{
		{
			name:    "permission failure with healthy budget",
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "4999"},
			body:    `{"message":"Resource not accessible by integration"}`,
		},
		{
			name:    "not found",
			status:  http.StatusNotFound,
			headers: map[string]string{},
			body:    `{"message":"Not Found"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range tt.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			_, err := newClientForServer(t, server).createInstallationToken(context.Background(), 42, nil)
			if err == nil {
				t.Fatal("createInstallationToken() err = nil, want an error")
			}

			var rle *RateLimitError
			if errors.As(err, &rle) {
				t.Errorf("errors.As(*RateLimitError) = true for a terminal %d: %v", tt.status, err)
			}
			if errors.Is(err, ErrRateLimited) {
				t.Errorf("errors.Is(err, ErrRateLimited) = true for a terminal %d", tt.status)
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("errors.As(*APIError) = false for a terminal %d: %v", tt.status, err)
			}
			if apiErr.StatusCode != tt.status {
				t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, tt.status)
			}
			if apiErr.Message != tt.body {
				t.Errorf("APIError.Message = %q, want %q", apiErr.Message, tt.body)
			}
		})
	}
}

// TestAPIError_MessageFormat pins the rendered message, which predates the
// type: it was a fmt.Errorf string callers already log and match on.
func TestAPIError_MessageFormat(t *testing.T) {
	err := &APIError{StatusCode: http.StatusNotFound, Message: `{"message":"Not Found"}`}

	want := `GitHub API returned status 404: {"message":"Not Found"}`
	if got := err.Error(); got != want {
		t.Errorf("Error() =\n  %q\nwant\n  %q", got, want)
	}
}

func TestRevokeInstallationToken(t *testing.T) {
	t.Parallel()

	failing := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})

	tests := []struct {
		name     string
		status   int
		header   http.Header
		opts     func(serverURL string) []InstallationTokenSourceOpt
		nilCtx   bool
		wantPath string
		wantErr  func(error) bool
	}{
		{
			name:     "revoked",
			status:   http.StatusNoContent,
			wantPath: "/installation/token",
			wantErr:  func(err error) bool { return err == nil },
		},
		{
			name:   "an Enterprise Server base path is kept",
			status: http.StatusNoContent,
			opts: func(u string) []InstallationTokenSourceOpt {
				return []InstallationTokenSourceOpt{WithEnterpriseURL(u)}
			},
			wantPath: "/api/v3/installation/token",
			wantErr:  func(err error) bool { return err == nil },
		},
		{
			name:     "a token GitHub no longer accepts",
			status:   http.StatusUnauthorized,
			wantPath: "/installation/token",
			wantErr: func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
			},
		},
		{
			name:     "throttled",
			status:   http.StatusTooManyRequests,
			header:   http.Header{"Retry-After": {"5"}},
			wantPath: "/installation/token",
			wantErr:  func(err error) bool { return errors.Is(err, ErrRateLimited) },
		},
		{
			name: "a base URL that does not parse is not sent to github.com",
			opts: func(string) []InstallationTokenSourceOpt {
				return []InstallationTokenSourceOpt{WithBaseURL("://bad")}
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "parse") },
		},
		{
			name: "transport fails the round trip",
			opts: func(u string) []InstallationTokenSourceOpt {
				return []InstallationTokenSourceOpt{WithBaseURL(u), WithHTTPClient(&http.Client{Transport: failing})}
			},
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "failed to execute request") },
		},
		{
			name:    "no context",
			nilCtx:  true,
			wantErr: func(err error) bool { return err != nil && strings.Contains(err.Error(), "failed to create request") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var method, path, auth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method, path, auth = r.Method, r.URL.Path, r.Header.Get("Authorization")
				for k, v := range tt.header {
					w.Header()[k] = v
				}
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			opts := []InstallationTokenSourceOpt{WithBaseURL(server.URL)}
			if tt.opts != nil {
				opts = tt.opts(server.URL)
			}
			ctx := context.Background()
			if tt.nilCtx {
				ctx = nil
			}

			err := RevokeInstallationToken(ctx, "ghs_revoke", opts...)
			if !tt.wantErr(err) {
				t.Fatalf("RevokeInstallationToken() err = %v", err)
			}
			if tt.wantPath == "" {
				return
			}
			if method != http.MethodDelete || path != tt.wantPath || auth != "Bearer ghs_revoke" {
				t.Errorf("request = %s %s with Authorization %q, want DELETE %s with the token itself", method, path, auth, tt.wantPath)
			}
		})
	}
}

// Test_createInstallationToken_BoundsResponse checks a server sending more than
// any real answer cannot make the client read it all.
func Test_createInstallationToken_BoundsResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"token":"`)
		_, _ = io.Copy(w, io.LimitReader(repeatReader('a'), maxResponseBytes+1))
		_, _ = io.WriteString(w, `"}`)
	}))
	defer server.Close()

	_, err := newClientForServer(t, server).createInstallationToken(context.Background(), 1, nil)
	if err == nil || !strings.Contains(err.Error(), "failed to decode response") {
		t.Errorf("err = %v, want the oversized response refused", err)
	}
}

// repeatReader is an endless stream of one byte.
type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// Test_createInstallationToken_RefusesAmbiguousPermission checks a permission
// named twice is refused before anything is sent, rather than one silently
// winning.
func Test_createInstallationToken_RefusesAmbiguousPermission(t *testing.T) {
	t.Parallel()

	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called.Store(true)
	}))
	defer server.Close()

	opts := &InstallationTokenOptions{Permissions: &InstallationPermissions{
		Contents: Ptr("read"),
		Other:    map[string]string{"contents": "write"},
	}}
	_, err := newClientForServer(t, server).createInstallationToken(context.Background(), 1, opts)

	if err == nil || !strings.Contains(err.Error(), `"contents" is set both`) {
		t.Errorf("err = %v, want the ambiguous permission named", err)
	}
	if called.Load() {
		t.Error("the request was sent")
	}
}

func TestFindInstallationID(t *testing.T) {
	t.Parallel()

	jwt := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "app-jwt", Expiry: time.Now().Add(time.Hour)})
	failing := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})

	tests := []struct {
		name     string
		owner    string
		status   int
		body     string
		opts     func(serverURL string) []InstallationTokenSourceOpt
		nilCtx   bool
		wantPath string
		wantID   int64
		wantErr  string
	}{
		{name: "found", owner: "acme", status: http.StatusOK, body: `{"id":123,"account":{"login":"acme"}}`, wantPath: "/users/acme/installation", wantID: 123},
		{
			name: "an Enterprise Server base path is kept", owner: "acme", status: http.StatusOK, body: `{"id":7}`,
			opts: func(u string) []InstallationTokenSourceOpt {
				return []InstallationTokenSourceOpt{WithEnterpriseURL(u)}
			},
			wantPath: "/api/v3/users/acme/installation", wantID: 7,
		},
		{name: "an owner is escaped into one segment", owner: "%2F..%", status: http.StatusOK, body: `{"id":5}`, wantPath: "/users/%2F..%/installation", wantID: 5},
		{name: "not installed", owner: "acme", status: http.StatusNotFound, body: `{"message":"Not Found"}`, wantPath: "/users/acme/installation", wantErr: "status 404"},
		{name: "a body that is not JSON", owner: "acme", status: http.StatusOK, body: `<html>`, wantPath: "/users/acme/installation", wantErr: "failed to decode response"},
		{name: "an answer without an ID", owner: "acme", status: http.StatusOK, body: `{"token":"ghs_x"}`, wantPath: "/users/acme/installation", wantErr: "without an ID"},
		{name: "a repository is not an owner", owner: "acme/api", wantErr: "invalid owner"},
		{name: "a dot segment is not an owner", owner: "..", wantErr: "invalid owner"},
		{name: "no owner", wantErr: "invalid owner"},
		{
			name: "a base URL that does not parse is not sent to github.com", owner: "acme",
			opts: func(string) []InstallationTokenSourceOpt {
				return []InstallationTokenSourceOpt{WithBaseURL("://bad")}
			},
			wantErr: "parse",
		},
		{
			name: "transport fails the round trip", owner: "acme",
			opts: func(u string) []InstallationTokenSourceOpt {
				return []InstallationTokenSourceOpt{WithBaseURL(u), WithHTTPClient(&http.Client{Transport: failing})}
			},
			wantErr: "failed to execute request",
		},
		{name: "no context", owner: "acme", nilCtx: true, wantErr: "failed to create request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var path, auth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path, auth = r.URL.Path, r.Header.Get("Authorization")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()

			opts := []InstallationTokenSourceOpt{WithBaseURL(server.URL)}
			if tt.opts != nil {
				opts = tt.opts(server.URL)
			}
			ctx := context.Background()
			if tt.nilCtx {
				ctx = nil
			}

			id, err := FindInstallationID(ctx, jwt, tt.owner, opts...)
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("FindInstallationID() err = %v, want %q", err, tt.wantErr)
			}
			if id != tt.wantID {
				t.Errorf("id = %d, want %d", id, tt.wantID)
			}
			if tt.wantPath != "" && (path != tt.wantPath || auth != "Bearer app-jwt") {
				t.Errorf("request = %s with Authorization %q, want %s with the App JWT", path, auth, tt.wantPath)
			}
		})
	}
}

func TestInstallationPermissions_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		wantField *string
		wantOther map[string]string
		wantErr   bool
	}{
		{name: "a field", body: `{"contents":"read"}`, wantField: Ptr("read")},
		{name: "a permission with no field", body: `{"installation_repositories":"write"}`, wantOther: map[string]string{"installation_repositories": "write"}},
		{name: "a value that is not a level is dropped", body: `{"future":{"nested":true}}`},
		{name: "null", body: `null`},
		{name: "a field of the wrong type", body: `{"contents":1}`, wantErr: true},
		{name: "an empty level stays on its field", body: `{"contents":""}`, wantField: Ptr("")},
		{name: "a field's name in another case stays on the field", body: `{"Contents":"read"}`, wantField: Ptr("read")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var p InstallationPermissions
			err := json.Unmarshal([]byte(tt.body), &p)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal() err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if (p.Contents == nil) != (tt.wantField == nil) || p.Contents != nil && *p.Contents != *tt.wantField {
				t.Errorf("Contents = %v, want %v", p.Contents, tt.wantField)
			}
			if !maps.Equal(p.Other, tt.wantOther) {
				t.Errorf("Other = %v, want %v", p.Other, tt.wantOther)
			}
			// What was decoded marshals again.
			if _, err := json.Marshal(p); err != nil {
				t.Errorf("Marshal() after Unmarshal err = %v", err)
			}
		})
	}
}

// TestInstallationPermissions_UnmarshalJSONUpdatesOther checks a second decode
// into the same value replaces a level, as it does for a field.
func TestInstallationPermissions_UnmarshalJSONUpdatesOther(t *testing.T) {
	t.Parallel()

	var p InstallationPermissions
	for _, body := range []string{`{"future":"write"}`, `{"future":"read"}`} {
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatalf("Unmarshal(%s) err = %v", body, err)
		}
	}
	if got := p.Other["future"]; got != "read" {
		t.Errorf(`Other["future"] = %q, want "read"`, got)
	}
}

// TestInstallationPermissions_MarshalJSONRefusesCaseVariant checks Other cannot
// sneak in a second level for a field by changing the name's case.
func TestInstallationPermissions_MarshalJSONRefusesCaseVariant(t *testing.T) {
	t.Parallel()

	p := InstallationPermissions{Contents: Ptr("read"), Other: map[string]string{"Contents": "write"}}
	if _, err := json.Marshal(p); err == nil {
		t.Error("Marshal() err = nil, want the permission named twice refused")
	}
}

// sameJSON reports whether a and b are the same JSON value, or both empty.
func sameJSON(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	var av, bv any
	return json.Unmarshal([]byte(a), &av) == nil && json.Unmarshal([]byte(b), &bv) == nil && reflect.DeepEqual(av, bv)
}

func TestSleepCtx(t *testing.T) {
	t.Parallel()

	// The retry tests record waits instead of spending them, so this is what
	// shows the wait is real: it takes at least d, and ends early, mid-wait,
	// when the context does.
	tests := []struct {
		name        string
		d           time.Duration
		cancelAfter time.Duration // 0: never cancelled
		minElapsed  time.Duration
		wantErr     error
	}{
		{name: "no wait", d: 0},
		{name: "a wait lasts its duration", d: 20 * time.Millisecond, minElapsed: 20 * time.Millisecond},
		{name: "a context done mid-wait ends it", d: time.Hour, cancelAfter: 10 * time.Millisecond, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelAfter > 0 {
				time.AfterFunc(tt.cancelAfter, cancel)
			}

			start := time.Now()
			err := sleepCtx(ctx, tt.d)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("sleepCtx(%v) = %v, want %v", tt.d, err, tt.wantErr)
			}
			if elapsed := time.Since(start); elapsed < tt.minElapsed {
				t.Errorf("sleepCtx(%v) returned after %v, want at least %v", tt.d, elapsed, tt.minElapsed)
			}
		})
	}
}
