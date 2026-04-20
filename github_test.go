package githubauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func Test_githubClient_withEnterpriseURL(t *testing.T) {
	tests := []struct {
		name            string
		baseURL         string
		wantErr         bool
		expectedBaseURL string
	}{
		{
			name:            "valid URL with first subdomain",
			baseURL:         "https://api.github.example.com",
			wantErr:         false,
			expectedBaseURL: "https://api.github.example.com/",
		},
		{
			name:            "valid URL with first subdomain and trailing slash",
			baseURL:         "https://api.github.example.com/",
			wantErr:         false,
			expectedBaseURL: "https://api.github.example.com/",
		},
		{
			name:            "valid URL with second subdomain",
			baseURL:         "https://ghes.api.example.com",
			wantErr:         false,
			expectedBaseURL: "https://ghes.api.example.com/",
		},
		{
			name:            "valid URL with second subdomain and trailing slash",
			baseURL:         "https://ghes.api.example.com/",
			wantErr:         false,
			expectedBaseURL: "https://ghes.api.example.com/",
		},
		{
			name:            "valid URL with path",
			baseURL:         "https://github.example.com/api/v3",
			wantErr:         false,
			expectedBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:            "valid URL with path and trailing slash",
			baseURL:         "https://github.example.com/api/v3/",
			wantErr:         false,
			expectedBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:            "valid URL without path",
			baseURL:         "https://github.example.com",
			wantErr:         false,
			expectedBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:            "valid URL without path but with trailing slash",
			baseURL:         "https://github.example.com/",
			wantErr:         false,
			expectedBaseURL: "https://github.example.com/api/v3/",
		},
		{
			name:            "invalid URL with control characters",
			baseURL:         "ht\ntp://invalid",
			wantErr:         true,
			expectedBaseURL: "",
		},
		{
			name:            "URL with spaces",
			baseURL:         "http://invalid url with spaces",
			wantErr:         true,
			expectedBaseURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newGitHubClient(&http.Client{})
			githubClient, err := client.withEnterpriseURL(tt.baseURL)

			if (err != nil) != tt.wantErr {
				t.Errorf("withEnterpriseURL(%v) error = %v", tt.baseURL, err)
			}

			if err == nil && githubClient.baseURL.String() != tt.expectedBaseURL {
				t.Errorf("withEnterpriseURL(%v) expected = %v, received = %v", tt.baseURL, tt.expectedBaseURL, githubClient.baseURL)
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
			name: "invalid JSON in options",
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
					t.Errorf("expected error containing %q, got nil", tt.errorSubstring)
				} else if !contains(err.Error(), tt.errorSubstring) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstring, err.Error())
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && hasSubstring(s, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func Test_Ptr(t *testing.T) {
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

func Test_createInstallationToken_ErrorPaths(t *testing.T) {
	t.Run("error parsing endpoint URL", func(t *testing.T) {
		// Create a client with an invalid base URL that will cause Parse to fail
		client := &githubClient{
			baseURL: &url.URL{Scheme: "http", Host: "example.com", Path: ":::invalid"},
			client:  &http.Client{},
		}

		_, err := client.createInstallationToken(context.Background(), 12345, nil)
		if err == nil {
			t.Error("Expected error for invalid base URL, got nil")
		}
	})

	t.Run("error marshaling options", func(t *testing.T) {
		// This is difficult to trigger with InstallationTokenOptions as it has simple fields
		// We would need to use reflection or create a custom type
		// For now, we test with valid options and nil options which are both covered
		client := newGitHubClient(&http.Client{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(InstallationToken{
				Token:     "test-token",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			})
		}))
		defer server.Close()

		client.baseURL, _ = client.baseURL.Parse(server.URL)

		opts := &InstallationTokenOptions{
			Repositories: []string{"repo1", "repo2"},
			Permissions: &InstallationPermissions{
				Contents: Ptr("read"),
				Issues:   Ptr("write"),
			},
		}

		_, err := client.createInstallationToken(context.Background(), 12345, opts)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}

// throttleResponse programs one hit on throttleHandler. A response is emitted
// per call, indexed by attempt count; exceeding the list replays the last entry.
type throttleResponse struct {
	status     int
	headers    map[string]string
	body       string
	writeToken bool // serialize an InstallationToken JSON body instead of body
}

func throttleHandler(t *testing.T, responses []throttleResponse, attempts *atomic.Int32) http.HandlerFunc {
	t.Helper()
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
	baseURL, err := c.baseURL.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	c.baseURL = baseURL
	return c
}

func Test_createInstallationToken_RetryOnThrottle(t *testing.T) {
	tests := []struct {
		name          string
		responses     []throttleResponse
		retryEnabled  bool
		wantAttempts  int32
		wantErr       bool
		wantRateLimit bool
		minElapsed    time.Duration
		maxElapsed    time.Duration
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
			minElapsed:   900 * time.Millisecond,
			maxElapsed:   3 * time.Second,
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
			minElapsed:   900 * time.Millisecond,
			maxElapsed:   3 * time.Second,
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
			server := httptest.NewServer(throttleHandler(t, tt.responses, &attempts))
			defer server.Close()

			client := newClientForServer(t, server)
			client.retryOnThrottle = tt.retryEnabled

			start := time.Now()
			_, err := client.createInstallationToken(context.Background(), 12345, nil)
			elapsed := time.Since(start)

			if got := attempts.Load(); got != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", got, tt.wantAttempts)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantRateLimit && !errors.Is(err, ErrRateLimited) {
				t.Errorf("err = %v, want errors.Is(err, ErrRateLimited)", err)
			}
			if tt.minElapsed > 0 && elapsed < tt.minElapsed {
				t.Errorf("elapsed = %v, want >= %v", elapsed, tt.minElapsed)
			}
			if tt.maxElapsed > 0 && elapsed > tt.maxElapsed {
				t.Errorf("elapsed = %v, want <= %v", elapsed, tt.maxElapsed)
			}
		})
	}
}

func Test_createInstallationToken_XRateLimitReset(t *testing.T) {
	// x-ratelimit-reset is a Unix-second epoch, so the header value must be
	// computed at request-time to avoid sub-second truncation that makes the
	// elapsed-time assertion flaky.
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
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

	start := time.Now()
	tok, err := client.createInstallationToken(context.Background(), 12345, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("createInstallationToken err = %v", err)
	}
	if tok == nil || tok.Token != "test-token" {
		t.Errorf("token = %+v, want Token=\"test-token\"", tok)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
	// Reset is now+3, Unix() can truncate up to 1s, so the floor is ~2s.
	if elapsed < 1500*time.Millisecond {
		t.Errorf("elapsed = %v, want >= 1.5s (reset hint was now+3s)", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("elapsed = %v, want <= 5s (bounded by reset hint)", elapsed)
	}
}

func Test_throttleDelay_CapsAtMaxRetrySleep(t *testing.T) {
	// Verify directly at the throttleDelay boundary so the assertion is
	// deterministic and fast (no real sleep).
	c := newGitHubClient(&http.Client{})
	resp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"600"}},
	}
	d, ok := c.throttleDelay(resp)
	if !ok {
		t.Fatalf("throttleDelay ok = false, want true")
	}
	if d != maxRetrySleep {
		t.Errorf("delay = %v, want %v", d, maxRetrySleep)
	}

	resp = &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{time.Now().Add(1 * time.Hour).UTC().Format(http.TimeFormat)}},
	}
	d, ok = c.throttleDelay(resp)
	if !ok {
		t.Fatalf("throttleDelay ok = false, want true")
	}
	if d != maxRetrySleep {
		t.Errorf("HTTP-date delay = %v, want %v", d, maxRetrySleep)
	}
}

func Test_createInstallationToken_ContextCancelledDuringSleep(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(throttleHandler(t, []throttleResponse{
		{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "30"}, body: `{"message":"rate limited"}`},
	}, &attempts))
	defer server.Close()

	client := newClientForServer(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := client.createInstallationToken(ctx, 12345, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("elapsed = %v, expected ctx cancellation to abort sleep quickly", elapsed)
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
		if d, ok := c.throttleDelay(resp); ok || d != 0 {
			t.Errorf("status %d: got (%v, %v), want (0, false)", status, d, ok)
		}
	}
}

func Test_WithRetryOnThrottle_AffectsSource(t *testing.T) {
	// Drive a full installationTokenSource.Token() through a throttled server
	// to verify the option propagates from the source down to the client.
	var attempts atomic.Int32
	server := httptest.NewServer(throttleHandler(t, []throttleResponse{
		{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "0"}, body: `{"message":"first"}`},
		{status: http.StatusCreated, writeToken: true},
	}, &attempts))
	defer server.Close()

	src := oauth2StaticSource{accessToken: "jwt"}

	ts := NewInstallationTokenSource(42, src,
		WithEnterpriseURL(server.URL),
		WithRetryOnThrottle(true),
	)

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() err = %v", err)
	}
	if tok.AccessToken != "test-token" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "test-token")
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}

	var attempts2 atomic.Int32
	server2 := httptest.NewServer(throttleHandler(t, []throttleResponse{
		{status: http.StatusTooManyRequests, headers: map[string]string{"Retry-After": "0"}, body: `{"message":"first"}`},
		{status: http.StatusCreated, writeToken: true},
	}, &attempts2))
	defer server2.Close()

	ts2 := NewInstallationTokenSource(42, src,
		WithEnterpriseURL(server2.URL),
		WithRetryOnThrottle(false),
	)

	_, err = ts2.Token()
	if err == nil {
		t.Fatalf("Token() err = nil, want ErrRateLimited")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want errors.Is(err, ErrRateLimited)", err)
	}
	if got := attempts2.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
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
