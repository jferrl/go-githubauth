// Package githubauth provides utilities for GitHub authentication,
// including generating and using GitHub App tokens and installation tokens.
//
// This file contains local mock implementations for testing purposes.
package githubauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// mockedHTTPClient represents a mock HTTP client for testing GitHub API interactions.
type mockedHTTPClient struct {
	server   *httptest.Server
	handlers map[string]http.HandlerFunc
}

// mockOption is a functional option for configuring mockedHTTPClient.
type mockOption func(*mockedHTTPClient)

// withRequestMatch configures the mock to return a specific response for a given endpoint pattern.
func withRequestMatch(endpoint string, response any) mockOption {
	return func(m *mockedHTTPClient) {
		m.handlers[endpoint] = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}
	}
}

// withRequestMatchHandler configures the mock to use a custom handler for a given endpoint pattern.
func withRequestMatchHandler(endpoint string, handler http.HandlerFunc) mockOption {
	return func(m *mockedHTTPClient) {
		m.handlers[endpoint] = handler
	}
}

// newMockedHTTPClient creates a new mock HTTP client with the provided options.
// Returns the HTTP client and a cleanup function that should be called to close the test server.
func newMockedHTTPClient(opts ...mockOption) (*http.Client, func()) {
	m := &mockedHTTPClient{
		handlers: make(map[string]http.HandlerFunc),
	}

	for _, opt := range opts {
		opt(m)
	}

	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path

		if handler, exists := m.handlers[key]; exists {
			handler(w, r)
			return
		}

		for pattern, handler := range m.handlers {
			if matchesPattern(key, pattern) {
				handler(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))

	client := &http.Client{
		Transport: &mockTransport{
			server: m.server,
		},
	}

	return client, m.server.Close
}

// mockTransport implements http.RoundTripper to redirect requests to our mock server.
type mockTransport struct {
	server *httptest.Server
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.server.URL[7:]
	return http.DefaultTransport.RoundTrip(req)
}

// matchesPattern performs simple pattern matching for GitHub API endpoints.
func matchesPattern(request, pattern string) bool {
	// Handle the specific case used in tests: POST /app/installations/{installation_id}/access_tokens
	if pattern == "POST /app/installations/{installation_id}/access_tokens" {
		return strings.HasPrefix(request, "POST /app/installations/") &&
			strings.HasSuffix(request, "/access_tokens")
	}

	// For other patterns, use exact matching
	return request == pattern
}

// Common GitHub API endpoint patterns used in tests
const (
	postAppInstallationsAccessTokensByInstallationID = "POST /app/installations/{installation_id}/access_tokens"
)
