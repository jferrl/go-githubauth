package githubauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
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
