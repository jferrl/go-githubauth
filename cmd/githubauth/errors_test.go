package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jferrl/go-githubauth"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		wantCode       int
		wantStatus     int
		wantRetryAfter time.Duration
		wantSuggestion string
	}{
		{
			name:           "misuse",
			err:            usagef("set --a or --b, not both"),
			wantCode:       exitUsage,
			wantSuggestion: "--help",
		},
		{
			name:           "an unusable key never reaches GitHub",
			err:            credentialError{errors.New("invalid key")},
			wantCode:       exitCredentials,
			wantSuggestion: "Check --key",
		},
		{
			name:           "throttled",
			err:            &githubauth.RateLimitError{StatusCode: http.StatusTooManyRequests, RetryAfter: 45 * time.Second},
			wantCode:       exitRateLimited,
			wantStatus:     http.StatusTooManyRequests,
			wantRetryAfter: 45 * time.Second,
			wantSuggestion: "Wait 45s",
		},
		{
			name:           "the JWT was rejected",
			err:            &githubauth.APIError{StatusCode: http.StatusUnauthorized},
			wantCode:       exitCredentials,
			wantStatus:     http.StatusUnauthorized,
			wantSuggestion: "rejected the App JWT",
		},
		{
			name:           "the App lacks a permission",
			err:            &githubauth.APIError{StatusCode: http.StatusForbidden},
			wantCode:       exitCredentials,
			wantStatus:     http.StatusForbidden,
			wantSuggestion: "lacks a permission",
		},
		{
			name:           "the App is not installed there",
			err:            &githubauth.APIError{StatusCode: http.StatusNotFound},
			wantCode:       exitNotFound,
			wantStatus:     http.StatusNotFound,
			wantSuggestion: "--installation",
		},
		{
			name:       "an unclassified status is a general failure",
			err:        &githubauth.APIError{StatusCode: http.StatusInternalServerError},
			wantCode:   exitFailure,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:           "anything else",
			err:            errors.New("dial tcp: connection refused"),
			wantCode:       exitFailure,
			wantSuggestion: "githubstatus.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classify(tt.err)
			if got.code != tt.wantCode {
				t.Errorf("code = %d, want %d", got.code, tt.wantCode)
			}
			if got.statusCode != tt.wantStatus {
				t.Errorf("statusCode = %d, want %d", got.statusCode, tt.wantStatus)
			}
			if tt.wantRetryAfter != 0 {
				if got.retryAfter == nil {
					t.Fatal("retryAfter = nil, want a duration")
				}
				if *got.retryAfter != tt.wantRetryAfter {
					t.Errorf("retryAfter = %v, want %v", *got.retryAfter, tt.wantRetryAfter)
				}
			}
			if tt.wantSuggestion == "" {
				return
			}
			if !strings.Contains(strings.Join(got.suggestions, "\n"), tt.wantSuggestion) {
				t.Errorf("suggestions = %q, want one containing %q", got.suggestions, tt.wantSuggestion)
			}
		})
	}
}

// TestReportRoutesByAudience pins where a failure goes: one JSON document on
// stdout for a machine, prose on stderr for a person, with stdout left clean
// for $(...).
func TestReportRoutesByAudience(t *testing.T) {
	t.Parallel()

	err := &githubauth.APIError{StatusCode: http.StatusNotFound, Message: `{"message":"Not Found"}`}

	tests := []struct {
		name       string
		out        output
		wantStdout bool
	}{
		{name: "a person reads stderr", out: output{}, wantStdout: false},
		{name: "--json speaks to a machine", out: output{json: true}, wantStdout: true},
		{name: "agent mode does too", out: output{agent: true}, wantStdout: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := report(err, &stdout, &stderr, tt.out)

			if code != exitNotFound {
				t.Errorf("report() = %d, want %d", code, exitNotFound)
			}
			if !tt.wantStdout {
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want it empty", stdout.String())
				}
				if !strings.Contains(stderr.String(), "githubauth: GitHub API returned status 404") {
					t.Errorf("stderr = %q, want the prose rendering", stderr.String())
				}
				return
			}

			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want it empty when the error went to stdout", stderr.String())
			}

			var doc errorDocument
			if jsonErr := json.Unmarshal(stdout.Bytes(), &doc); jsonErr != nil {
				t.Fatalf("decoding %q: %v", stdout.String(), jsonErr)
			}
			if doc.Type != "githubauth.error" || doc.SchemaVersion != "1" {
				t.Errorf("envelope = %+v, want the githubauth.error discriminators", doc)
			}
			if doc.Error.ExitCode != exitNotFound {
				t.Errorf("exit_code = %d, want %d", doc.Error.ExitCode, exitNotFound)
			}
			if doc.Error.StatusCode != http.StatusNotFound {
				t.Errorf("status_code = %d, want 404", doc.Error.StatusCode)
			}
			if len(doc.Error.Suggestions) == 0 {
				t.Error("suggestions is empty, want at least one")
			}
		})
	}
}

// TestReportRetryAfterIsActionable checks the field that tells a caller how
// long to wait.
func TestReportRetryAfterIsActionable(t *testing.T) {
	t.Parallel()

	err := &githubauth.RateLimitError{StatusCode: http.StatusForbidden, RetryAfter: 1500 * time.Millisecond}

	var stdout, stderr bytes.Buffer
	if code := report(err, &stdout, &stderr, output{agent: true}); code != exitRateLimited {
		t.Errorf("report() = %d, want %d", code, exitRateLimited)
	}

	var doc errorDocument
	if jsonErr := json.Unmarshal(stdout.Bytes(), &doc); jsonErr != nil {
		t.Fatalf("decoding %q: %v", stdout.String(), jsonErr)
	}
	if doc.Error.RetryAfterSeconds == nil {
		t.Fatal("retry_after_seconds is absent, want it present for a rate limit")
	}
	// Rounded up: sleeping 1s when GitHub asked for 1.5 gets throttled again.
	if *doc.Error.RetryAfterSeconds != 2 {
		t.Errorf("retry_after_seconds = %d, want 2", *doc.Error.RetryAfterSeconds)
	}
}

// TestReportPassesThroughChildStatus covers --exec: the child's code is its
// own answer and must not be reclassified.
func TestReportPassesThroughChildStatus(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := report(exitStatus(7), &stdout, &stderr, output{agent: true}); code != 7 {
		t.Errorf("report() = %d, want 7", code)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("wrote stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

// TestReportSuppressesTheDoubleReport keeps the flag package's own message from
// being printed twice when it has already written to stderr.
func TestReportSuppressesTheDoubleReport(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := report(usageError{err: errors.New("flag provided but not defined: -nope"), reported: true}, &stdout, &stderr, output{})

	if code != exitUsage {
		t.Errorf("report() = %d, want %d", code, exitUsage)
	}
	if strings.Contains(stderr.String(), "not defined") {
		t.Errorf("stderr = %q, want the already-reported message left out", stderr.String())
	}
}
