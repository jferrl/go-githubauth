package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/jferrl/go-githubauth"
)

// Exit codes. Each names a different next move, so a caller can tell "wait and
// retry" from "this key will never work" without reading the message.
const (
	exitOK          = 0 // the token was produced
	exitFailure     = 1 // something else went wrong, retrying may help
	exitUsage       = 2 // the invocation is wrong, fix the flags
	exitCredentials = 3 // GitHub refused the key or the App's permissions
	exitRateLimited = 4 // throttled, wait retry_after_seconds and repeat
	exitNotFound    = 5 // the App is not installed where it was asked to be
)

// credentialError marks a failure to build the App token source: an unparseable
// PEM, or an identity GitHub could never accept. It is distinct from a rejected
// request because nothing was sent yet.
type credentialError struct{ err error }

func (e credentialError) Error() string { return e.err.Error() }
func (e credentialError) Unwrap() error { return e.err }

// exitStatus carries a child process's exit code out through the error path, so
// --exec exits as the command it ran did.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// failure is an error classified for reporting: the code to exit with, and what
// to do about it.
type failure struct {
	summary     string
	code        int
	statusCode  int
	retryAfter  *time.Duration
	suggestions []string
	// reported is set when the flag package has already written the message,
	// so the prose rendering does not print it twice.
	reported bool
}

// classify maps an error to its exit code and the advice that goes with it.
// Every branch ends in a suggestion naming a command or a flag.
func classify(err error) failure {
	var ue usageError
	if errors.As(err, &ue) {
		return failure{
			summary:  err.Error(),
			code:     exitUsage,
			reported: ue.reported,
			suggestions: []string{
				`Run "githubauth <command> --help" for the flags of a command.`,
			},
		}
	}

	var ce credentialError
	if errors.As(err, &ce) {
		return failure{
			summary: err.Error(),
			code:    exitCredentials,
			suggestions: []string{
				"Check --key: it must be the App's PEM private key, a path to it, or - for stdin.",
				"Check --client-id (or --app-id) against the App's settings page.",
			},
		}
	}

	var rle *githubauth.RateLimitError
	if errors.As(err, &rle) {
		return failure{
			summary:    err.Error(),
			code:       exitRateLimited,
			statusCode: rle.StatusCode,
			retryAfter: &rle.RetryAfter,
			suggestions: []string{
				fmt.Sprintf("Wait %s, then run the same command again.", rle.RetryAfter.Round(time.Second)),
			},
		}
	}

	var apiErr *githubauth.APIError
	if errors.As(err, &apiErr) {
		f := failure{summary: err.Error(), code: exitFailure, statusCode: apiErr.StatusCode}
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			f.code = exitCredentials
			f.suggestions = []string{
				"GitHub rejected the App JWT: check that --key is the current key for --client-id and that the clock is right.",
			}
		case http.StatusForbidden:
			f.code = exitCredentials
			f.suggestions = []string{
				"The App lacks a permission this call needs. Grant it in the App's settings, then reinstall it.",
			}
		case http.StatusNotFound:
			f.code = exitNotFound
			f.suggestions = []string{
				"Check --installation: the App may not be installed on that account.",
				`List the App's installations: curl -H "Authorization: Bearer $(githubauth jwt)" https://api.github.com/app/installations`,
			}
		}
		return f
	}

	return failure{
		summary: err.Error(),
		code:    exitFailure,
		suggestions: []string{
			"Retry. If it persists, check https://www.githubstatus.com.",
		},
	}
}

// errorDocument is the JSON failure envelope. The type and schema_version make
// it identifiable in a stream that may carry anything else, and let the shape
// change later without breaking a reader that checks them.
type errorDocument struct {
	Type          string    `json:"type"`
	SchemaVersion string    `json:"schema_version"`
	Error         errorBody `json:"error"`
}

type errorBody struct {
	Summary           string   `json:"summary"`
	ExitCode          int      `json:"exit_code"`
	StatusCode        int      `json:"status_code,omitempty"`
	RetryAfterSeconds *int     `json:"retry_after_seconds,omitempty"`
	Suggestions       []string `json:"suggestions,omitempty"`
}

// report renders err and returns the exit code.
//
// Under --json or agent mode the failure is one JSON document on stdout and
// stderr stays quiet, so a machine reader finds one error on one stream.
// Otherwise it is prose on stderr, and stdout stays empty so
// $(githubauth token) never captures an error message.
func report(err error, stdout, stderr io.Writer, out output) int {
	var status exitStatus
	if errors.As(err, &status) {
		return int(status)
	}

	f := classify(err)
	if out.json || out.agent {
		return writeErrorDocument(stdout, stderr, f)
	}

	if !f.reported {
		_, _ = fmt.Fprintf(stderr, "githubauth: %s\n", f.summary)
	}
	for _, s := range f.suggestions {
		_, _ = fmt.Fprintf(stderr, "  %s\n", s)
	}
	return f.code
}

// writeErrorDocument emits the JSON envelope. A closed stdout falls back to
// stderr prose, so a failure is still visible to someone.
func writeErrorDocument(stdout, stderr io.Writer, f failure) int {
	body := errorBody{
		Summary:     f.summary,
		ExitCode:    f.code,
		StatusCode:  f.statusCode,
		Suggestions: f.suggestions,
	}
	if f.retryAfter != nil {
		secs := int(math.Ceil(f.retryAfter.Seconds()))
		body.RetryAfterSeconds = &secs
	}

	doc := errorDocument{Type: "githubauth.error", SchemaVersion: "1", Error: body}
	if err := json.NewEncoder(stdout).Encode(doc); err != nil {
		_, _ = fmt.Fprintf(stderr, "githubauth: %s\n", f.summary)
	}
	return f.code
}
