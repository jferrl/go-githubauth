package githubauth

import (
	"net/http"
	"testing"
)

// TestCleanHTTPClient_BoundsEveryStage guards the timeouts on the default
// transport. Dial and TLS were already bounded, but nothing capped the wait for
// a response header, so a server that accepted the connection and then went
// quiet would hang Token() indefinitely: the default context is
// context.Background(), and the token cache holds its mutex across a refresh,
// so a single stalled request blocks every concurrent caller.
func TestCleanHTTPClient_BoundsEveryStage(t *testing.T) {
	c := cleanHTTPClient()

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}

	stages := []struct {
		name string
		got  int64
	}{
		{"TLSHandshakeTimeout", int64(tr.TLSHandshakeTimeout)},
		{"ResponseHeaderTimeout", int64(tr.ResponseHeaderTimeout)},
		{"IdleConnTimeout", int64(tr.IdleConnTimeout)},
		{"ExpectContinueTimeout", int64(tr.ExpectContinueTimeout)},
	}

	for _, s := range stages {
		if s.got <= 0 {
			t.Errorf("%s = %v, want a positive bound", s.name, s.got)
		}
	}
}
