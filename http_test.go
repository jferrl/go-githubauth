package githubauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
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

	// The header timeout ends once headers arrive; only this one bounds a
	// server that then stalls the body.
	if c.Timeout <= 0 {
		t.Errorf("Timeout = %v, want a positive bound", c.Timeout)
	}
}

// TestInstallationTokenSource_DoesNotLeakJWTOnRedirect guards the App JWT.
// oauth2.Transport sets Authorization on every hop, so a followed cross-host
// redirect would hand the JWT to whatever host the server named.
func TestInstallationTokenSource_DoesNotLeakJWTOnRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer other.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer api.Close()

	jwt := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "app-jwt", Expiry: time.Now().Add(time.Hour)})
	clients := []struct {
		name string
		opt  []InstallationTokenSourceOpt
	}{
		{name: "default client"},
		{name: "caller's client", opt: []InstallationTokenSourceOpt{WithHTTPClient(&http.Client{})}},
	}

	for _, c := range clients {
		t.Run(c.name, func(t *testing.T) {
			leaked = ""
			opts := append([]InstallationTokenSourceOpt{WithBaseURL(api.URL)}, c.opt...)

			_, err := NewInstallationTokenSource(1, jwt, opts...).Token()

			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTemporaryRedirect {
				t.Errorf("err = %v, want an APIError carrying the refused 307", err)
			}
			if leaked != "" {
				t.Errorf("the other host received Authorization %q", leaked)
			}
		})
	}
}

func TestSameHostRedirect(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		want error
	}{
		{name: "same host", from: "https://ghe.example.com/a", to: "https://ghe.example.com/b", want: nil},
		{name: "same host upgraded to TLS", from: "http://ghe.example.com/a", to: "https://ghe.example.com/a", want: nil},
		{name: "another host", from: "https://ghe.example.com/a", to: "https://evil.example.com/a", want: http.ErrUseLastResponse},
		{name: "TLS dropped", from: "https://ghe.example.com/a", to: "http://ghe.example.com/a", want: http.ErrUseLastResponse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from := httptest.NewRequest(http.MethodPost, tt.from, nil)
			to := httptest.NewRequest(http.MethodPost, tt.to, nil)
			if got := sameHostRedirect(to, []*http.Request{from}); !errors.Is(got, tt.want) {
				t.Errorf("sameHostRedirect() = %v, want %v", got, tt.want)
			}
		})
	}
}
