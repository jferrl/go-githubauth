package githubauth

import (
	"errors"
	"net"
	"net/http"
	"runtime"
	"time"
)

// cleanHTTPClient returns a new http.Client with clean defaults and connection pooling.
// Implementation based on github.com/hashicorp/go-cleanhttp
// Licensed under MPL-2.0: https://github.com/hashicorp/go-cleanhttp/blob/master/LICENSE
func cleanHTTPClient() *http.Client {
	return &http.Client{
		// Without this a server that stalls mid-response hangs Token() forever:
		// the default context is context.Background(), and the token cache holds
		// its mutex across the refresh, so one stalled request blocks every
		// concurrent caller. It bounds one attempt; the retry sleep is outside it.
		Timeout:       60 * time.Second,
		CheckRedirect: sameHostRedirect,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		},
	}
}

// sameHostRedirect refuses a redirect that leaves the original host or drops
// TLS. oauth2.Transport sets Authorization on every hop, which defeats the
// header stripping http.Client does across hosts, so following one would hand
// the App JWT to whoever the server points at. The refused 3xx is returned as
// the response.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	orig := via[0].URL
	if req.URL.Host != orig.Host || (orig.Scheme == "https" && req.URL.Scheme != "https") {
		return http.ErrUseLastResponse
	}
	return nil
}
