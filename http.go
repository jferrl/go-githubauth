package githubauth

import (
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
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
		},
	}
}
