package githubauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkInstallationTokenSource_CacheHit measures the path almost every
// Token() call takes: a cached token that is still valid. The call count is
// asserted afterwards so a regression that turned cache hits back into HTTP
// requests would fail the benchmark rather than quietly reporting a slower
// number.
func BenchmarkInstallationTokenSource_CacheHit(b *testing.B) {
	var calls atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(InstallationToken{
			Token:     "ghs_benchmark",
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generating key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	app, err := NewApplicationTokenSource("Iv1.testclientid", keyPEM)
	if err != nil {
		b.Fatalf("NewApplicationTokenSource() error = %v", err)
	}
	src := NewInstallationTokenSource(1, app, WithBaseURL(srv.URL))

	// Prime the cache so the loop measures hits, not the initial mint.
	if _, err := src.Token(); err != nil {
		b.Fatalf("priming Token() error = %v", err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := src.Token(); err != nil {
			b.Fatalf("Token() error = %v", err)
		}
	}

	b.StopTimer()

	if got := calls.Load(); got != 1 {
		b.Fatalf("benchmark made %d installation-token requests, want 1: the loop was not measuring cache hits", got)
	}
}
