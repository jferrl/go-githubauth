package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerify(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{"zen":"Keep it logically awesome."}`)
	valid := sign(secret, body)

	tests := []struct {
		name    string
		body    []byte
		sig     string
		wantErr error
	}{
		{"valid", body, valid, nil},
		{"missing", body, "", ErrMissingSignature},
		{"wrong prefix", body, "sha1=abcd", ErrInvalidSignatureFormat},
		{"non-hex payload", body, "sha256=zzzz", ErrInvalidSignatureFormat},
		{"tampered body", []byte(`{"zen":"tampered"}`), valid, ErrSignatureMismatch},
		{"wrong secret", body, sign([]byte("other"), body), ErrSignatureMismatch},
		{"empty body valid", []byte{}, sign(secret, []byte{}), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(secret, tt.body, tt.sig)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() err = %v, want errors.Is(%v)", err, tt.wantErr)
			}
		})
	}
}

func TestMiddleware_Valid(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{"action":"opened"}`)

	var gotBody []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, sign(secret, body))
	rec := httptest.NewRecorder()

	Middleware(secret)(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body restored incorrectly: got %q, want %q", gotBody, body)
	}
}

func TestMiddleware_InvalidSignature(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{"action":"opened"}`)

	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, "sha256=deadbeef")
	rec := httptest.NewRecorder()

	Middleware(secret)(next).ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler was called on invalid signature")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_MissingSignature(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{}`)

	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	Middleware(secret)(next).ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler was called without a signature")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_MaxPayloadSize(t *testing.T) {
	secret := []byte("super-secret")
	body := bytes.Repeat([]byte("a"), 1024)

	called := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, sign(secret, body))
	rec := httptest.NewRecorder()

	Middleware(secret, WithMaxPayloadSize(512))(next).ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler was called on oversized body")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte("secret"), []byte(`{"zen":"ok"}`), "sha256=")
	f.Add([]byte{}, []byte{}, "")
	f.Add([]byte("k"), []byte("body"), "sha1=abc")
	f.Fuzz(func(t *testing.T, secret, body []byte, sig string) {
		// Must never panic on arbitrary input.
		_ = Verify(secret, body, sig)

		valid := sign(secret, body)

		// An empty secret is refused no matter how well-formed the signature
		// is, because anyone can compute an HMAC under a zero-length key.
		if len(secret) == 0 {
			if !errors.Is(Verify(secret, body, valid), ErrMissingSecret) {
				t.Fatal("empty secret accepted a self-signed payload")
			}
			return
		}

		// With a real secret, a freshly computed signature must always verify.
		if err := Verify(secret, body, valid); err != nil {
			t.Fatalf("self-signed payload failed: %v", err)
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	secret := []byte("super-secret")
	body := bytes.Repeat([]byte("a"), 4096)
	sig := sign(secret, body)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if err := Verify(secret, body, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func TestMiddleware_CustomErrorHandler(t *testing.T) {
	secret := []byte("super-secret")
	body := []byte(`{}`)

	var captured error
	handler := Middleware(secret, WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		captured = err
		w.WriteHeader(http.StatusTeapot)
	}))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, "sha256=deadbeef")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if !errors.Is(captured, ErrSignatureMismatch) {
		t.Fatalf("captured err = %v, want errors.Is(ErrSignatureMismatch)", captured)
	}
}

// TestVerify_RejectsEmptySecret proves that an empty or nil secret is refused
// rather than used as an HMAC key. HMAC accepts a zero-length key happily, so a
// deployment that wires up Middleware(nil) — a missing env var, a typo'd config
// key — would verify every delivery against a key an attacker can reproduce,
// and forged payloads would sail through as authentic.
func TestVerify_RejectsEmptySecret(t *testing.T) {
	body := []byte(`{"zen":"Keep it logically awesome."}`)

	tests := []struct {
		name   string
		secret []byte
	}{
		{"nil secret", nil},
		{"empty secret", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A signature an attacker can compute without knowing any secret.
			forged := sign(tt.secret, body)

			err := Verify(tt.secret, body, forged)
			if !errors.Is(err, ErrMissingSecret) {
				t.Fatalf("Verify() with %s err = %v, want errors.Is(ErrMissingSecret)", tt.name, err)
			}
		})
	}
}

// TestMiddleware_RejectsEmptySecret proves the middleware refuses a forged
// delivery when it was configured without a secret, instead of passing it to
// the downstream handler as verified.
func TestMiddleware_RejectsEmptySecret(t *testing.T) {
	body := []byte(`{"action":"opened"}`)

	var reached bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, sign(nil, body))
	rec := httptest.NewRecorder()

	Middleware(nil)(next).ServeHTTP(rec, req)

	if reached {
		t.Error("downstream handler was reached; a forged delivery was accepted with no secret configured")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
