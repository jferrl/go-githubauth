// Package webhook verifies GitHub webhook deliveries.
//
// GitHub signs each webhook delivery with HMAC-SHA256 over the raw request
// body using the secret configured on the webhook. This package verifies the
// X-Hub-Signature-256 header in constant time and exposes an http.Handler
// middleware for ergonomic integration.
//
// See https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Header names GitHub sets on every webhook delivery.
const (
	SignatureHeader = "X-Hub-Signature-256"
	EventHeader     = "X-GitHub-Event"
	DeliveryHeader  = "X-GitHub-Delivery"
)

// DefaultMaxPayloadSize matches GitHub's documented 25 MiB delivery cap.
const DefaultMaxPayloadSize int64 = 25 * 1024 * 1024

const signaturePrefix = "sha256="

// Sentinel errors returned by Verify. Callers can branch with errors.Is.
var (
	ErrMissingSignature       = errors.New("webhook: missing signature header")
	ErrInvalidSignatureFormat = errors.New("webhook: invalid signature format")
	ErrSignatureMismatch      = errors.New("webhook: signature mismatch")
)

// Verify reports whether signature is a valid HMAC-SHA256 of body using secret.
// signature must be in GitHub's "sha256=<hex>" form, as delivered in the
// X-Hub-Signature-256 header. Comparison runs in constant time.
func Verify(secret, body []byte, signature string) error {
	if signature == "" {
		return ErrMissingSignature
	}

	hexSig, ok := strings.CutPrefix(signature, signaturePrefix)
	if !ok {
		return fmt.Errorf("%w: expected %q prefix", ErrInvalidSignatureFormat, signaturePrefix)
	}

	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignatureFormat, err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return ErrSignatureMismatch
	}
	return nil
}

// MiddlewareOpt configures Middleware.
type MiddlewareOpt func(*middlewareConfig)

type middlewareConfig struct {
	maxPayloadSize int64
	onError        func(http.ResponseWriter, *http.Request, error)
}

// WithMaxPayloadSize overrides the request body size cap. A non-positive value
// disables the cap, which is not recommended in production.
func WithMaxPayloadSize(n int64) MiddlewareOpt {
	return func(c *middlewareConfig) { c.maxPayloadSize = n }
}

// WithErrorHandler overrides how verification failures are reported. The
// default writes 401 Unauthorized (or 413 for oversized bodies) with no body.
func WithErrorHandler(fn func(http.ResponseWriter, *http.Request, error)) MiddlewareOpt {
	return func(c *middlewareConfig) { c.onError = fn }
}

// Middleware returns net/http middleware that verifies the signature header
// against secret before invoking next. Failed verifications short-circuit
// with 401 Unauthorized; bodies larger than the configured cap return 413.
// The request body is restored for downstream handlers.
func Middleware(secret []byte, opts ...MiddlewareOpt) func(http.Handler) http.Handler {
	cfg := middlewareConfig{maxPayloadSize: DefaultMaxPayloadSize}
	for _, o := range opts {
		o(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reader := r.Body
			if cfg.maxPayloadSize > 0 {
				reader = http.MaxBytesReader(w, r.Body, cfg.maxPayloadSize)
			}

			body, err := io.ReadAll(reader)
			if err != nil {
				handleErr(w, r, cfg.onError, err)
				return
			}

			if err := Verify(secret, body, r.Header.Get(SignatureHeader)); err != nil {
				handleErr(w, r, cfg.onError, err)
				return
			}

			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			next.ServeHTTP(w, r)
		})
	}
}

func handleErr(w http.ResponseWriter, r *http.Request, custom func(http.ResponseWriter, *http.Request, error), err error) {
	if custom != nil {
		custom(w, r, err)
		return
	}

	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "signature verification failed", http.StatusUnauthorized)
}
