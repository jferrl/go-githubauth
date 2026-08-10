package webhook_test

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jferrl/go-githubauth/webhook"
)

// Middleware verifies X-Hub-Signature-256 on every delivery and restores the
// request body before invoking the wrapped handler. Failed verifications
// short-circuit with 401; oversized bodies return 413.
func ExampleMiddleware() {
	secret := []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		// The body reaching this handler is already authenticated.
		event := r.Header.Get(webhook.EventHeader)
		delivery := r.Header.Get(webhook.DeliveryHeader)

		log.Printf("received %s delivery=%s", event, delivery)
		w.WriteHeader(http.StatusNoContent)
	})

	log.Fatal(http.ListenAndServe(":8080", webhook.Middleware(secret)(mux)))
}

// Verify checks a delivery outside net/http — AWS Lambda, Cloud Run event
// triggers, or messages consumed from a queue.
func ExampleVerify() {
	secret := []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))
	body := []byte(`{"action":"opened"}`)
	signature := "sha256=..." // value of the X-Hub-Signature-256 header

	err := webhook.Verify(secret, body, signature)
	switch {
	case err == nil:
		// body is trusted from here
	case errors.Is(err, webhook.ErrMissingSignature):
		fmt.Println("header absent")
	case errors.Is(err, webhook.ErrInvalidSignatureFormat):
		fmt.Println("malformed header")
	case errors.Is(err, webhook.ErrSignatureMismatch):
		fmt.Println("wrong secret or tampered body")
	}
}
