# go-githubauth

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/jferrl/go-githubauth)
[![Test Status](https://github.com/jferrl/go-githubauth/workflows/tests/badge.svg)](https://github.com/jferrl/go-githubauth/actions?query=workflow%3Atests)
[![codecov](https://codecov.io/gh/jferrl/go-githubauth/branch/main/graph/badge.svg?token=68I4BZF235)](https://codecov.io/gh/jferrl/go-githubauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/jferrl/go-githubauth)](https://goreportcard.com/report/github.com/jferrl/go-githubauth)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

`go-githubauth` is a Go package that provides utilities for GitHub authentication, including generating and using GitHub App tokens, installation tokens, and personal access tokens.

**v1.5.0** removes the `go-github` dependency, implementing a lightweight internal GitHub API client. This reduces external dependencies while maintaining full compatibility with the OAuth2 token source interface.

---

⭐ **Found this package useful?** Give it a star on GitHub! Your support helps others discover this project and motivates continued development.

[![Star this repo](https://img.shields.io/github/stars/jferrl/go-githubauth?style=social)](https://github.com/jferrl/go-githubauth/stargazers)

**Share this project:**
[![Share on X](https://img.shields.io/badge/share%20on-X-1DA1F2?logo=x&style=flat-square)](https://twitter.com/intent/tweet?text=Check%20out%20go-githubauth%20-%20a%20Go%20package%20for%20GitHub%20App%20authentication%20with%20JWT%20and%20installation%20tokens!&url=https://github.com/jferrl/go-githubauth&hashtags=golang,github,authentication,jwt)
[![Share on Reddit](https://img.shields.io/badge/share%20on-reddit-FF4500?logo=reddit&style=flat-square)](https://reddit.com/submit?url=https://github.com/jferrl/go-githubauth&title=go-githubauth:%20Go%20package%20for%20GitHub%20App%20authentication)

---

## Features

`go-githubauth` package provides implementations of the `TokenSource` interface from the `golang.org/x/oauth2` package. This interface has a single method, Token, which returns an *oauth2.Token.

### v1.5.0 Features

- **📦 Zero External Dependencies**: Removed `go-github` dependency - lightweight internal implementation
- **🔐 Personal Access Token Support**: Native support for both classic and fine-grained personal access tokens
- **⚡ Token Caching**: Dual-layer caching system for optimal performance
  - JWT tokens cached until expiration (up to 10 minutes)  
  - Installation tokens cached until expiration (defined by GitHub response)
- **🚀 Pooled HTTP Client**: Production-ready HTTP client with connection pooling
- **📈 Performance Optimizations**: Up to 99% reduction in unnecessary GitHub API calls
- **🏗️ Production Ready**: Optimized for high-throughput and enterprise applications
- **🌐 Simplified Enterprise Support**: Streamlined configuration with single base URL parameter

### Core Capabilities

- Generate GitHub Application JWT [Generating a jwt for a github app](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- Obtain GitHub App installation tokens [Authenticating as a GitHub App](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api?apiVersion=2022-11-28#authenticating-with-a-token-generated-by-an-app)
- Authenticate with Personal Access Tokens (classic and fine-grained) [Managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- Verify incoming webhook deliveries with constant-time HMAC-SHA256 checks [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- Sign JWTs with external `crypto.Signer` backends (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit, PKCS#11 HSMs, ssh-agent) so the private key never touches process memory
- RS256-signed JWTs with proper clock drift protection
- Support for both legacy App IDs and modern Client IDs (recommended by GitHub)
- Intelligent token caching with **proactive refresh** — tokens are regenerated 30s before expiry to eliminate in-flight 401s (tunable via `WithExpirySkew` / `WithInstallationExpirySkew`)
- Clean HTTP clients with connection pooling and no shared state

### Requirements

- Go 1.25 or higher (required by `golang.org/x/oauth2`)
- This package is designed to be used with the `golang.org/x/oauth2` package
- No external GitHub SDK dependencies required

## Installation

To use `go-githubauth` in your project, you need to have Go installed. You can get the package via:

```bash
go get -u github.com/jferrl/go-githubauth
```

## Usage

### Usage with [oauth2](golang.org/x/oauth2)

You can use this package standalone with any HTTP client, or integrate it with the [go-github](https://github.com/google/go-github) SDK if you need additional GitHub API functionality.

#### Client ID (Recommended)

```go
package main

import (
 "context"
 "fmt"
 "os"
 "strconv"

 "github.com/google/go-github/v76/github"
 "github.com/jferrl/go-githubauth"
 "golang.org/x/oauth2"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g., "Iv1.1234567890abcdef"
 installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

 // Go automatically infers the type as string for Client ID
 appTokenSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

 // oauth2.NewClient creates a new http.Client that adds an Authorization header with the token
 httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
 githubClient := github.NewClient(httpClient)

 _, _, err = githubClient.PullRequests.CreateComment(context.Background(), "owner", "repo", 1, &github.PullRequestComment{
  Body: github.String("Awesome comment!"),
 })
 if err != nil {
  fmt.Println("Error creating comment:", err)
  return
 }
}
```

#### App ID (Legacy)

```go
package main

import (
 "context"
 "fmt"
 "os"
 "strconv"

 "github.com/google/go-github/v76/github"
 "github.com/jferrl/go-githubauth"
 "golang.org/x/oauth2"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 appID, _ := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
 installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

 // Explicitly cast to int64 for App ID - Go automatically infers the type
 appTokenSource, err := githubauth.NewApplicationTokenSource(int64(appID), privateKey)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

 httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
 githubClient := github.NewClient(httpClient)

 _, _, err = githubClient.PullRequests.CreateComment(context.Background(), "owner", "repo", 1, &github.PullRequestComment{
  Body: github.String("Awesome comment!"),
 })
 if err != nil {
  fmt.Println("Error creating comment:", err)
  return
 }
}
```

### Generate GitHub Application Token

First, create a GitHub App and generate a private key. To authenticate as a GitHub App, you need to generate a JWT. [Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)

#### With Client ID (Recommended)

```go
package main

import (
 "fmt"
 "os"
 "time"

 "github.com/jferrl/go-githubauth"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g., "Iv1.1234567890abcdef"

 // Type automatically inferred as string
 tokenSource, err := githubauth.NewApplicationTokenSource(
  clientID, 
  privateKey, 
  githubauth.WithApplicationTokenExpiration(5*time.Minute),
 )
 if err != nil {
  fmt.Println("Error creating token source:", err)
  return
 }

 token, err := tokenSource.Token()
 if err != nil {
  fmt.Println("Error generating token:", err)
  return
 }

 fmt.Println("Generated JWT token:", token.AccessToken)
}
```

#### With App ID

```go
package main

import (
 "fmt"
 "os"
 "strconv"
 "time"

 "github.com/jferrl/go-githubauth"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 appID, _ := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)

 // Type automatically inferred as int64
 tokenSource, err := githubauth.NewApplicationTokenSource(
  int64(appID), 
  privateKey, 
  githubauth.WithApplicationTokenExpiration(5*time.Minute),
 )
 if err != nil {
  fmt.Println("Error creating token source:", err)
  return
 }

 token, err := tokenSource.Token()
 if err != nil {
  fmt.Println("Error generating token:", err)
  return
 }

 fmt.Println("Generated JWT token:", token.AccessToken)
}
```

### Generate GitHub App Installation Token

To authenticate as a GitHub App installation, you need to obtain an installation token using your GitHub App JWT.

```go
package main

import (
 "fmt"
 "os"
 "strconv"

 "github.com/jferrl/go-githubauth"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g., "Iv1.1234567890abcdef"
 installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

 // Create GitHub App JWT token source with Client ID
 appTokenSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 // Create installation token source using the app token source
 installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

 token, err := installationTokenSource.Token()
 if err != nil {
  fmt.Println("Error generating installation token:", err)
  return
 }

 fmt.Println("Generated installation token:", token.AccessToken)
}
```

### Proactive Token Refresh

`oauth2.ReuseTokenSource` only refreshes a cached token *after* its expiry has passed. A request that starts at `T-100ms` with a token expiring at `T` can arrive at GitHub with an already-expired credential and receive a 401 that the caller must manually retry. This is especially painful with short application-token windows (default 10 min, optionally lower).

Both `NewApplicationTokenSource` and `NewInstallationTokenSource` wrap the returned source in `ReuseTokenSourceWithSkew`, which refreshes when `time.Until(exp) <= skew`. The default `DefaultExpirySkew` is **30 seconds**, so a default 10-minute application JWT has ~9m30s of effective validity — the tail risk is closed, the overhead is negligible.

```go
// Use a shorter skew (e.g. to maximize validity for very short JWTs).
appTokenSource, err := githubauth.NewApplicationTokenSource(
    clientID,
    privateKey,
    githubauth.WithApplicationTokenExpiration(1*time.Minute),
    githubauth.WithExpirySkew(5*time.Second),
)

// Override the installation-layer skew too (default 30s is usually fine for 1h tokens).
installationTokenSource := githubauth.NewInstallationTokenSource(
    installationID,
    appTokenSource,
    githubauth.WithInstallationExpirySkew(1*time.Minute),
)
```

Passing `WithExpirySkew(0)` (or any non-positive value) disables the skew and falls back to the exact `oauth2.ReuseTokenSource` behavior. For third-party `oauth2.TokenSource` implementations outside this package, `ReuseTokenSourceWithSkew` is exported directly:

```go
src := githubauth.ReuseTokenSourceWithSkew(nil, someTokenSource, 30*time.Second)
```

The wrapper is safe for concurrent use — concurrent `Token()` calls that find the cache stale collapse into a single upstream fetch.

### Signing with External Key Stores (AWS KMS, GCP KMS, Vault, HSM)

For regulated or high-security environments, the private key should never leave its secure boundary. `NewApplicationTokenSourceFromSigner` accepts any `crypto.Signer` whose public key is RSA — AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault Transit, PKCS#11 HSMs, and ssh-agent all fit.

The same `crypto.Signer` call (`Sign(rand, digest, crypto.SHA256)`) maps to each backend's native RSASSA-PKCS1-v1_5 SHA-256 signing operation. GitHub requires RS256.

```go
package main

import (
 "context"
 "fmt"
 "os"

 "github.com/jferrl/go-githubauth"
)

func main() {
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID")

 // signer is any crypto.Signer backed by an RSA key: *rsa.PrivateKey,
 // an AWS KMS wrapper, a GCP KMS wrapper, a Vault Transit wrapper,
 // a PKCS#11 HSM library like github.com/ThalesGroup/crypto11, or
 // an ssh-agent adapter. The private key never touches process memory.
 signer := newKMSBackedSigner(context.Background(), os.Getenv("KMS_KEY_ARN"))

 appTokenSource, err := githubauth.NewApplicationTokenSourceFromSigner(clientID, signer)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 token, err := appTokenSource.Token()
 if err != nil {
  fmt.Println("Error generating JWT:", err)
  return
 }

 fmt.Println("Generated JWT token:", token.AccessToken)
}
```

Backend references (all support `RSASSA_PKCS1_V1_5_SHA_256` on RSA keys ≥ 2048):

- **AWS KMS** — [Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html), [`service/kms`](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/kms). Community adapters: [form3tech-oss/jwt-go-aws-kms](https://github.com/form3tech-oss/jwt-go-aws-kms), [salrashid123/signer](https://github.com/salrashid123/signer)
- **Google Cloud KMS** — [Create and validate signatures](https://cloud.google.com/kms/docs/create-validate-signatures), [`cloud.google.com/go/kms/apiv1`](https://pkg.go.dev/cloud.google.com/go/kms/apiv1). Adapter: [salrashid123/signer/kms](https://github.com/salrashid123/signer/tree/master/kms)
- **HashiCorp Vault Transit** — [Sign data](https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data). Adapter: [salrashid123/signer/vault](https://github.com/salrashid123/signer/tree/master/vault)
- **Azure Key Vault** — [Sign API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign) with `alg=RS256`
- **PKCS#11 / HSM** — [ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11) implements `crypto.Signer` directly, no adapter needed

**🔐 Security Note**: The signer's public key must be RSA. The constructor rejects non-RSA signers (ECDSA, ed25519) at construction time since GitHub requires RS256.

### Personal Access Token Authentication

GitHub Personal Access Tokens provide direct authentication for users and organizations. This package supports both classic personal access tokens and fine-grained personal access tokens.

#### Using Personal Access Tokens

##### With oauth2 Client (Standalone)

```go
package main

import (
 "context"
 "fmt"
 "io"
 "net/http"
 "os"

 "github.com/jferrl/go-githubauth"
 "golang.org/x/oauth2"
)

func main() {
 // Personal access token from environment variable
 token := os.Getenv("GITHUB_TOKEN") // e.g., "ghp_..." or "github_pat_..."

 // Create token source
 tokenSource := githubauth.NewPersonalAccessTokenSource(token)

 // Create HTTP client with OAuth2 transport
 httpClient := oauth2.NewClient(context.Background(), tokenSource)

 // Use the HTTP client for GitHub API calls
 resp, err := httpClient.Get("https://api.github.com/user")
 if err != nil {
  fmt.Println("Error getting user:", err)
  return
 }
 defer resp.Body.Close()

 body, _ := io.ReadAll(resp.Body)
 fmt.Printf("User info: %s\n", body)
}
```

##### With go-github SDK (Optional)

```go
package main

import (
 "context"
 "fmt"
 "os"

 "github.com/google/go-github/v76/github"
 "github.com/jferrl/go-githubauth"
 "golang.org/x/oauth2"
)

func main() {
 // Personal access token from environment variable
 token := os.Getenv("GITHUB_TOKEN") // e.g., "ghp_..." or "github_pat_..."

 // Create token source
 tokenSource := githubauth.NewPersonalAccessTokenSource(token)

 // Create HTTP client with OAuth2 transport
 httpClient := oauth2.NewClient(context.Background(), tokenSource)
 githubClient := github.NewClient(httpClient)

 // Use the GitHub client for API calls
 user, _, err := githubClient.Users.Get(context.Background(), "")
 if err != nil {
  fmt.Println("Error getting user:", err)
  return
 }

 fmt.Printf("Authenticated as: %s\n", user.GetLogin())
}
```

#### Creating Personal Access Tokens

1. **Classic Personal Access Token**: Visit [GitHub Settings > Developer settings > Personal access tokens > Tokens (classic)](https://github.com/settings/tokens)
2. **Fine-grained Personal Access Token**: Visit [GitHub Settings > Developer settings > Personal access tokens > Fine-grained tokens](https://github.com/settings/personal-access-tokens/new)

**🔐 Security Note**: Store your personal access tokens securely and never commit them to version control. Use environment variables or secure credential management systems.

### Webhook Signature Verification

GitHub signs every webhook delivery with HMAC-SHA256 over the raw request body, using the secret configured on the webhook. The `webhook` subpackage verifies the `X-Hub-Signature-256` header in constant time and ships an `http.Handler` middleware that restores the body for downstream handlers.

See [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

#### With the middleware (recommended)

```go
package main

import (
 "encoding/json"
 "log"
 "net/http"
 "os"

 "github.com/jferrl/go-githubauth/webhook"
)

func main() {
 secret := []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))

 mux := http.NewServeMux()
 mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
  event := r.Header.Get(webhook.EventHeader)
  delivery := r.Header.Get(webhook.DeliveryHeader)

  var payload map[string]any
  if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
   http.Error(w, "bad payload", http.StatusBadRequest)
   return
  }

  log.Printf("received %s delivery=%s", event, delivery)
  w.WriteHeader(http.StatusNoContent)
 })

 // Middleware verifies the signature, restores r.Body, then invokes mux.
 // Failed verifications short-circuit with 401; oversized bodies return 413.
 log.Fatal(http.ListenAndServe(":8080", webhook.Middleware(secret)(mux)))
}
```

Middleware options:

- `webhook.WithMaxPayloadSize(n int64)` — override the 25 MiB default cap (GitHub's documented delivery limit).
- `webhook.WithErrorHandler(fn)` — customize the response for verification failures (e.g., structured logging, alternate status codes).

#### Direct verification (queues, Lambda, custom transports)

Use `webhook.Verify` when the request does not arrive through `net/http`, for example in AWS Lambda, Cloud Run event triggers, or after consuming from a message queue.

```go
import (
 "errors"

 "github.com/jferrl/go-githubauth/webhook"
)

func handle(secret, body []byte, signature string) error {
 if err := webhook.Verify(secret, body, signature); err != nil {
  switch {
  case errors.Is(err, webhook.ErrMissingSignature):
   // header absent
  case errors.Is(err, webhook.ErrInvalidSignatureFormat):
   // malformed header
  case errors.Is(err, webhook.ErrSignatureMismatch):
   // wrong secret or tampered body
  }
  return err
 }
 // body is trusted from here
 return nil
}
```

**🔐 Security Note**: Store the webhook secret with the same care as a credential. A leaked secret lets an attacker forge deliveries to your endpoint.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
