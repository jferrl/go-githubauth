# go-githubauth

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/jferrl/go-githubauth)
[![Test Status](https://github.com/jferrl/go-githubauth/workflows/tests/badge.svg)](https://github.com/jferrl/go-githubauth/actions?query=workflow%3Atests)
[![codecov](https://codecov.io/gh/jferrl/go-githubauth/branch/main/graph/badge.svg?token=68I4BZF235)](https://codecov.io/gh/jferrl/go-githubauth)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

GitHub authentication for Go, exposed as standard [`oauth2.TokenSource`](https://pkg.go.dev/golang.org/x/oauth2#TokenSource) implementations: GitHub App JWTs, installation tokens, and personal access tokens. Depends only on `golang-jwt/jwt` and `golang.org/x/oauth2` — no GitHub SDK required.

## Installation

```bash
go get github.com/jferrl/go-githubauth
```

Requires Go 1.25+.

## Quick start

Authenticating as a GitHub App is a two-step chain: an RS256 JWT identifies the App, and it is exchanged for an installation token scoped to one installation. Both sources cache their tokens and refresh them proactively.

```go
privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g. "Iv1.1234567890abcdef"
installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

appTokenSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
if err != nil {
	log.Fatal(err)
}
installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

// Every request carries a valid installation token; refresh is automatic.
// Works standalone or with any SDK that accepts an *http.Client, e.g.
// github.NewClient(httpClient) from google/go-github.
httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
```

`NewApplicationTokenSource` accepts a string Client ID (recommended by GitHub) or an `int64` App ID (legacy) — the type is inferred from the argument. Runnable examples for every constructor live on [pkg.go.dev](https://pkg.go.dev/github.com/jferrl/go-githubauth).

## Features

- `oauth2.TokenSource` implementations for GitHub App JWTs, installation tokens, and personal access tokens (classic and fine-grained)
- Token caching with **proactive refresh**: tokens regenerate 30s before expiry, eliminating in-flight 401s (tunable via `WithExpirySkew` / `WithInstallationExpirySkew`)
- JWT signing through the standard `crypto.Signer` interface, so the private key can live in AWS KMS, GCP KMS, Azure Key Vault, Vault Transit, a PKCS#11 HSM, or ssh-agent
- Webhook delivery verification (`X-Hub-Signature-256`, constant-time) with ready-made `http.Handler` middleware
- GitHub Enterprise Server and GitHub Enterprise Cloud (data residency) support
- Automatic single retry on throttled responses (`WithRetryOnThrottle`, enabled by default)
- Two dependencies total: `golang-jwt/jwt` and `golang.org/x/oauth2`

## Comparison with ghinstallation

[`ghinstallation`](https://github.com/bradleyfalzon/ghinstallation) is the long-standing library in this space and works well. The core difference is the integration model: `ghinstallation` is an `http.RoundTripper` you install as an HTTP transport, while `go-githubauth` implements `oauth2.TokenSource`, so credentials compose with anything that speaks oauth2 — `oauth2.NewClient`, [go-github](https://github.com/google/go-github), gRPC per-RPC credentials, or code that just needs the token string.

|  | go-githubauth | ghinstallation |
|---|---|---|
| Integration model | `oauth2.TokenSource` | `http.RoundTripper` |
| Dependencies | `golang-jwt/jwt`, `x/oauth2` | `golang-jwt/jwt`, `google/go-github` |
| App identifiers | Client ID (`string`, recommended by GitHub) and App ID (`int64`) | App ID (`int64`) |
| Token refresh | Proactive, tunable (`WithExpirySkew`, default 30s) | Proactive, fixed 1 minute |
| External signers (KMS/HSM) | Standard `crypto.Signer` — existing KMS adapters plug in directly | Library-specific `Signer` interface |
| Webhook signature verification | Included (`webhook` subpackage) | Not included |
| Personal access tokens | Included | Not included |
| GitHub Enterprise | `WithEnterpriseURL` (GHES) and `WithBaseURL` (GHEC data residency) | `BaseURL` field |

If `ghinstallation` already fits your setup, there is no urgent reason to switch. Choose `go-githubauth` when you want oauth2-native composition, Client ID support, KMS-backed signing through the standard `crypto.Signer` interface, or a smaller dependency tree.

## Personal access tokens

```go
tokenSource := githubauth.NewPersonalAccessTokenSource(os.Getenv("GITHUB_TOKEN"))
httpClient := oauth2.NewClient(context.Background(), tokenSource)
```

Works with both classic (`ghp_...`) and fine-grained (`github_pat_...`) tokens.

## GitHub Enterprise

- `WithEnterpriseURL` — GitHub Enterprise Server (GHES). The URL is normalized the way GHES expects, appending `/api/v3/` when needed.
- `WithBaseURL` — the URL is used verbatim. Fits GitHub Enterprise Cloud with data residency (`https://api.SUBDOMAIN.ghe.com/`) or an `httptest` server in tests.

```go
githubauth.NewInstallationTokenSource(installationID, appTokenSource,
	githubauth.WithEnterpriseURL("https://github.example.com"))

githubauth.NewInstallationTokenSource(installationID, appTokenSource,
	githubauth.WithBaseURL("https://api.octocorp.ghe.com"))
```

Options combine in any order. An unparseable URL (or a nil client passed to `WithHTTPClient`) is reported by the first `Token()` call instead of silently falling back to the public GitHub API.

## Proactive token refresh

`oauth2.ReuseTokenSource` refreshes a cached token only *after* it expires, so a request that starts just before expiry can reach GitHub with a dead credential and 401. Both constructors instead wrap their sources in `ReuseTokenSourceWithSkew`, refreshing when `time.Until(exp) <= skew` (default `DefaultExpirySkew`, 30s).

```go
appTokenSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey,
	githubauth.WithApplicationTokenExpiration(1*time.Minute),
	githubauth.WithExpirySkew(5*time.Second), // effective validity: 55s
)
```

A zero or negative skew restores exact `oauth2.ReuseTokenSource` behavior. The wrapper is exported as `ReuseTokenSourceWithSkew` for use with any third-party `oauth2.TokenSource`, and is safe for concurrent use.

## Signing with external key stores (KMS, HSM, Vault)

`NewApplicationTokenSourceFromSigner` accepts any RSA-backed [`crypto.Signer`](https://pkg.go.dev/crypto#Signer), so the App private key never touches process memory. GitHub requires RS256; non-RSA signers are rejected at construction time.

```go
// signer: *rsa.PrivateKey, or a wrapper for AWS KMS, GCP KMS, Azure Key
// Vault, Vault Transit, a PKCS#11 HSM, or ssh-agent.
appTokenSource, err := githubauth.NewApplicationTokenSourceFromSigner(clientID, signer)
```

All major backends support the required `RSASSA_PKCS1_V1_5_SHA_256` operation: [AWS KMS](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html), [GCP KMS](https://cloud.google.com/kms/docs/create-validate-signatures), [Azure Key Vault](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign), [Vault Transit](https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data), and [PKCS#11 via crypto11](https://github.com/ThalesGroup/crypto11). Community `crypto.Signer` adapters: [form3tech-oss/jwt-go-aws-kms](https://github.com/form3tech-oss/jwt-go-aws-kms), [salrashid123/signer](https://github.com/salrashid123/signer).

## Webhook verification

The `webhook` subpackage verifies the `X-Hub-Signature-256` header (HMAC-SHA256, constant time) and ships middleware that restores the body for downstream handlers. Failed verifications short-circuit with 401; oversized bodies return 413.

```go
secret := []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))

mux := http.NewServeMux()
mux.HandleFunc("/webhook", handleWebhook) // body is already authenticated here

log.Fatal(http.ListenAndServe(":8080", webhook.Middleware(secret)(mux)))
```

Options: `webhook.WithMaxPayloadSize(n)` (default 25 MiB, GitHub's delivery cap) and `webhook.WithErrorHandler(fn)`.

Outside `net/http` (Lambda, queues), use `webhook.Verify` directly:

```go
if err := webhook.Verify(secret, body, signature); err != nil {
	// branch with errors.Is: webhook.ErrMissingSignature,
	// webhook.ErrInvalidSignatureFormat, webhook.ErrSignatureMismatch
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub. If this package is useful to you, [a star](https://github.com/jferrl/go-githubauth/stargazers) helps others discover it.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
