// Package githubauth provides GitHub authentication as standard
// [golang.org/x/oauth2.TokenSource] implementations: GitHub App JWTs,
// GitHub App installation tokens, and personal access tokens.
//
// Because every credential is exposed through the oauth2.TokenSource
// interface, the package composes with anything that accepts one —
// [golang.org/x/oauth2.NewClient], the google/go-github SDK, gRPC per-RPC
// credentials, or code that simply needs the token string. The module
// depends only on github.com/golang-jwt/jwt and golang.org/x/oauth2; no
// GitHub SDK is required.
//
// # GitHub App authentication
//
// Authenticating as a GitHub App is a two-step chain: a short-lived
// RS256-signed JWT identifies the App itself, and that JWT is exchanged for
// an installation access token scoped to one installation of the App.
//
//	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
//	clientID := os.Getenv("GITHUB_APP_CLIENT_ID")
//	installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)
//
//	appSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
//	if err != nil {
//		// handle error
//	}
//	installationSource := githubauth.NewInstallationTokenSource(installationID, appSource)
//
//	// httpClient authenticates every request with a fresh installation token.
//	httpClient := oauth2.NewClient(context.Background(), installationSource)
//
// NewApplicationTokenSource accepts either a string Client ID (recommended
// by GitHub for new Apps) or an int64 App ID (legacy); the type parameter is
// inferred from the argument.
//
// # Token caching and proactive refresh
//
// Both NewApplicationTokenSource and NewInstallationTokenSource wrap their
// sources in ReuseTokenSourceWithSkew: tokens are cached and refreshed
// DefaultExpirySkew (30 seconds) before expiry rather than after it, so a
// request that starts near the expiry instant never reaches GitHub with an
// already-expired credential. The window is tunable with WithExpirySkew
// (application JWTs) and WithInstallationExpirySkew (installation tokens).
//
// # Recovering from a revoked token
//
// Expiry is not the only way a token dies. GitHub revokes an installation
// token when the App is suspended, when its permissions change, on an explicit
// revocation, and it revokes every token for an installation when the private
// key is rotated. A cache keyed on expiry cannot see any of that, so it keeps
// serving the dead credential and every request 401s until the hour is up.
//
// Invalidate discards the cached token so the next call mints a fresh one:
//
//	resp, err := client.Do(req)
//	if resp.StatusCode == http.StatusUnauthorized {
//		githubauth.Invalidate(installationSource)
//		// retry once
//	}
//
// It reports false for a source with nothing to discard, such as
// NewPersonalAccessTokenSource. Sources cache independently, so invalidating an
// installation token source does not touch the application JWT behind it.
//
// # Signing with external key stores
//
// NewApplicationTokenSourceFromSigner accepts any RSA-backed [crypto.Signer]
// — AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault Transit,
// PKCS#11 HSMs, or ssh-agent — so the App private key never enters process
// memory. GitHub requires RS256; non-RSA signers are rejected at
// construction time.
//
// # GitHub Enterprise
//
// WithEnterpriseURL targets GitHub Enterprise Server, normalizing the URL
// the way GHES expects (appending /api/v3/ when needed). WithBaseURL uses
// the supplied URL verbatim, which fits GitHub Enterprise Cloud with data
// residency (https://api.SUBDOMAIN.ghe.com/) and httptest servers.
//
// # Webhook verification
//
// The webhook subpackage verifies GitHub webhook deliveries
// (X-Hub-Signature-256, HMAC-SHA256 in constant time) and ships an
// http.Handler middleware that restores the request body for downstream
// handlers. See github.com/jferrl/go-githubauth/webhook.
package githubauth
