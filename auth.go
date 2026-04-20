// Package githubauth provides utilities for GitHub authentication,
// including generating and using GitHub App tokens and installation tokens.
//
// This package implements oauth2.TokenSource interfaces for GitHub App
// authentication and GitHub App installation token generation. It is built
// on top of the golang.org/x/oauth2 library.
package githubauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	// DefaultApplicationTokenExpiration is the default expiration time for GitHub App tokens.
	// The maximum allowed expiration is 10 minutes.
	DefaultApplicationTokenExpiration = 10 * time.Minute

	// DefaultExpirySkew is the default early-refresh window applied to cached
	// tokens returned by NewApplicationTokenSource and NewInstallationTokenSource.
	// At 30s the effective validity of a default 10-minute application JWT becomes
	// 9m30s, which is acceptable and eliminates the common in-flight 401 caused
	// by a request starting near exp and arriving at GitHub after exp.
	DefaultExpirySkew = 30 * time.Second

	// bearerTokenType is the token type used for OAuth2 Bearer tokens.
	bearerTokenType = "Bearer"
)

// ReuseTokenSourceWithSkew wraps src so cached tokens are refreshed proactively,
// skew before their expiry. oauth2.ReuseTokenSource refreshes only once exp has
// passed (via oauth2.Token.Valid), so a request that starts at T-100ms with a
// token expiring at T can arrive at GitHub already expired and yield a 401 the
// caller must manually retry. This wrapper refreshes when
// time.Until(t.Expiry) <= skew, cutting out that race.
//
// If skew is zero or negative the wrapper delegates to oauth2.ReuseTokenSource,
// preserving its exact behavior. An initial non-nil t is used until it needs
// refresh under the same rule. The returned source is safe for concurrent use;
// concurrent Token calls that find the cache stale collapse into a single
// upstream fetch.
func ReuseTokenSourceWithSkew(t *oauth2.Token, src oauth2.TokenSource, skew time.Duration) oauth2.TokenSource {
	if skew <= 0 {
		return oauth2.ReuseTokenSource(t, src)
	}
	return &reuseTokenSourceWithSkew{
		t:    t,
		src:  src,
		skew: skew,
	}
}

type reuseTokenSourceWithSkew struct {
	mu   sync.Mutex
	t    *oauth2.Token
	src  oauth2.TokenSource
	skew time.Duration
}

// Token returns the cached token if it is still valid beyond the configured
// skew, otherwise it calls the underlying source and caches the result.
func (r *reuseTokenSourceWithSkew) Token() (*oauth2.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.valid() {
		return r.t, nil
	}
	t, err := r.src.Token()
	if err != nil {
		return nil, err
	}
	r.t = t
	return t, nil
}

func (r *reuseTokenSourceWithSkew) valid() bool {
	if r.t == nil || r.t.AccessToken == "" {
		return false
	}
	if r.t.Expiry.IsZero() {
		return true
	}
	return time.Until(r.t.Expiry) > r.skew
}

// Identifier constrains GitHub App identifiers to int64 (App ID) or string (Client ID).
type Identifier interface {
	~int64 | ~string
}

// applicationTokenSource generates GitHub App JWTs for authentication.
// JWTs are signed with RS256 and include iat, exp, and iss claims per GitHub's requirements.
// Signing is delegated to a crypto.Signer so the private key may live in memory
// (*rsa.PrivateKey), in a KMS/HSM/Vault, or behind ssh-agent.
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
type applicationTokenSource struct {
	issuer     string // App ID (numeric) or Client ID (alphanumeric)
	signer     crypto.Signer
	expiration time.Duration
	skew       time.Duration
}

// ApplicationTokenOpt is a functional option for configuring an applicationTokenSource.
type ApplicationTokenOpt func(*applicationTokenSource)

// WithApplicationTokenExpiration sets the JWT expiration duration.
// Must be between 0 and 10 minutes per GitHub's JWT requirements. Invalid values default to 10 minutes.
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#about-json-web-tokens-jwts
func WithApplicationTokenExpiration(exp time.Duration) ApplicationTokenOpt {
	return func(a *applicationTokenSource) {
		if exp > DefaultApplicationTokenExpiration || exp <= 0 {
			exp = DefaultApplicationTokenExpiration
		}
		a.expiration = exp
	}
}

// WithExpirySkew overrides the default early-refresh window (DefaultExpirySkew,
// 30s) applied to the token cache returned by NewApplicationTokenSource. The
// cached token is refreshed when time.Until(exp) <= d. A zero or negative value
// disables the skew and falls back to oauth2.ReuseTokenSource behavior
// (refresh only after exp has passed).
//
// Tune this when your application token expiration (see
// WithApplicationTokenExpiration) is short: the effective validity is
// expiration - skew, so with the default 10-minute expiration and 30s skew
// tokens are refreshed at 9m30s.
func WithExpirySkew(d time.Duration) ApplicationTokenOpt {
	return func(a *applicationTokenSource) {
		a.skew = d
	}
}

// NewApplicationTokenSource creates a GitHub App JWT token source from a
// PEM-encoded RSA private key.
// Accepts either int64 App ID or string Client ID. GitHub recommends Client IDs for new apps.
// Generated JWTs are RS256-signed with iat, exp, and iss claims.
// JWTs expire in max 10 minutes and include clock drift protection (iat set 60s in past).
//
// The returned token source is wrapped in ReuseTokenSourceWithSkew with
// DefaultExpirySkew (30s), so cached tokens are refreshed before exp rather
// than after. With the default 10-minute expiration the effective validity
// is 9m30s. Override with WithExpirySkew.
//
// For KMS, HSM, Vault, or ssh-agent backed signing, use
// NewApplicationTokenSourceFromSigner instead — the private key never leaves
// its secure boundary.
//
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
func NewApplicationTokenSource[T Identifier](id T, privateKey []byte, opts ...ApplicationTokenOpt) (oauth2.TokenSource, error) {
	issuer, err := resolveIssuer(id)
	if err != nil {
		return nil, err
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, err
	}

	return newApplicationTokenSource(issuer, privKey, opts...), nil
}

// NewApplicationTokenSourceFromSigner creates a GitHub App JWT token source
// backed by an external crypto.Signer. Any RSA-backed signer works: AWS KMS,
// GCP KMS, Azure Key Vault, HashiCorp Vault Transit, PKCS#11 HSMs, or
// ssh-agent. The private key never touches process memory.
//
// The signer's public key must be RSA — GitHub requires RS256 (RSASSA-PKCS1-v1_5
// with SHA-256, per RFC 7518 §3.3). The signer must return signatures in that
// form when called with crypto.SHA256; every stdlib-compatible RSA signer does.
//
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
func NewApplicationTokenSourceFromSigner[T Identifier](id T, signer crypto.Signer, opts ...ApplicationTokenOpt) (oauth2.TokenSource, error) {
	issuer, err := resolveIssuer(id)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("signer is required")
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, errors.New("signer public key must be RSA (GitHub requires RS256)")
	}

	return newApplicationTokenSource(issuer, signer, opts...), nil
}

// resolveIssuer converts a generic App ID / Client ID to its string form
// and rejects zero values.
func resolveIssuer[T Identifier](id T) (string, error) {
	switch v := any(id).(type) {
	case int64:
		if v == 0 {
			return "", errors.New("application identifier is required")
		}
		return strconv.FormatInt(v, 10), nil
	case string:
		if v == "" {
			return "", errors.New("application identifier is required")
		}
		return v, nil
	default:
		return "", errors.New("unsupported identifier type")
	}
}

func newApplicationTokenSource(issuer string, signer crypto.Signer, opts ...ApplicationTokenOpt) oauth2.TokenSource {
	t := &applicationTokenSource{
		issuer:     issuer,
		signer:     signer,
		expiration: DefaultApplicationTokenExpiration,
		skew:       DefaultExpirySkew,
	}
	for _, opt := range opts {
		opt(t)
	}
	return ReuseTokenSourceWithSkew(nil, t, t.skew)
}

// Token generates a GitHub App JWT with required claims: iat, exp, iss, and alg.
// The iat claim is set 60 seconds in the past to account for clock drift.
// Signing is routed through the configured crypto.Signer.
// Generated JWTs can be used with "Authorization: Bearer" header for GitHub API requests.
func (t *applicationTokenSource) Token() (*oauth2.Token, error) {
	// To protect against clock drift, set the issuance time 60 seconds in the past.
	now := time.Now().Add(-60 * time.Second)
	expiresAt := now.Add(t.expiration)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    t.issuer,
	})

	signingString, err := token.SigningString()
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(signingString))
	sig, err := t.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: signingString + "." + base64.RawURLEncoding.EncodeToString(sig),
		TokenType:   bearerTokenType,
		Expiry:      expiresAt,
	}, nil
}

// InstallationTokenSourceOpt is a functional option for InstallationTokenSource.
type InstallationTokenSourceOpt func(*installationTokenSource)

// WithInstallationTokenOptions sets the options for the GitHub App installation token.
func WithInstallationTokenOptions(opts *InstallationTokenOptions) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		i.opts = opts
	}
}

// WithHTTPClient sets the HTTP client for the GitHub App installation token source.
func WithHTTPClient(client *http.Client) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		client.Transport = &oauth2.Transport{
			Source: i.src,
			Base:   client.Transport,
		}

		i.client = newGitHubClient(client)
	}
}

// WithEnterpriseURL sets the base URL for GitHub Enterprise Server.
// This option should be used after WithHTTPClient to ensure the HTTP client is properly configured.
// If the provided base URL is invalid, the option is ignored and default GitHub base URL is used.
func WithEnterpriseURL(baseURL string) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		enterpriseClient, err := i.client.withEnterpriseURL(baseURL)
		if err != nil {
			return
		}

		i.client = enterpriseClient
	}
}

// WithContext sets the context for the GitHub App installation token source.
func WithContext(ctx context.Context) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		i.ctx = ctx
	}
}

// WithRetryOnThrottle enables or disables a single automatic retry when
// GitHub returns a throttled response (HTTP 429, or 403 with rate-limit
// headers) for the installation token POST. Enabled by default.
//
// On a throttled response the client sleeps the duration hinted by
// Retry-After or x-ratelimit-reset (capped at 60s, honoring ctx cancellation)
// and retries once. Subsequent failures bubble up unchanged. On a terminal
// throttle the returned error wraps ErrRateLimited so callers can branch with
// errors.Is.
//
// Disable this when the caller implements its own backoff or when deterministic
// latency matters more than transient rate-limit resilience.
func WithRetryOnThrottle(enabled bool) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		i.client.retryOnThrottle = enabled
	}
}

// WithInstallationExpirySkew overrides the default early-refresh window
// (DefaultExpirySkew, 30s) applied to the installation token cache returned
// by NewInstallationTokenSource. Installation tokens live 1 hour, so the 30s
// default leaves ~59m30s effective validity — this option exists mostly for
// parity with WithExpirySkew. A zero or negative value falls back to
// oauth2.ReuseTokenSource behavior.
func WithInstallationExpirySkew(d time.Duration) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		i.skew = d
	}
}

// installationTokenSource represents a GitHub App installation token source
// that generates access tokens for authenticating as a specific GitHub App installation.
//
// See: https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
type installationTokenSource struct {
	id     int64
	ctx    context.Context
	src    oauth2.TokenSource
	client *githubClient
	opts   *InstallationTokenOptions
	skew   time.Duration
}

// NewInstallationTokenSource creates a GitHub App installation token source.
// Requires installation ID and a GitHub App JWT token source for authentication.
//
// The returned token source is wrapped in ReuseTokenSourceWithSkew so cached
// tokens are refreshed DefaultExpirySkew before their expiry, eliminating
// in-flight 401s when a request starts close to exp and reaches GitHub after.
// Override the window with WithInstallationExpirySkew.
//
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
func NewInstallationTokenSource(id int64, src oauth2.TokenSource, opts ...InstallationTokenSourceOpt) oauth2.TokenSource {
	ctx := context.Background()

	httpClient := cleanHTTPClient()
	httpClient.Transport = &oauth2.Transport{
		Source: oauth2.ReuseTokenSource(nil, src),
		Base:   httpClient.Transport,
	}

	i := &installationTokenSource{
		id:     id,
		ctx:    ctx,
		src:    src,
		client: newGitHubClient(httpClient),
		skew:   DefaultExpirySkew,
	}

	for _, opt := range opts {
		opt(i)
	}

	return ReuseTokenSourceWithSkew(nil, i, i.skew)
}

// Token generates a new GitHub App installation token for authenticating as a GitHub App installation.
func (t *installationTokenSource) Token() (*oauth2.Token, error) {
	token, err := t.client.createInstallationToken(t.ctx, t.id, t.opts)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: token.Token,
		TokenType:   bearerTokenType,
		Expiry:      token.ExpiresAt,
	}, nil
}

// personalAccessTokenSource represents a static GitHub personal access token source
// that provides OAuth2 authentication using a pre-generated token.
// Personal access tokens can be classic or fine-grained and provide access to repositories
// based on the token's configured permissions and scope.
//
// See: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
type personalAccessTokenSource struct {
	token string
}

// NewPersonalAccessTokenSource creates a token source for GitHub personal access tokens.
// The provided token should be a valid GitHub personal access token (classic or fine-grained).
// This token source returns the same token value for all Token() calls without expiration,
// making it suitable for long-lived authentication scenarios.
func NewPersonalAccessTokenSource(token string) oauth2.TokenSource {
	return &personalAccessTokenSource{
		token: token,
	}
}

// Token returns the configured personal access token as an OAuth2 token.
// The returned token has no expiry time since personal access tokens
// remain valid until manually revoked or expired by GitHub.
func (t *personalAccessTokenSource) Token() (*oauth2.Token, error) {
	if t.token == "" {
		return nil, errors.New("token not provided")
	}

	return &oauth2.Token{
		AccessToken: t.token,
		TokenType:   bearerTokenType,
	}, nil
}
