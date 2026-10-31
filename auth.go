package githubauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	// DefaultApplicationTokenExpiration is the default expiration time for GitHub App tokens.
	// The maximum allowed expiration is 10 minutes.
	DefaultApplicationTokenExpiration = 10 * time.Minute

	// DefaultExpirySkew is the default early-refresh window applied to cached
	// tokens returned by NewApplicationTokenSource and NewInstallationTokenSource.
	// At 30s the effective validity of a default 10-minute application JWT becomes
	// 8m30s, which is acceptable and eliminates the common in-flight 401 caused
	// by a request starting near exp and arriving at GitHub after exp.
	DefaultExpirySkew = 30 * time.Second

	// ExtraPermissions is the oauth2.Token Extra key under which an installation
	// token carries the permissions GitHub granted it, as a map[string]string.
	ExtraPermissions = "permissions"

	// ExtraRepositories is the oauth2.Token Extra key under which an
	// installation token limited to some repositories carries their names, as a
	// []string. It is absent for a token covering the whole installation.
	ExtraRepositories = "repositories"

	// applicationTokenBackdate is how far into the past the iat claim of an
	// application JWT is set, so a fast local clock cannot make GitHub see an
	// iat in the future. It is subtracted from exp as well, so it is also the
	// lower bound an expiration must exceed to yield a usable token.
	applicationTokenBackdate = 60 * time.Second

	// minApplicationTokenExpiration is the smallest expiration that yields a
	// token the cache can actually hold: it must clear the backdate (or the JWT
	// is born expired) and then the refresh skew on top (or every Token() call
	// re-signs). Expirations at or below it fall back to the default.
	minApplicationTokenExpiration = applicationTokenBackdate + DefaultExpirySkew

	// bearerTokenType is the token type used for OAuth2 Bearer tokens.
	bearerTokenType = "Bearer"
)

// ReuseTokenSourceWithSkew wraps src so a cached token is refreshed skew before
// it expires, rather than oauth2's default of 10s, so a request that starts
// close to expiry does not reach GitHub with a dead token and earn a 401.
//
// It is oauth2.ReuseTokenSourceWithExpiry, which oauth2.NewClient recognises
// and uses as is rather than adding a cache of its own that would refresh 10s
// before expiry whatever skew says. A zero or negative skew gives
// oauth2.ReuseTokenSource. An initial non-nil t is used until it needs refresh.
// The returned source is safe for concurrent use, and concurrent Token calls
// that find the cache stale collapse into a single upstream fetch.
func ReuseTokenSourceWithSkew(t *oauth2.Token, src oauth2.TokenSource, skew time.Duration) oauth2.TokenSource {
	if skew <= 0 {
		return oauth2.ReuseTokenSource(t, src)
	}
	// oauth2's cache writes its window into each token it holds. Copies keep
	// that write off tokens the caller or src shares, such as a
	// StaticTokenSource's, which two caches would otherwise race on.
	return oauth2.ReuseTokenSourceWithExpiry(copyToken(t), copyingSource{src}, skew)
}

// copyingSource returns a copy of each token src returns.
type copyingSource struct{ src oauth2.TokenSource }

func (c copyingSource) Token() (*oauth2.Token, error) {
	t, err := c.src.Token()
	if err != nil {
		return nil, err
	}
	return copyToken(t), nil
}

func copyToken(t *oauth2.Token) *oauth2.Token {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// Identifier constrains GitHub App identifiers to an integer App ID or a string
// Client ID. int is admitted so an untyped constant such as 12345 is accepted.
type Identifier interface {
	~int64 | ~int | ~string
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

// ApplicationTokenOpt configures NewApplicationTokenSource and
// NewApplicationTokenSourceFromSigner.
type ApplicationTokenOpt func(*applicationTokenSource)

// WithApplicationTokenExpiration sets the JWT expiration duration.
// Must be greater than 90 seconds and at most 10 minutes. Ten minutes is
// GitHub's ceiling. The lower bound is the 60 second clock-drift backdate plus
// DefaultExpirySkew: at or below the backdate the JWT is already expired when
// minted, and within the skew above it the cache never holds the token, so
// every call re-signs — a remote round trip for a KMS, HSM or Vault signer.
// Invalid values default to 10 minutes.
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#about-json-web-tokens-jwts
func WithApplicationTokenExpiration(exp time.Duration) ApplicationTokenOpt {
	// Normalized once, here: an option is a value callers may share across
	// goroutines, so applying it must not write to what it captured.
	if exp > DefaultApplicationTokenExpiration || exp <= minApplicationTokenExpiration {
		exp = DefaultApplicationTokenExpiration
	}
	return func(a *applicationTokenSource) {
		a.expiration = exp
	}
}

// WithExpirySkew overrides the default early-refresh window (DefaultExpirySkew,
// 30s) applied to the token cache returned by NewApplicationTokenSource. The
// cached token is refreshed d before it expires. A zero or negative value falls
// back to oauth2.ReuseTokenSource and its 10s.
//
// Tune this when your application token expiration (see
// WithApplicationTokenExpiration) is short: the effective validity is
// expiration - 60s of clock-drift backdating - skew, so with the default
// 10-minute expiration and 30s skew tokens are refreshed at 8m30s.
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
// than after. With the default 10-minute expiration, which is backdated 60s
// for clock drift, the effective validity is 8m30s. Override with
// WithExpirySkew.
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
	// Every Identifier form is comparable, and its zero value, 0 or "", is the
	// one input GitHub cannot use.
	var zero T
	if id == zero {
		return "", errors.New("application identifier is required")
	}

	// Defined types such as "type AppID int64" satisfy Identifier, but a type
	// switch matches the exact dynamic type and would reject them, hence the
	// switch on the underlying kind. reflect also sidesteps fmt's Stringer
	// dispatch, which would let a defined type with a String method rewrite
	// its own issuer.
	v := reflect.ValueOf(id)
	if v.Kind() == reflect.String {
		return v.String(), nil
	}

	// Identifier admits only int and int64 kinds here; Int reads both.
	return strconv.FormatInt(v.Int(), 10), nil
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

// Token signs a GitHub App JWT with the iat, exp and iss claims, using RS256.
// The iat claim is set 60 seconds in the past to account for clock drift.
// Signing is routed through the configured crypto.Signer.
// Generated JWTs can be used with "Authorization: Bearer" header for GitHub API requests.
func (t *applicationTokenSource) Token() (*oauth2.Token, error) {
	now := time.Now().Add(-applicationTokenBackdate)
	expiresAt := now.Add(t.expiration)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    t.issuer,
	})

	signingString, err := token.SigningString()
	// Unreachable guard: SigningString fails only if the fixed header map or
	// the RegisteredClaims above fail to marshal, which they cannot. Kept so a
	// future claim type that can fail is not silently signed as an empty JWT.
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

// InstallationTokenSourceOpt configures NewInstallationTokenSource, and the
// subset RevokeInstallationToken and FindInstallationID document.
type InstallationTokenSourceOpt func(*installationTokenSource)

// WithInstallationTokenOptions sets the options for the GitHub App installation token.
func WithInstallationTokenOptions(opts *InstallationTokenOptions) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		i.opts = opts
	}
}

// WithHTTPClient sets the HTTP client used to call the GitHub API. Its transport
// is wrapped so installation-token requests are authenticated with the GitHub
// App JWT; a base URL from WithBaseURL or WithEnterpriseURL is kept whichever
// comes first.
//
// A nil client is a configuration error reported by the first call to Token().
func WithHTTPClient(client *http.Client) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		if client == nil {
			i.setConfigErr(errors.New("WithHTTPClient: http client must not be nil"))
			return
		}

		// Work on a shallow copy so the caller's *http.Client is not mutated;
		// only the Transport is swapped to inject GitHub App authentication.
		authClient := *client
		authClient.Transport = &oauth2.Transport{
			Source: cachedSource(i.src),
			Base:   client.Transport,
		}
		// The caller's policy still applies, but only after ours: their client
		// was not built knowing every hop would carry the App JWT.
		callerCheck := client.CheckRedirect
		authClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := sameHostRedirect(req, via); err != nil || callerCheck == nil {
				return err
			}
			return callerCheck(req, via)
		}

		// Swap only the underlying *http.Client so the base URL and retry
		// settings already configured on i.client survive, regardless of the
		// order options are applied in.
		i.client.httpClient = &authClient
	}
}

// WithEnterpriseURL sets the base URL for GitHub Enterprise Server (GHES). The
// URL is normalized the way GHES expects, appending the "/api/v3/" path when the
// host is not already an "api." subdomain. For GitHub Enterprise Cloud or a
// verbatim URL (such as an httptest server), use WithBaseURL instead.
//
// It combines with WithHTTPClient and WithRetryOnThrottle in any order. Given
// with WithBaseURL, the last of the two wins. If the URL cannot be parsed, the
// error is reported by the first call to Token() rather than silently falling
// back to the public GitHub API; with several invalid options, the first
// one's error is reported.
func WithEnterpriseURL(baseURL string) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		if err := i.client.withEnterpriseURL(baseURL); err != nil {
			i.setConfigErr(err)
		}
	}
}

// WithBaseURL sets the API base URL used to create installation tokens, closely
// mirroring how go-github lets callers point the client at a custom endpoint.
// Unlike WithEnterpriseURL, the URL is used verbatim — only a trailing slash is
// appended when missing, and no "/api/v3/" suffix is added.
//
// Use this for:
//   - GitHub Enterprise Cloud with data residency (https://api.SUBDOMAIN.ghe.com/)
//   - pointing the client at an httptest server in tests
//
// It combines with WithHTTPClient and WithRetryOnThrottle in any order. Given
// with WithEnterpriseURL, the last of the two wins. If the URL cannot be
// parsed, the error is reported by the first call to Token() rather than
// silently falling back to the public GitHub API; with several invalid
// options, the first one's error is reported.
func WithBaseURL(baseURL string) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		if err := i.client.withBaseURL(baseURL); err != nil {
			i.setConfigErr(err)
		}
	}
}

// WithContext sets the context every token request runs under, retry wait
// included; the default is context.Background. Once it is done, every later
// request fails with its error, so the source stops refreshing once its cached
// token goes stale; prefer a context that lives as long as the source. It is
// stored on the source because oauth2.TokenSource.Token takes no context.
func WithContext(ctx context.Context) InstallationTokenSourceOpt {
	return func(i *installationTokenSource) {
		i.ctx = ctx
	}
}

// WithRetryOnThrottle enables or disables a single automatic retry when
// GitHub throttles the installation token POST. Enabled by default.
//
// Any 429 counts as throttled. A 403 counts only when GitHub identifies it as a
// rate limit — it carries Retry-After, reports an exhausted budget via
// X-RateLimit-Remaining: 0, or says so in its message. A permission failure such
// as "Resource not accessible by integration" is terminal and is retried by
// neither setting, despite carrying rate-limit headers.
//
// On a throttled response the client sleeps the duration hinted by Retry-After
// or x-ratelimit-reset, falling back to one minute for a hintless rate-limit 403
// (honoring ctx cancellation), and retries once. A hint longer than 60s is not
// slept through: the error returns at once, its RateLimitError.RetryAfter set to
// GitHub's full wait. On a terminal throttle the returned error wraps
// ErrRateLimited so callers can branch with errors.Is.
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

	// configErr records the first invalid-configuration error encountered while
	// applying options (e.g. an unparseable base URL or a nil HTTP client). It is
	// surfaced by Token() so misconfiguration fails loudly instead of silently
	// falling back to the public GitHub API.
	configErr error
}

// setConfigErr records err as the source's configuration error, keeping the
// first error so the reported failure is independent of option order.
func (t *installationTokenSource) setConfigErr(err error) {
	if t.configErr == nil {
		t.configErr = err
	}
}

// NewInstallationTokenSource creates a GitHub App installation token source.
// Requires installation ID and a GitHub App JWT token source for authentication.
//
// A non-positive installation ID is a configuration error, reported by the
// first call to Token() rather than sent to GitHub as a request that can only 404.
//
// The returned token source is wrapped in ReuseTokenSourceWithSkew so cached
// tokens are refreshed DefaultExpirySkew before their expiry, eliminating
// in-flight 401s when a request starts close to exp and reaches GitHub after.
// Override the window with WithInstallationExpirySkew.
//
// See https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
func NewInstallationTokenSource(id int64, src oauth2.TokenSource, opts ...InstallationTokenSourceOpt) oauth2.TokenSource {
	i := newInstallationTokenSource(id, src, opts)

	// A non-positive ID can only produce /app/installations/0/access_tokens and
	// a 404. Fail like a misconfiguration rather than like a GitHub outage.
	// It wins over an option's error, as it did when checked first.
	if id <= 0 {
		i.configErr = errors.New("installation identifier is required")
	}

	return ReuseTokenSourceWithSkew(nil, i, i.skew)
}

// RevokeInstallationToken revokes an installation access token before its hour
// is up, so a copy that leaked stops working. A source from
// NewInstallationTokenSource that handed the token out does not know, and keeps
// returning it from its cache until it expires; build a new source instead.
// WithBaseURL, WithEnterpriseURL and WithHTTPClient apply as they do to
// NewInstallationTokenSource. The other
// options are ignored.
//
// See https://docs.github.com/en/rest/apps/installations?apiVersion=2022-11-28#revoke-an-installation-access-token
func RevokeInstallationToken(ctx context.Context, token string, opts ...InstallationTokenSourceOpt) error {
	// The token authenticates its own revocation, in place of the App JWT.
	i := newInstallationTokenSource(0, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}), opts)
	if i.configErr != nil {
		return i.configErr
	}
	return i.client.revokeInstallationToken(ctx)
}

// FindInstallationID returns the ID of the App's installation on owner, a user
// or organization login, for a caller who knows the account but not the ID. src
// is the App's JWT source. WithBaseURL, WithEnterpriseURL and WithHTTPClient
// apply as they do to NewInstallationTokenSource. The other options are ignored.
//
// See https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-user-installation-for-the-authenticated-app
func FindInstallationID(ctx context.Context, src oauth2.TokenSource, owner string, opts ...InstallationTokenSourceOpt) (int64, error) {
	// A slash or dot segment would move the request to another endpoint.
	if owner == "" || owner == "." || owner == ".." || strings.Contains(owner, "/") {
		return 0, fmt.Errorf("invalid owner %q: want a user or organization login", owner)
	}
	i := newInstallationTokenSource(0, src, opts)
	if i.configErr != nil {
		return 0, i.configErr
	}
	return i.client.findInstallationID(ctx, owner)
}

// newInstallationTokenSource applies opts to a source whose requests src
// authenticates.
func newInstallationTokenSource(id int64, src oauth2.TokenSource, opts []InstallationTokenSourceOpt) *installationTokenSource {
	httpClient := cleanHTTPClient()
	httpClient.Transport = &oauth2.Transport{
		Source: cachedSource(src),
		Base:   httpClient.Transport,
	}

	i := &installationTokenSource{
		id:     id,
		ctx:    context.Background(),
		src:    src,
		client: newGitHubClient(httpClient),
		skew:   DefaultExpirySkew,
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// cachedSource reuses the App JWT across installation-token requests. A source
// from NewApplicationTokenSource already caches with its own skew, and wrapping
// it again would let the outer cache hold the JWT past that skew.
func cachedSource(src oauth2.TokenSource) oauth2.TokenSource {
	// ReuseTokenSource hands src back only when it already is an oauth2 cache,
	// as NewApplicationTokenSource returns; that cache keeps its own window.
	if oauth2.ReuseTokenSource(nil, src) == src {
		return src
	}
	return ReuseTokenSourceWithSkew(nil, src, DefaultExpirySkew)
}

// Token mints an installation access token, carrying what GitHub granted it in
// its Extra fields.
func (t *installationTokenSource) Token() (*oauth2.Token, error) {
	if t.configErr != nil {
		return nil, t.configErr
	}

	token, err := t.client.createInstallationToken(t.ctx, t.id, t.opts)
	if err != nil {
		return nil, err
	}

	tok := &oauth2.Token{
		AccessToken: token.Token,
		TokenType:   bearerTokenType,
		Expiry:      token.ExpiresAt,
	}

	// GitHub's answer says what the token can do, which may differ from what
	// was asked: metadata:read comes with every token.
	extra := map[string]any{}
	if token.Permissions != nil {
		extra[ExtraPermissions] = token.Permissions.levels()
	}
	if len(token.Repositories) > 0 {
		names := make([]string, 0, len(token.Repositories))
		for _, r := range token.Repositories {
			if r.Name != nil {
				names = append(names, *r.Name)
			}
		}
		extra[ExtraRepositories] = names
	}
	if len(extra) == 0 {
		return tok, nil
	}
	return tok.WithExtra(extra), nil
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
		return nil, errors.New("personal access token is required")
	}

	return &oauth2.Token{
		AccessToken: t.token,
		TokenType:   bearerTokenType,
	}, nil
}
