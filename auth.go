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
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	// DefaultApplicationTokenExpiration is the default expiration time for GitHub App tokens.
	// The maximum allowed expiration is 10 minutes.
	DefaultApplicationTokenExpiration = 10 * time.Minute

	// bearerTokenType is the token type used for OAuth2 Bearer tokens.
	bearerTokenType = "Bearer"
)

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

// NewApplicationTokenSource creates a GitHub App JWT token source from a
// PEM-encoded RSA private key.
// Accepts either int64 App ID or string Client ID. GitHub recommends Client IDs for new apps.
// Generated JWTs are RS256-signed with iat, exp, and iss claims.
// JWTs expire in max 10 minutes and include clock drift protection (iat set 60s in past).
//
// The returned token source is wrapped in oauth2.ReuseTokenSource to prevent unnecessary
// token regeneration. Don't worry about wrapping the result again since ReuseTokenSource
// prevents re-wrapping automatically.
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
	}
	for _, opt := range opts {
		opt(t)
	}
	return oauth2.ReuseTokenSource(nil, t)
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
}

// NewInstallationTokenSource creates a GitHub App installation token source.
// Requires installation ID and a GitHub App JWT token source for authentication.
//
// The returned token source is wrapped in oauth2.ReuseTokenSource to prevent unnecessary
// token regeneration. Don't worry about wrapping the result again since ReuseTokenSource
// prevents re-wrapping automatically.
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
	}

	for _, opt := range opts {
		opt(i)
	}

	return oauth2.ReuseTokenSource(nil, i)
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
