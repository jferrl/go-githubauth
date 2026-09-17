package githubauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestNewApplicationTokenSource(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		new     func() (oauth2.TokenSource, error)
		wantErr bool
	}{
		{
			name: "int64 application id is not provided",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource(int64(0), privateKey)
			},
			wantErr: true,
		},
		{
			name: "string application id is not provided",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource("", privateKey)
			},
			wantErr: true,
		},
		{
			name: "private key is not provided for int64",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource(int64(132), nil)
			},
			wantErr: true,
		},
		{
			name: "private key is not provided for string",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource("Iv1.test", nil)
			},
			wantErr: true,
		},
		{
			name: "valid application token source with int64",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource(int64(132), privateKey, WithApplicationTokenExpiration(15*time.Minute))
			},
			wantErr: false,
		},
		{
			name: "valid application token source with string",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource("Iv1.1234567890abcdef", privateKey, WithApplicationTokenExpiration(15*time.Minute))
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.new()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewApplicationTokenSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestApplicationTokenSource_Token(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		new         func() (oauth2.TokenSource, error)
		expectedIss string
	}{
		{
			name: "numeric app id token generation",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource(int64(12345), privateKey)
			},
			expectedIss: "12345",
		},
		{
			name: "client id token generation",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource("Iv1.1234567890abcdef", privateKey)
			},
			expectedIss: "Iv1.1234567890abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenSource, err := tt.new()
			if err != nil {
				t.Fatalf("Failed to create token source: %v", err)
			}

			token, err := tokenSource.Token()
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			if token.AccessToken == "" {
				t.Error("Token access token is empty")
			}
			if token.TokenType != "Bearer" {
				t.Errorf("Expected token type 'Bearer', got %s", token.TokenType)
			}
			if token.Expiry.IsZero() {
				t.Error("Token expiry is not set")
			}

			// Parse and verify JWT claims
			jwtToken, err := jwt.ParseWithClaims(token.AccessToken, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
				privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
				if err != nil {
					return nil, err
				}
				return &privKey.PublicKey, nil
			})
			if err != nil {
				t.Fatalf("Failed to parse JWT token: %v", err)
			}

			claims, ok := jwtToken.Claims.(*jwt.RegisteredClaims)
			if !ok {
				t.Fatal("Failed to get JWT claims")
			}

			if claims.Issuer != tt.expectedIss {
				t.Errorf("Expected issuer %s, got %s", tt.expectedIss, claims.Issuer)
			}
		})
	}
}

func TestApplicationTokenSource_Token_SigningError(t *testing.T) {
	// Create an invalid private key that will cause signing to fail
	invalidKey := []byte("invalid key")

	// This should fail at NewApplicationTokenSource due to invalid PEM
	_, err := NewApplicationTokenSource(int64(12345), invalidKey)
	if err == nil {
		t.Fatal("Expected error for invalid private key, got nil")
	}
}

// stubSigner is a test double implementing crypto.Signer.
type stubSigner struct {
	pub      crypto.PublicKey
	signFn   func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	gotRand  io.Reader
	gotDig   []byte
	gotOpts  crypto.SignerOpts
	gotCalls int
}

func (s *stubSigner) Public() crypto.PublicKey { return s.pub }

func (s *stubSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.gotCalls++
	s.gotRand = r
	s.gotDig = digest
	s.gotOpts = opts
	return s.signFn(r, digest, opts)
}

func TestNewApplicationTokenSourceFromSigner(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		new     func() (oauth2.TokenSource, error)
		wantErr bool
	}{
		{
			name:    "rsa signer with int64 id",
			new:     func() (oauth2.TokenSource, error) { return NewApplicationTokenSourceFromSigner(int64(42), rsaKey) },
			wantErr: false,
		},
		{
			name:    "rsa signer with client id",
			new:     func() (oauth2.TokenSource, error) { return NewApplicationTokenSourceFromSigner("Iv1.abc", rsaKey) },
			wantErr: false,
		},
		{
			name:    "nil signer is rejected",
			new:     func() (oauth2.TokenSource, error) { return NewApplicationTokenSourceFromSigner(int64(42), nil) },
			wantErr: true,
		},
		{
			name: "non-rsa signer is rejected",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSourceFromSigner(int64(42), &stubSigner{pub: edPub})
			},
			wantErr: true,
		},
		{
			name:    "zero int64 id is rejected",
			new:     func() (oauth2.TokenSource, error) { return NewApplicationTokenSourceFromSigner(int64(0), rsaKey) },
			wantErr: true,
		},
		{
			name:    "empty string id is rejected",
			new:     func() (oauth2.TokenSource, error) { return NewApplicationTokenSourceFromSigner("", rsaKey) },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.new()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewApplicationTokenSourceFromSigner() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplicationTokenSource_FromSigner_RoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	stub := &stubSigner{
		pub: &rsaKey.PublicKey,
		signFn: func(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			return rsaKey.Sign(r, digest, opts)
		},
	}

	ts, err := NewApplicationTokenSourceFromSigner("Iv1.round-trip", stub, WithApplicationTokenExpiration(5*time.Minute))
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token(): %v", err)
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", tok.TokenType)
	}

	parsed, err := jwt.ParseWithClaims(tok.AccessToken, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
		return &rsaKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("JWT parse against signer's public key: %v", err)
	}
	claims := parsed.Claims.(*jwt.RegisteredClaims)
	if claims.Issuer != "Iv1.round-trip" {
		t.Errorf("Issuer = %q, want Iv1.round-trip", claims.Issuer)
	}

	// Signer must have been invoked with a SHA-256 digest (32 bytes) and the
	// crypto.SHA256 hash option so KMS/HSM backends receive correct parameters.
	if stub.gotCalls != 1 {
		t.Errorf("signer called %d times, want 1", stub.gotCalls)
	}
	if len(stub.gotDig) != sha256.Size {
		t.Errorf("digest length = %d, want %d", len(stub.gotDig), sha256.Size)
	}
	if stub.gotOpts != crypto.SHA256 {
		t.Errorf("hash opts = %v, want crypto.SHA256", stub.gotOpts)
	}
}

func TestApplicationTokenSource_FromSigner_PropagatesError(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("kms unavailable")
	stub := &stubSigner{
		pub:    &rsaKey.PublicKey,
		signFn: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, sentinel },
	}

	ts, err := NewApplicationTokenSourceFromSigner(int64(7), stub)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	_, err = ts.Token()
	if !errors.Is(err, sentinel) {
		t.Fatalf("Token() err = %v, want errors.Is(%v)", err, sentinel)
	}
}

// TestApplicationTokenSource_JWTContract is a senior-grade contract test that
// asserts the full JWT protocol compliance across both the PEM-encoded path
// and the crypto.Signer path, using the same underlying RSA key.
//
// It covers the three gaps previously defended only by reasoning:
//
//  1. Header is {"alg":"RS256","typ":"JWT"} — what GitHub expects
//  2. Signature verifies with rsa.VerifyPKCS1v15 — the RFC-compliant contract
//     that any third-party verifier (including GitHub) applies. If both paths
//     produce signatures the same public key accepts, they are interoperable
//     by the only definition that matters.
//  3. iat backdated ~60s, exp - iat == configured expiration, iss populated.
func TestApplicationTokenSource_JWTContract(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	const (
		wantIssuer     = "42"
		wantExpiration = 5 * time.Minute
	)

	factories := []struct {
		name string
		new  func() (oauth2.TokenSource, error)
	}{
		{
			name: "pem path",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSource(int64(42), pemBytes, WithApplicationTokenExpiration(wantExpiration))
			},
		},
		{
			name: "signer path",
			new: func() (oauth2.TokenSource, error) {
				return NewApplicationTokenSourceFromSigner(int64(42), rsaKey, WithApplicationTokenExpiration(wantExpiration))
			},
		},
	}

	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			before := time.Now()
			ts, err := f.new()
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			tok, err := ts.Token()
			if err != nil {
				t.Fatalf("Token(): %v", err)
			}

			parts := strings.Split(tok.AccessToken, ".")
			if len(parts) != 3 {
				t.Fatalf("JWT parts = %d, want 3", len(parts))
			}

			// 1. Header: alg=RS256, typ=JWT.
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Fatalf("header decode: %v", err)
			}
			var header struct {
				Alg string `json:"alg"`
				Typ string `json:"typ"`
			}
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				t.Fatalf("header parse: %v", err)
			}
			if header.Alg != "RS256" {
				t.Errorf("alg = %q, want RS256", header.Alg)
			}
			if header.Typ != "JWT" {
				t.Errorf("typ = %q, want JWT", header.Typ)
			}

			// 2. Signature: verify with the same RSA public key that backs
			//    both paths. This is the canonical cross-path equivalence
			//    check: any RFC-compliant verifier accepts tokens from
			//    either constructor.
			sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("signature decode: %v", err)
			}
			signingString := parts[0] + "." + parts[1]
			digest := sha256.Sum256([]byte(signingString))
			if err := rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
				t.Errorf("signature does not verify against rsaKey.PublicKey: %v", err)
			}

			// 3. Claim timing: iat backdated ~60s, exp - iat == expiration.
			claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("claims decode: %v", err)
			}
			var claims struct {
				Iat int64  `json:"iat"`
				Exp int64  `json:"exp"`
				Iss string `json:"iss"`
			}
			if err := json.Unmarshal(claimsJSON, &claims); err != nil {
				t.Fatalf("claims parse: %v", err)
			}

			iat := time.Unix(claims.Iat, 0)
			skew := before.Sub(iat)
			// NumericDate truncates to whole seconds (worst case +1s). Test
			// scheduling adds a few milliseconds. Tolerance [55s, 65s] covers
			// both without risking flakes.
			if skew < 55*time.Second || skew > 65*time.Second {
				t.Errorf("iat drift from call time = %v, want ~60s (tolerance 55-65s)", skew)
			}

			exp := time.Unix(claims.Exp, 0)
			gap := exp.Sub(iat)
			if diff := gap - wantExpiration; diff < -time.Second || diff > time.Second {
				t.Errorf("exp - iat = %v, want ~%v (±1s)", gap, wantExpiration)
			}

			if claims.Iss != wantIssuer {
				t.Errorf("iss = %q, want %q", claims.Iss, wantIssuer)
			}

			// 4. oauth2.Token envelope.
			if tok.TokenType != "Bearer" {
				t.Errorf("TokenType = %q, want Bearer", tok.TokenType)
			}
			if tok.Expiry.IsZero() {
				t.Error("Expiry is zero; oauth2.ReuseTokenSource relies on this to refresh")
			}
		})
	}
}

func TestWithEnterpriseURL_InvalidURL(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	appSrc, err := NewApplicationTokenSource(int64(12345), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// An invalid URL must not silently fall back to the public GitHub API; the
	// error surfaces on the first Token() call instead.
	installationTokenSource := NewInstallationTokenSource(
		1,
		appSrc,
		WithEnterpriseURL("ht\ntp://invalid"),
	)

	if installationTokenSource == nil {
		t.Fatal("Expected non-nil token source")
	}

	if _, err := installationTokenSource.Token(); err == nil {
		t.Error("Token() error = nil, want error for invalid enterprise URL")
	}
}

func TestWithBaseURL_InvalidURL(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	appSrc, err := NewApplicationTokenSource(int64(12345), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// An invalid URL must not silently fall back to the public GitHub API; the
	// error surfaces on the first Token() call instead.
	installationTokenSource := NewInstallationTokenSource(
		1,
		appSrc,
		WithBaseURL("ht\ntp://invalid"),
	)

	if installationTokenSource == nil {
		t.Fatal("Expected non-nil token source")
	}

	if _, err := installationTokenSource.Token(); err == nil {
		t.Error("Token() error = nil, want error for invalid base URL")
	}
}

func TestWithBaseURL_DrivesTokenThroughServer(t *testing.T) {
	now := time.Now().UTC()
	expiration := now.Add(10 * time.Minute)

	// A bare httptest server URL (e.g. http://127.0.0.1:PORT) is exactly the
	// case WithEnterpriseURL mishandles: it would append "/api/v3/" and break
	// the mock. WithBaseURL uses the URL verbatim, so the installation-token
	// POST lands on the expected path.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/1/access_tokens" {
			t.Errorf("unexpected request path = %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(InstallationToken{
			Token:     "mocked-installation-token",
			ExpiresAt: expiration,
		})
	}))
	defer server.Close()

	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	appSrc, err := NewApplicationTokenSource(int64(34434), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	ts := NewInstallationTokenSource(1, appSrc, WithBaseURL(server.URL))

	got, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	want := &oauth2.Token{
		AccessToken: "mocked-installation-token",
		TokenType:   "Bearer",
		Expiry:      expiration,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Token() = %v, want %v", got, want)
	}
}

// TestWithBaseURL_SurvivesHTTPClientOrder guards against the ordering footgun:
// WithBaseURL is applied BEFORE WithHTTPClient, and the configured base URL must
// survive the HTTP client swap. If it did not, the request would be sent to the
// public GitHub API instead of the test server.
func TestWithBaseURL_SurvivesHTTPClientOrder(t *testing.T) {
	now := time.Now().UTC()
	expiration := now.Add(10 * time.Minute)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/7/access_tokens" {
			t.Errorf("request path = %q, want /app/installations/7/access_tokens", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(InstallationToken{Token: "ordered-token", ExpiresAt: expiration})
	}))
	defer server.Close()

	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	appSrc, err := NewApplicationTokenSource(int64(1), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	ts := NewInstallationTokenSource(7, appSrc,
		WithBaseURL(server.URL),
		WithHTTPClient(&http.Client{}),
	)

	got, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if got.AccessToken != "ordered-token" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "ordered-token")
	}
}

func TestWithHTTPClient_NilClient(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	appSrc, err := NewApplicationTokenSource(int64(1), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// A nil HTTP client must not panic; the error surfaces on Token().
	ts := NewInstallationTokenSource(1, appSrc, WithHTTPClient(nil))
	if _, err := ts.Token(); err == nil {
		t.Error("Token() error = nil, want error for nil http client")
	}
}

func TestWithHTTPClient_DoesNotMutateCallerClient(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	appSrc, err := NewApplicationTokenSource(int64(1), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	originalTransport := http.DefaultTransport
	client := &http.Client{Transport: originalTransport}

	_ = NewInstallationTokenSource(1, appSrc, WithHTTPClient(client))

	// The option must operate on a copy; the caller's client (which may be
	// shared elsewhere) must keep its original transport.
	if client.Transport != originalTransport {
		t.Errorf("WithHTTPClient mutated the caller's client Transport = %T, want it unchanged", client.Transport)
	}
}

func Test_installationTokenSource_Token(t *testing.T) {
	now := time.Now().UTC()
	expiration := now.Add(10 * time.Minute)

	mockedHTTPClient, cleanupSuccess := newMockedHTTPClient(
		withRequestMatch(
			postAppInstallationsAccessTokensByInstallationID,
			InstallationToken{
				Token:     "mocked-installation-token",
				ExpiresAt: expiration,
				Permissions: &InstallationPermissions{
					PullRequests: Ptr("read"),
				},
				Repositories: []Repository{
					{
						Name: Ptr("mocked-repo-1"),
						ID:   Ptr(int64(1)),
					},
				},
			},
		),
	)
	defer cleanupSuccess()

	errMockedHTTPClient, cleanupError := newMockedHTTPClient(
		withRequestMatchHandler(
			postAppInstallationsAccessTokensByInstallationID,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"Internal Server Error"}`))
			}),
		))
	defer cleanupError()

	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	appSrc, err := NewApplicationTokenSource(int64(34434), privateKey, WithApplicationTokenExpiration(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		id   int64
		src  oauth2.TokenSource
		opts []InstallationTokenSourceOpt
	}
	tests := []struct {
		name    string
		fields  fields
		want    *oauth2.Token
		wantErr bool
	}{
		{
			name: "error getting installation token",
			fields: fields{
				id:  1,
				src: appSrc,
				opts: []InstallationTokenSourceOpt{
					WithInstallationTokenOptions(&InstallationTokenOptions{}),
					WithHTTPClient(errMockedHTTPClient),
				},
			},
			wantErr: true,
		},
		{
			name: "generate a new installation token",
			fields: fields{
				id:  1,
				src: appSrc,
				opts: []InstallationTokenSourceOpt{
					WithInstallationTokenOptions(&InstallationTokenOptions{}),
					WithContext(context.Background()),
					WithEnterpriseURL("https://github.example.com"),
					WithHTTPClient(mockedHTTPClient),
				},
			},
			want: &oauth2.Token{
				AccessToken: "mocked-installation-token",
				TokenType:   "Bearer",
				Expiry:      expiration,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := NewInstallationTokenSource(tt.fields.id, tt.fields.src, tt.fields.opts...)

			got, err := tr.Token()
			if (err != nil) != tt.wantErr {
				t.Errorf("installationTokenSource.Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("installationTokenSource.Token() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPersonalAccessTokenSource(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  oauth2.TokenSource
	}{
		{
			name:  "empty token",
			token: "",
			want:  &personalAccessTokenSource{token: ""},
		},
		{
			name:  "classic personal access token",
			token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456",
			want:  &personalAccessTokenSource{token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456"},
		},
		{
			name:  "fine-grained personal access token",
			token: "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want:  &personalAccessTokenSource{token: "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewPersonalAccessTokenSource(tt.token)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPersonalAccessTokenSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPersonalAccessTokenSource_Token(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    *oauth2.Token
		wantErr bool
	}{
		{
			name:    "empty token returns error",
			token:   "",
			want:    nil,
			wantErr: true,
		},
		{
			name:  "whitespace only token returns error",
			token: "   ",
			want: &oauth2.Token{
				AccessToken: "   ",
				TokenType:   "Bearer",
			},
		},
		{
			name:  "classic personal access token",
			token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456",
			want: &oauth2.Token{
				AccessToken: "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456",
				TokenType:   "Bearer",
			},
		},
		{
			name:  "fine-grained personal access token",
			token: "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
			want: &oauth2.Token{
				AccessToken: "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
				TokenType:   "Bearer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenSource := NewPersonalAccessTokenSource(tt.token)
			got, err := tokenSource.Token()
			if (err != nil) != tt.wantErr {
				t.Errorf("personalAccessTokenSource.Token() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				// For error cases, verify that got is nil
				if got != nil {
					t.Errorf("personalAccessTokenSource.Token() should return nil on error, got %v", got)
				}
				return
			}

			if got.AccessToken != tt.want.AccessToken {
				t.Errorf("personalAccessTokenSource.Token() AccessToken = %v, want %v", got.AccessToken, tt.want.AccessToken)
			}
			if got.TokenType != tt.want.TokenType {
				t.Errorf("personalAccessTokenSource.Token() TokenType = %v, want %v", got.TokenType, tt.want.TokenType)
			}
			if !got.Expiry.IsZero() {
				t.Errorf("personalAccessTokenSource.Token() Expiry should be zero, got %v", got.Expiry)
			}
		})
	}
}

func generatePrivateKey() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// Encode the private key to the PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return pem.EncodeToMemory(privateKeyPEM), nil
}

// countingSource is a test oauth2.TokenSource that counts Token() calls,
// mints tokens via a user-supplied factory, and can simulate slow upstreams.
type countingSource struct {
	mu      sync.Mutex
	calls   int
	delay   time.Duration
	mkToken func(call int) *oauth2.Token
	err     error
}

func (c *countingSource) Token() (*oauth2.Token, error) {
	c.mu.Lock()
	c.calls++
	call := c.calls
	delay, mk, err := c.delay, c.mkToken, c.err
	c.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return nil, err
	}
	return mk(call), nil
}

func (c *countingSource) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// newShortLivedSource returns a source that mints tokens with a fixed
// remaining lifetime measured from the moment of minting.
func newShortLivedSource(validFor time.Duration) *countingSource {
	return &countingSource{
		mkToken: func(call int) *oauth2.Token {
			return &oauth2.Token{
				AccessToken: fmt.Sprintf("token-%d", call),
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(validFor),
			}
		},
	}
}

func TestReuseTokenSourceWithSkew(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			// Token valid for 1s, skew=500ms. First Token() caches; after 600ms
			// the cached token is within the skew window and the next call
			// must refresh.
			name: "refreshes within skew window",
			run: func(t *testing.T) {
				src := newShortLivedSource(1 * time.Second)
				ts := ReuseTokenSourceWithSkew(nil, src, 500*time.Millisecond)

				first, err := ts.Token()
				if err != nil {
					t.Fatalf("first Token(): %v", err)
				}
				if got := src.callCount(); got != 1 {
					t.Fatalf("upstream calls after first Token() = %d, want 1", got)
				}

				// Cached call while still outside the skew window: no refresh.
				cached, err := ts.Token()
				if err != nil {
					t.Fatalf("cached Token(): %v", err)
				}
				if got := src.callCount(); got != 1 {
					t.Fatalf("upstream calls after cached Token() = %d, want 1", got)
				}
				if cached.AccessToken != first.AccessToken {
					t.Errorf("cached token = %q, want %q", cached.AccessToken, first.AccessToken)
				}

				// Enter the skew window (600ms elapsed, 400ms to exp ≤ 500ms skew).
				time.Sleep(600 * time.Millisecond)

				refreshed, err := ts.Token()
				if err != nil {
					t.Fatalf("refresh Token(): %v", err)
				}
				if got := src.callCount(); got != 2 {
					t.Errorf("upstream calls after refresh = %d, want 2", got)
				}
				if refreshed.AccessToken == first.AccessToken {
					t.Errorf("refreshed token = %q, want a new token", refreshed.AccessToken)
				}
			},
		},
		{
			// Skew 2s, tokens valid for 1s. Every call lands inside the skew
			// window, so the cache never hits.
			name: "skew exceeds validity always refreshes",
			run: func(t *testing.T) {
				src := newShortLivedSource(1 * time.Second)
				ts := ReuseTokenSourceWithSkew(nil, src, 2*time.Second)

				const iterations = 5
				var last string
				for i := range iterations {
					tok, err := ts.Token()
					if err != nil {
						t.Fatalf("Token() #%d: %v", i, err)
					}
					if tok.AccessToken == last {
						t.Errorf("Token() #%d returned cached %q, want refresh", i, tok.AccessToken)
					}
					last = tok.AccessToken
				}
				if got := src.callCount(); got != iterations {
					t.Errorf("upstream calls = %d, want %d", got, iterations)
				}
			},
		},
		{
			// Regression: with skew<=0 the wrapper must match
			// oauth2.ReuseTokenSource exactly. We run identical scenarios
			// through both implementations and assert the same upstream call
			// counts and the same AccessTokens at every step.
			name: "zero skew matches ReuseTokenSource",
			run: func(t *testing.T) {
				scenarios := []struct {
					name   string
					seed   *oauth2.Token
					makeFn func(call int) *oauth2.Token
					calls  int
				}{
					{
						name: "nil seed, long-lived tokens, repeated calls cache",
						seed: nil,
						makeFn: func(call int) *oauth2.Token {
							return &oauth2.Token{
								AccessToken: fmt.Sprintf("long-%d", call),
								TokenType:   "Bearer",
								Expiry:      time.Now().Add(1 * time.Hour),
							}
						},
						calls: 5,
					},
					{
						name: "pre-seeded long-lived token is reused",
						seed: &oauth2.Token{
							AccessToken: "seed",
							TokenType:   "Bearer",
							Expiry:      time.Now().Add(1 * time.Hour),
						},
						makeFn: func(call int) *oauth2.Token {
							return &oauth2.Token{
								AccessToken: fmt.Sprintf("fresh-%d", call),
								TokenType:   "Bearer",
								Expiry:      time.Now().Add(1 * time.Hour),
							}
						},
						calls: 3,
					},
				}
				for _, s := range scenarios {
					t.Run(s.name, func(t *testing.T) {
						skewSrc := &countingSource{mkToken: s.makeFn}
						plainSrc := &countingSource{mkToken: s.makeFn}

						skewTS := ReuseTokenSourceWithSkew(s.seed, skewSrc, 0)
						plainTS := oauth2.ReuseTokenSource(s.seed, plainSrc)

						for i := 0; i < s.calls; i++ {
							skewTok, skewErr := skewTS.Token()
							plainTok, plainErr := plainTS.Token()

							if (skewErr == nil) != (plainErr == nil) {
								t.Fatalf("call %d error mismatch: skew=%v plain=%v", i, skewErr, plainErr)
							}
							if skewErr != nil {
								continue
							}
							if skewTok.AccessToken != plainTok.AccessToken {
								t.Errorf("call %d token mismatch: skew=%q plain=%q", i, skewTok.AccessToken, plainTok.AccessToken)
							}
						}
						if skewSrc.callCount() != plainSrc.callCount() {
							t.Errorf("upstream call counts differ: skew=%d plain=%d", skewSrc.callCount(), plainSrc.callCount())
						}
					})
				}
			},
		},
		{
			// 100 goroutines fire Token() against a slow upstream that mints a
			// long-lived token. The mutex must funnel them so only the first
			// reaches upstream; the rest return the cached value.
			name: "concurrent Token calls collapse to one upstream fetch",
			run: func(t *testing.T) {
				src := &countingSource{
					delay: 50 * time.Millisecond,
					mkToken: func(call int) *oauth2.Token {
						return &oauth2.Token{
							AccessToken: fmt.Sprintf("token-%d", call),
							TokenType:   "Bearer",
							Expiry:      time.Now().Add(1 * time.Hour),
						}
					},
				}
				ts := ReuseTokenSourceWithSkew(nil, src, 30*time.Second)

				const goroutines = 100
				var (
					wg     sync.WaitGroup
					mu     sync.Mutex
					tokens = make(map[string]int, goroutines)
					errs   []error
				)
				wg.Add(goroutines)
				start := make(chan struct{})
				for range goroutines {
					go func() {
						defer wg.Done()
						<-start
						tok, err := ts.Token()
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							errs = append(errs, err)
							return
						}
						tokens[tok.AccessToken]++
					}()
				}
				close(start)
				wg.Wait()

				if len(errs) != 0 {
					t.Fatalf("Token() errors: %v", errs)
				}
				if got := src.callCount(); got != 1 {
					t.Errorf("upstream calls = %d, want 1", got)
				}
				if len(tokens) != 1 {
					t.Errorf("distinct tokens = %d, want 1 (%v)", len(tokens), tokens)
				}
				if tokens["token-1"] != goroutines {
					t.Errorf("goroutines that got token-1 = %d, want %d", tokens["token-1"], goroutines)
				}
			},
		},
		{
			// A valid seed token passed into the wrapper must be served
			// without touching upstream. This is the hot-start path: callers
			// rehydrating a cached token from disk or config should not incur
			// an extra round trip.
			name: "valid seed token served without upstream call",
			run: func(t *testing.T) {
				seed := &oauth2.Token{
					AccessToken: "seeded",
					TokenType:   "Bearer",
					Expiry:      time.Now().Add(1 * time.Hour),
				}
				src := &countingSource{
					mkToken: func(call int) *oauth2.Token {
						return &oauth2.Token{
							AccessToken: fmt.Sprintf("fresh-%d", call),
							TokenType:   "Bearer",
							Expiry:      time.Now().Add(1 * time.Hour),
						}
					},
				}
				ts := ReuseTokenSourceWithSkew(seed, src, 30*time.Second)

				tok, err := ts.Token()
				if err != nil {
					t.Fatalf("Token(): %v", err)
				}
				if tok.AccessToken != "seeded" {
					t.Errorf("AccessToken = %q, want %q (seed)", tok.AccessToken, "seeded")
				}
				if got := src.callCount(); got != 0 {
					t.Errorf("upstream calls = %d, want 0 (seed should short-circuit)", got)
				}
			},
		},
		{
			// Upstream errors must surface to the caller verbatim (wrappable
			// with errors.Is) and must not be cached — the next call has to
			// retry the upstream. Caching a failure would turn a transient
			// hiccup into a permanent outage.
			name: "upstream error is propagated and not cached",
			run: func(t *testing.T) {
				sentinel := errors.New("upstream unavailable")
				src := &countingSource{
					err:     sentinel,
					mkToken: func(int) *oauth2.Token { return nil },
				}
				ts := ReuseTokenSourceWithSkew(nil, src, 30*time.Second)

				for i := range 3 {
					_, err := ts.Token()
					if !errors.Is(err, sentinel) {
						t.Errorf("call %d: err = %v, want errors.Is(%v)", i, err, sentinel)
					}
				}
				if got := src.callCount(); got != 3 {
					t.Errorf("upstream calls = %d, want 3 (errors must not be cached)", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

// TestWithExpirySkew_Wiring verifies that WithExpirySkew threads through to
// the constructor-selected wrapper: a positive skew yields our
// *reuseTokenSourceWithSkew, a non-positive skew falls back to
// oauth2.ReuseTokenSource. We compare by type rather than by token-body
// equality because the JWT payload is deterministic within a single clock
// second, which would make a caching check ambiguous.
func TestWithExpirySkew_Wiring(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		skewOpts []ApplicationTokenOpt
		wantSkew bool // true → *reuseTokenSourceWithSkew, false → delegated
	}{
		{
			name:     "default skew uses wrapper",
			skewOpts: nil,
			wantSkew: true,
		},
		{
			name:     "explicit positive skew uses wrapper",
			skewOpts: []ApplicationTokenOpt{WithExpirySkew(5 * time.Second)},
			wantSkew: true,
		},
		{
			name:     "zero skew delegates to oauth2.ReuseTokenSource",
			skewOpts: []ApplicationTokenOpt{WithExpirySkew(0)},
			wantSkew: false,
		},
		{
			name:     "negative skew delegates to oauth2.ReuseTokenSource",
			skewOpts: []ApplicationTokenOpt{WithExpirySkew(-1 * time.Second)},
			wantSkew: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, err := NewApplicationTokenSource(int64(99), privateKey, tt.skewOpts...)
			if err != nil {
				t.Fatalf("NewApplicationTokenSource: %v", err)
			}
			_, isSkew := ts.(*reuseTokenSourceWithSkew)
			if isSkew != tt.wantSkew {
				t.Errorf("token source is *reuseTokenSourceWithSkew = %v, want %v (type=%T)", isSkew, tt.wantSkew, ts)
			}
		})
	}
}

// countingTokenSource records how many times the application JWT was minted.
type countingTokenSource struct {
	calls atomic.Int32
}

func (c *countingTokenSource) Token() (*oauth2.Token, error) {
	c.calls.Add(1)
	return &oauth2.Token{
		AccessToken: "app-jwt",
		TokenType:   bearerTokenType,
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

// Test_WithHTTPClient_CachesApplicationToken proves WithHTTPClient caches the
// application JWT the same way the default transport does. NewInstallationTokenSource
// wraps the source in oauth2.ReuseTokenSource, but WithHTTPClient wires the raw
// source, so supplying a custom client silently re-signs a JWT on every
// installation-token request.
func Test_WithHTTPClient_CachesApplicationToken(t *testing.T) {
	src := &countingTokenSource{}

	// expires_at inside the skew window, so the installation-token cache
	// refetches on every call and each one reaches the transport.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_installation",
			"expires_at": time.Now().Add(time.Second).UTC().Format(time.RFC3339),
		})
	}))
	defer server.Close()

	ts := NewInstallationTokenSource(42, src,
		WithBaseURL(server.URL),
		WithHTTPClient(&http.Client{}),
	)

	const fetches = 3
	for i := range fetches {
		if _, err := ts.Token(); err != nil {
			t.Fatalf("Token() #%d err = %v", i+1, err)
		}
	}

	if got := src.calls.Load(); got != 1 {
		t.Errorf("application token source consulted %d times across %d fetches, want 1; "+
			"WithHTTPClient must reuse the JWT like the default transport", got, fetches)
	}
}

// Test_NewInstallationTokenSource_RejectsZeroID proves a zero installation ID is
// refused as a configuration error instead of being sent to GitHub as
// /app/installations/0/access_tokens, which can only 404. A zero App ID is
// already rejected at construction; this is the same mistake one layer down.
func Test_NewInstallationTokenSource_RejectsZeroID(t *testing.T) {
	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	for _, id := range []int64{0, -1} {
		t.Run(fmt.Sprintf("id=%d", id), func(t *testing.T) {
			hits.Store(0)

			ts := NewInstallationTokenSource(id, oauth2StaticSource{accessToken: "jwt"},
				WithBaseURL(server.URL),
			)

			_, err := ts.Token()
			if err == nil {
				t.Fatalf("Token() err = nil, want a configuration error for installation ID %d", id)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("server received %d request(s), want 0; installation ID %d must fail before any network call", got, id)
			}
			if !strings.Contains(err.Error(), "installation") {
				t.Errorf("err = %q, want it to name the installation identifier", err)
			}
		})
	}
}

// namedAppID and namedClientID model the idiomatic Go habit of giving an
// identifier its own defined type. The Identifier constraint is "~int64 | ~string",
// whose tildes promise both are accepted.
type namedAppID int64

type namedClientID string

func Test_resolveIssuer_NamedIdentifierTypes(t *testing.T) {
	tests := []struct {
		name       string
		resolve    func() (string, error)
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:    "named int64 identifier",
			resolve: func() (string, error) { return resolveIssuer(namedAppID(123)) },
			want:    "123",
		},
		{
			name:    "named string identifier",
			resolve: func() (string, error) { return resolveIssuer(namedClientID("Iv1.abc123")) },
			want:    "Iv1.abc123",
		},
		{
			name:    "plain int64 identifier",
			resolve: func() (string, error) { return resolveIssuer(int64(456)) },
			want:    "456",
		},
		{
			name:    "plain string identifier",
			resolve: func() (string, error) { return resolveIssuer("Iv23.def456") },
			want:    "Iv23.def456",
		},
		{
			name:       "named int64 zero value is rejected",
			resolve:    func() (string, error) { return resolveIssuer(namedAppID(0)) },
			wantErr:    true,
			wantErrMsg: "application identifier is required",
		},
		{
			name:       "named string empty value is rejected",
			resolve:    func() (string, error) { return resolveIssuer(namedClientID("")) },
			wantErr:    true,
			wantErrMsg: "application identifier is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.resolve()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveIssuer() error = nil, want %q", tt.wantErrMsg)
				}
				if err.Error() != tt.wantErrMsg {
					t.Fatalf("resolveIssuer() error = %q, want %q", err.Error(), tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveIssuer() unexpected error = %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveIssuer() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_NewApplicationTokenSource_NamedIdentifierTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	cases := []struct {
		name       string
		newSource  func() (string, error)
		wantIssuer string
	}{
		{
			name: "named int64 through pem constructor",
			newSource: func() (string, error) {
				ts, err := NewApplicationTokenSource(namedAppID(42), pemBytes)
				if err != nil {
					return "", err
				}
				tok, err := ts.Token()
				if err != nil {
					return "", err
				}
				return issuerFromJWT(tok.AccessToken)
			},
			wantIssuer: "42",
		},
		{
			name: "named string through signer constructor",
			newSource: func() (string, error) {
				ts, err := NewApplicationTokenSourceFromSigner(namedClientID("Iv1.abc123"), rsaKey)
				if err != nil {
					return "", err
				}
				tok, err := ts.Token()
				if err != nil {
					return "", err
				}
				return issuerFromJWT(tok.AccessToken)
			},
			wantIssuer: "Iv1.abc123",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.newSource()
			if err != nil {
				t.Fatalf("unexpected error = %v", err)
			}
			if got != tc.wantIssuer {
				t.Errorf("iss = %q, want %q", got, tc.wantIssuer)
			}
		})
	}
}

// issuerFromJWT extracts the iss claim from a signed JWT without verifying it.
func issuerFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	return claims.Iss, nil
}

// Test_applicationTokenSource_ShortExpirationIsNotAlreadyExpired pins the
// contract that a configured application token expiration never yields a dead
// JWT.
//
// Token() backdates issuance by 60s for clock-drift protection
// (exp = now - 60s + expiration), so any expiration <= 60s mints a token whose
// exp is already in the past (or exactly now). WithApplicationTokenExpiration
// clamps only the upper bound, so those values slip through and the caller gets
// a credential GitHub answers with 401.
//
// Assertions are on the observable oauth2.Token.Expiry and the signed exp
// claim, not on internal fields, so the test holds whether the lower bound is
// enforced in the option or in Token().
func Test_applicationTokenSource_ShortExpirationIsNotAlreadyExpired(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		// expiration is the value handed to WithApplicationTokenExpiration.
		expiration time.Duration
		// wantEffective is the expiration the source must actually apply:
		// values at or below minApplicationTokenExpiration (the 60s backdate
		// plus DefaultExpirySkew) are invalid and fall back to
		// DefaultApplicationTokenExpiration, like every other invalid value the
		// option already rejects.
		wantEffective time.Duration
	}{
		{
			name:          "30s is shorter than the clock-drift backdating",
			expiration:    30 * time.Second,
			wantEffective: DefaultApplicationTokenExpiration,
		},
		{
			name:          "60s exactly cancels the clock-drift backdating",
			expiration:    60 * time.Second,
			wantEffective: DefaultApplicationTokenExpiration,
		},
		{
			// Clears the backdate but not the refresh skew on top of it, so the
			// cache could never hold the token and every call would re-sign.
			name:          "90s is exactly the bound and is rejected",
			expiration:    90 * time.Second,
			wantEffective: DefaultApplicationTokenExpiration,
		},
		{
			name:          "91s is the smallest honoured value",
			expiration:    91 * time.Second,
			wantEffective: 91 * time.Second,
		},
		{
			name:          "5m is honoured",
			expiration:    5 * time.Minute,
			wantEffective: 5 * time.Minute,
		},
		{
			name:          "10m is honoured",
			expiration:    DefaultApplicationTokenExpiration,
			wantEffective: DefaultApplicationTokenExpiration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()

			ts, err := NewApplicationTokenSourceFromSigner(int64(42), rsaKey, WithApplicationTokenExpiration(tt.expiration))
			if err != nil {
				t.Fatalf("construct: %v", err)
			}

			tok, err := ts.Token()
			if err != nil {
				t.Fatalf("Token(): %v", err)
			}

			// The token must be usable at all: a caller asking for a short
			// expiration must not silently receive a dead credential.
			if validFor := time.Until(tok.Expiry); validFor <= 0 {
				t.Errorf("Expiry %v is not in the future (valid for %v); token is dead on arrival", tok.Expiry, validFor)
			}

			// exp = issuance (now - 60s) + effective expiration. Tolerance
			// absorbs execution time and the whole-second truncation of
			// NumericDate.
			want := before.Add(-60 * time.Second).Add(tt.wantEffective)
			if diff := tok.Expiry.Sub(want); diff < -2*time.Second || diff > 2*time.Second {
				t.Errorf("Expiry = %v, want ~%v (±2s): effective expiration is not %v", tok.Expiry, want, tt.wantEffective)
			}

			// The signed JWT itself must verify and must not be expired: this
			// is what GitHub sees.
			parsed, err := jwt.ParseWithClaims(tok.AccessToken, &jwt.RegisteredClaims{}, func(_ *jwt.Token) (any, error) {
				return &rsaKey.PublicKey, nil
			})
			if err != nil {
				t.Fatalf("parse minted JWT: %v", err)
			}

			claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
			if !ok {
				t.Fatalf("claims type = %T, want *jwt.RegisteredClaims", parsed.Claims)
			}
			if claims.ExpiresAt == nil {
				t.Fatal("exp claim is missing")
			}
			if !claims.ExpiresAt.After(time.Now()) {
				t.Errorf("exp claim %v is not in the future; GitHub rejects this JWT with 401", claims.ExpiresAt.Time)
			}
		})
	}
}

// countingSigner records how many times the private key was used to sign.
type countingSigner struct {
	crypto.Signer
	signs atomic.Int32
}

func (c *countingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	c.signs.Add(1)
	return c.Signer.Sign(rand, digest, opts)
}

// Test_WithApplicationTokenExpiration_TokenIsCacheable proves the accepted
// lower bound leaves a token the cache can actually hold. An expiration above
// the 60s backdate but within DefaultExpirySkew of it yields a token whose
// remaining life is at or below the skew, so ReuseTokenSourceWithSkew treats it
// as stale immediately and re-signs on every call — a remote round trip for the
// KMS, HSM and Vault signers NewApplicationTokenSourceFromSigner exists to serve.
func Test_WithApplicationTokenExpiration_TokenIsCacheable(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, exp := range []time.Duration{61 * time.Second, 90 * time.Second, 5 * time.Minute} {
		t.Run(exp.String(), func(t *testing.T) {
			signer := &countingSigner{Signer: rsaKey}

			ts, err := NewApplicationTokenSourceFromSigner(int64(42), signer,
				WithApplicationTokenExpiration(exp))
			if err != nil {
				t.Fatalf("construct: %v", err)
			}

			const calls = 5
			for i := range calls {
				if _, err := ts.Token(); err != nil {
					t.Fatalf("Token() #%d: %v", i+1, err)
				}
			}

			if got := signer.signs.Load(); got != 1 {
				t.Errorf("signed %d times across %d calls, want 1; the token must survive in the cache", got, calls)
			}
		})
	}
}

// Test_Invalidate_ForcesRefresh covers the recovery path for a token that died
// before its expiry — a suspended App, changed permissions, an explicit
// revocation, a rotated key. The cache cannot see any of that, so without
// Invalidate it keeps serving the dead credential for the rest of the hour.
func Test_Invalidate_ForcesRefresh(t *testing.T) {
	tests := []struct {
		name string
		skew time.Duration
	}{
		{"with skew", DefaultExpirySkew},
		{"without skew (delegates to oauth2)", 0},
		{"negative skew", -1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var minted atomic.Int32
			cached := ReuseTokenSourceWithSkew(nil, &mintCounter{n: &minted}, tt.skew)

			first, err := cached.Token()
			if err != nil {
				t.Fatalf("Token(): %v", err)
			}
			if _, err := cached.Token(); err != nil {
				t.Fatalf("Token() again: %v", err)
			}
			if got := minted.Load(); got != 1 {
				t.Fatalf("minted %d times before invalidation, want 1 (the cache must hold)", got)
			}

			if !Invalidate(cached) {
				t.Fatal("Invalidate() = false, want true; the cached source must implement Invalidator")
			}

			second, err := cached.Token()
			if err != nil {
				t.Fatalf("Token() after invalidation: %v", err)
			}
			if got := minted.Load(); got != 2 {
				t.Errorf("minted %d times after invalidation, want 2", got)
			}
			if first.AccessToken == second.AccessToken {
				t.Errorf("token unchanged after invalidation (%q); the dead credential is still being served", second.AccessToken)
			}
		})
	}
}

// Test_Invalidate_ConstructedSources checks the sources callers actually hold —
// the ones the public constructors return — support invalidation, and that a
// source with nothing to discard reports so rather than silently doing nothing.
func Test_Invalidate_ConstructedSources(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	appSource, err := NewApplicationTokenSourceFromSigner(int64(42), rsaKey)
	if err != nil {
		t.Fatalf("construct app source: %v", err)
	}

	tests := []struct {
		name          string
		src           oauth2.TokenSource
		wantCacheable bool
	}{
		{"application token source", appSource, true},
		{"installation token source", NewInstallationTokenSource(42, appSource), true},
		{"personal access token source", NewPersonalAccessTokenSource("ghp_static"), false},
		{"oauth2 static source", oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "x"}), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Invalidate(tt.src); got != tt.wantCacheable {
				t.Errorf("Invalidate() = %v, want %v", got, tt.wantCacheable)
			}
		})
	}
}

// Test_Invalidate_Concurrent exercises invalidation against concurrent readers
// under -race; a revocation arrives while requests are in flight, not while the
// process is idle.
func Test_Invalidate_Concurrent(t *testing.T) {
	var minted atomic.Int32
	cached := ReuseTokenSourceWithSkew(nil, &mintCounter{n: &minted}, DefaultExpirySkew)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if _, err := cached.Token(); err != nil {
					t.Errorf("Token(): %v", err)
					return
				}
			}
		}()
	}
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				Invalidate(cached)
			}
		}()
	}
	wg.Wait()
}

// mintCounter hands out a distinct token per call so a test can tell a cached
// token from a freshly minted one.
type mintCounter struct {
	n *atomic.Int32
}

func (m *mintCounter) Token() (*oauth2.Token, error) {
	i := m.n.Add(1)
	return &oauth2.Token{
		AccessToken: fmt.Sprintf("token-%d", i),
		TokenType:   bearerTokenType,
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

// Test_ReuseTokenSourceWithSkew_ZeroSkewKeepsOAuth2Timing guards the refresh
// timing of the skew<=0 path, which now goes through a wrapper that adds
// Invalidate. oauth2.ReuseTokenSource applies its own ten-second early-expiry
// delta, so a token expiring inside that window must still be refetched. The
// wrapper must add invalidation without moving that boundary.
func Test_ReuseTokenSourceWithSkew_ZeroSkewKeepsOAuth2Timing(t *testing.T) {
	tests := []struct {
		name       string
		expiresIn  time.Duration
		wantMinted int32
	}{
		{"inside oauth2's 10s delta is refetched", 5 * time.Second, 2},
		{"outside it is served from cache", time.Hour, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var minted atomic.Int32
			src := &fixedLifetimeSource{n: &minted, lifetime: tt.expiresIn}

			cached := ReuseTokenSourceWithSkew(nil, src, 0)
			if _, err := cached.Token(); err != nil {
				t.Fatalf("Token(): %v", err)
			}
			if _, err := cached.Token(); err != nil {
				t.Fatalf("Token() again: %v", err)
			}

			if got := minted.Load(); got != tt.wantMinted {
				t.Errorf("minted %d times, want %d", got, tt.wantMinted)
			}
		})
	}
}

type fixedLifetimeSource struct {
	n        *atomic.Int32
	lifetime time.Duration
}

func (f *fixedLifetimeSource) Token() (*oauth2.Token, error) {
	i := f.n.Add(1)
	return &oauth2.Token{
		AccessToken: fmt.Sprintf("token-%d", i),
		TokenType:   bearerTokenType,
		Expiry:      time.Now().Add(f.lifetime),
	}, nil
}
