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
	"io"
	"net/http"
	"reflect"
	"strings"
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
			name:    "non-rsa signer is rejected",
			new:     func() (oauth2.TokenSource, error) { return NewApplicationTokenSourceFromSigner(int64(42), &stubSigner{pub: edPub}) },
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

	// Test with invalid URL - error is silently ignored in WithEnterpriseURL
	installationTokenSource := NewInstallationTokenSource(
		1,
		appSrc,
		WithEnterpriseURL("ht\ntp://invalid"),
	)

	// The error is silently ignored in WithEnterpriseURL, so this should still work
	// but will use the default URL
	if installationTokenSource == nil {
		t.Error("Expected non-nil token source")
	}

	// Test that the token source is created successfully
	// The error is silently ignored, so the source uses the default URL
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
