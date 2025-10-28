package githubauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"reflect"
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
					PullRequests: ptr("read"),
				},
				Repositories: []Repository{
					{
						Name: ptr("mocked-repo-1"),
						ID:   ptr(int64(1)),
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
