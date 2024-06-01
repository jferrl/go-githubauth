package githubauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	"golang.org/x/oauth2"
)

func TestNewApplicationTokenSource(t *testing.T) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		appID      int64
		privateKey []byte
		opts       []ApplicationTokenOpt
	}
	tests := []struct {
		name    string
		args    args
		want    oauth2.TokenSource
		wantErr bool
	}{
		{
			name:    "application id is not provided",
			args:    args{},
			wantErr: true,
		},
		{
			name:    "private key is not provided",
			args:    args{appID: 132},
			wantErr: true,
		},
		{
			name: "valid application token source",
			args: args{
				appID:      132,
				privateKey: privateKey,
				opts: []ApplicationTokenOpt{
					WithApplicationTokenExpiration(15 * time.Minute),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewApplicationTokenSource(tt.args.appID, tt.args.privateKey, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewApplicationTokenSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_installationTokenSource_Token(t *testing.T) {
	now := time.Now().UTC()
	expiration := now.Add(10 * time.Minute)

	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.PostAppInstallationsAccessTokensByInstallationId,
			github.InstallationToken{
				Token: github.String("mocked-installation-token"),
				ExpiresAt: &github.Timestamp{
					Time: expiration,
				},
				Permissions: &github.InstallationPermissions{
					PullRequests: github.String("read"),
				},
				Repositories: []*github.Repository{
					{
						Name: github.String("mocked-repo-1"),
						ID:   github.Int64(1),
					},
				},
			},
		),
	)

	errMockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatchHandler(
			mock.PostAppInstallationsAccessTokensByInstallationId,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"Internal Server Error"}`))
			}),
		))

	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	appSrc, err := NewApplicationTokenSource(34434, privateKey, WithApplicationTokenExpiration(5*time.Minute))
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
					WithInstallationTokenOptions(&github.InstallationTokenOptions{}),
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
					WithInstallationTokenOptions(&github.InstallationTokenOptions{}),
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
