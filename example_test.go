package githubauth_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jferrl/go-githubauth"
	"golang.org/x/oauth2"
)

// Authenticate as a GitHub App with a Client ID (recommended by GitHub for
// new Apps). The returned source caches the JWT and refreshes it 30s before
// expiry.
func ExampleNewApplicationTokenSource() {
	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g. "Iv1.1234567890abcdef"

	appSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
	if err != nil {
		fmt.Println("creating application token source:", err)
		return
	}

	token, err := appSource.Token()
	if err != nil {
		fmt.Println("generating JWT:", err)
		return
	}

	fmt.Println("app JWT:", token.AccessToken)
}

// Authenticate with a legacy numeric App ID and a custom JWT expiration.
func ExampleNewApplicationTokenSource_appID() {
	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	appID, _ := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)

	appSource, err := githubauth.NewApplicationTokenSource(
		appID,
		privateKey,
		githubauth.WithApplicationTokenExpiration(5*time.Minute),
	)
	if err != nil {
		fmt.Println("creating application token source:", err)
		return
	}

	token, err := appSource.Token()
	if err != nil {
		fmt.Println("generating JWT:", err)
		return
	}

	fmt.Println("app JWT:", token.AccessToken)
}

// The full GitHub App chain: App JWT -> installation token -> authenticated
// HTTP client. The client works standalone or can be passed to
// github.NewClient from google/go-github.
func ExampleNewInstallationTokenSource() {
	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	clientID := os.Getenv("GITHUB_APP_CLIENT_ID")
	installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

	appSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
	if err != nil {
		fmt.Println("creating application token source:", err)
		return
	}

	installationSource := githubauth.NewInstallationTokenSource(installationID, appSource)

	// Every request carries a valid installation token; refresh is automatic.
	httpClient := oauth2.NewClient(context.Background(), installationSource)

	resp, err := httpClient.Get("https://api.github.com/installation/repositories")
	if err != nil {
		fmt.Println("listing installation repositories:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Println("status:", resp.Status)
}

// Point the installation token source at GitHub Enterprise Server (GHES) or
// GitHub Enterprise Cloud (GHEC) with data residency.
func ExampleNewInstallationTokenSource_enterprise() {
	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	clientID := os.Getenv("GITHUB_APP_CLIENT_ID")
	installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

	appSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
	if err != nil {
		fmt.Println("creating application token source:", err)
		return
	}

	// GHES: the URL is normalized the way GHES expects (/api/v3/ appended).
	ghes := githubauth.NewInstallationTokenSource(
		installationID,
		appSource,
		githubauth.WithEnterpriseURL("https://github.example.com"),
	)

	// GHEC with data residency: the URL is used verbatim.
	ghec := githubauth.NewInstallationTokenSource(
		installationID,
		appSource,
		githubauth.WithBaseURL("https://api.octocorp.ghe.com"),
	)

	_, _ = ghes, ghec
}

// Sign App JWTs with an external key store. Any RSA-backed crypto.Signer
// works: AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault
// Transit, PKCS#11 HSMs, or ssh-agent. A local *rsa.PrivateKey stands in for
// a KMS-backed signer here; in production the private key never touches
// process memory.
func ExampleNewApplicationTokenSourceFromSigner() {
	clientID := os.Getenv("GITHUB_APP_CLIENT_ID")

	block, _ := pem.Decode([]byte(os.Getenv("GITHUB_APP_PRIVATE_KEY")))
	if block == nil {
		fmt.Println("no PEM block found")
		return
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("parsing private key:", err)
		return
	}
	var signer crypto.Signer = key // swap for a KMS/HSM/Vault-backed signer

	appSource, err := githubauth.NewApplicationTokenSourceFromSigner(clientID, signer)
	if err != nil {
		fmt.Println("creating application token source:", err)
		return
	}

	token, err := appSource.Token()
	if err != nil {
		fmt.Println("generating JWT:", err)
		return
	}

	fmt.Println("app JWT:", token.AccessToken)
}

// Authenticate with a classic or fine-grained personal access token.
func ExampleNewPersonalAccessTokenSource() {
	token := os.Getenv("GITHUB_TOKEN") // "ghp_..." or "github_pat_..."

	tokenSource := githubauth.NewPersonalAccessTokenSource(token)
	httpClient := oauth2.NewClient(context.Background(), tokenSource)

	resp, err := httpClient.Get("https://api.github.com/user")
	if err != nil {
		fmt.Println("getting user:", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Println("status:", resp.Status)
}

// Wrap any third-party oauth2.TokenSource so cached tokens refresh before
// expiry instead of after it.
func ExampleReuseTokenSourceWithSkew() {
	var upstream oauth2.TokenSource // any token source, e.g. from another provider

	src := githubauth.ReuseTokenSourceWithSkew(nil, upstream, 30*time.Second)
	_ = src
}
