# go-githubauth

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=blue)](https://pkg.go.dev/github.com/jferrl/go-githubauth)
[![Test Status](https://github.com/jferrl/go-githubauth/workflows/tests/badge.svg)](https://github.com/jferrl/go-githubauth/actions?query=workflow%3Atests)
[![codecov](https://codecov.io/gh/jferrl/go-githubauth/branch/main/graph/badge.svg?token=68I4BZF235)](https://codecov.io/gh/jferrl/go-githubauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/jferrl/go-githubauth)](https://goreportcard.com/report/github.com/jferrl/go-githubauth)

`go-githubauth` is a Go package that provides utilities for GitHub authentication, including generating and using GitHub App tokens and installation tokens.

**v1.3.0** introduces Go generics support for unified authentication with both numeric App IDs and alphanumeric Client IDs in a single, type-safe API.

---

⭐ **Found this package useful?** Give it a star on GitHub! Your support helps others discover this project and motivates continued development.

[![Star this repo](https://img.shields.io/github/stars/jferrl/go-githubauth?style=social)](https://github.com/jferrl/go-githubauth/stargazers)

---

## Features

`go-githubauth` package provides implementations of the `TokenSource` interface from the `golang.org/x/oauth2` package. This interface has a single method, Token, which returns an *oauth2.Token.

### v1.3.0 Features

- **🔥 Go Generics Support**: Single `NewApplicationTokenSource` function supports both `int64` App IDs and `string` Client IDs
- **🛡️ Type Safety**: Compile-time verification of identifier types through generic constraints
- **⚡ Type Inference**: Automatic type detection - no need to specify generic parameters explicitly
- **📖 Enhanced Documentation**: Official GitHub API references and comprehensive JWT details

### Core Capabilities

- Generate GitHub Application JWT [Generating a jwt for a github app](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
- Obtain GitHub App installation tokens [Authenticating as a GitHub App](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api?apiVersion=2022-11-28#authenticating-with-a-token-generated-by-an-app)
- RS256-signed JWTs with proper clock drift protection
- Support for both legacy App IDs and modern Client IDs (recommended by GitHub)

### Requirements

- This package is designed to be used with the `golang.org/x/oauth2` package

## Installation

To use `go-githubauth` in your project, you need to have Go installed. You can get the package via:

```bash
go get -u github.com/jferrl/go-githubauth
```

## Usage

### Usage with [go-github](https://github.com/google/go-github) and [oauth2](golang.org/x/oauth2)

#### Client ID (Recommended)

```go
package main

import (
 "context"
 "fmt"
 "os"
 "strconv"

 "github.com/google/go-github/v73/github"
 "github.com/jferrl/go-githubauth"
 "golang.org/x/oauth2"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g., "Iv1.1234567890abcdef"
 installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

 // Go automatically infers the type as string for Client ID
 appTokenSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

 // oauth2.NewClient creates a new http.Client that adds an Authorization header with the token
 httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
 githubClient := github.NewClient(httpClient)

 _, _, err = githubClient.PullRequests.CreateComment(context.Background(), "owner", "repo", 1, &github.PullRequestComment{
  Body: github.String("Awesome comment!"),
 })
 if err != nil {
  fmt.Println("Error creating comment:", err)
  return
 }
}
```

#### App ID (Legacy)

```go
package main

import (
 "context"
 "fmt"
 "os"
 "strconv"

 "github.com/google/go-github/v73/github"
 "github.com/jferrl/go-githubauth"
 "golang.org/x/oauth2"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 appID, _ := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
 installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

 // Explicitly cast to int64 for App ID - Go automatically infers the type
 appTokenSource, err := githubauth.NewApplicationTokenSource(int64(appID), privateKey)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

 httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
 githubClient := github.NewClient(httpClient)

 _, _, err = githubClient.PullRequests.CreateComment(context.Background(), "owner", "repo", 1, &github.PullRequestComment{
  Body: github.String("Awesome comment!"),
 })
 if err != nil {
  fmt.Println("Error creating comment:", err)
  return
 }
}
```

### Generate GitHub Application Token

First, create a GitHub App and generate a private key. To authenticate as a GitHub App, you need to generate a JWT. [Generating a JWT for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)

#### With Client ID (Recommended)

```go
package main

import (
 "fmt"
 "os"
 "time"

 "github.com/jferrl/go-githubauth"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g., "Iv1.1234567890abcdef"

 // Type automatically inferred as string
 tokenSource, err := githubauth.NewApplicationTokenSource(
  clientID, 
  privateKey, 
  githubauth.WithApplicationTokenExpiration(5*time.Minute),
 )
 if err != nil {
  fmt.Println("Error creating token source:", err)
  return
 }

 token, err := tokenSource.Token()
 if err != nil {
  fmt.Println("Error generating token:", err)
  return
 }

 fmt.Println("Generated JWT token:", token.AccessToken)
}
```

#### With App ID

```go
package main

import (
 "fmt"
 "os"
 "strconv"
 "time"

 "github.com/jferrl/go-githubauth"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 appID, _ := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)

 // Type automatically inferred as int64
 tokenSource, err := githubauth.NewApplicationTokenSource(
  int64(appID), 
  privateKey, 
  githubauth.WithApplicationTokenExpiration(5*time.Minute),
 )
 if err != nil {
  fmt.Println("Error creating token source:", err)
  return
 }

 token, err := tokenSource.Token()
 if err != nil {
  fmt.Println("Error generating token:", err)
  return
 }

 fmt.Println("Generated JWT token:", token.AccessToken)
}
```

### Generate GitHub App Installation Token

To authenticate as a GitHub App installation, you need to obtain an installation token using your GitHub App JWT.

```go
package main

import (
 "fmt"
 "os"
 "strconv"

 "github.com/jferrl/go-githubauth"
)

func main() {
 privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
 clientID := os.Getenv("GITHUB_APP_CLIENT_ID") // e.g., "Iv1.1234567890abcdef"
 installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

 // Create GitHub App JWT token source with Client ID
 appTokenSource, err := githubauth.NewApplicationTokenSource(clientID, privateKey)
 if err != nil {
  fmt.Println("Error creating application token source:", err)
  return
 }

 // Create installation token source using the app token source
 installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

 token, err := installationTokenSource.Token()
 if err != nil {
  fmt.Println("Error generating installation token:", err)
  return
 }

 fmt.Println("Generated installation token:", token.AccessToken)
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
