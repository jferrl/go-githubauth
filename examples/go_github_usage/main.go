package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/google/go-github/v62/github"
	"github.com/jferrl/go-githubauth"
	"golang.org/x/oauth2"
)

func main() {
	privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	appID := os.Getenv("GITHUB_APP_ID")
	installationID, _ := strconv.ParseInt(os.Getenv("GITHUB_INSTALLATION_ID"), 10, 64)

	appTokenSource, err := githubauth.NewApplicationTokenSource(appID, privateKey)
	if err != nil {
		fmt.Println("Error creating application token source:", err)
		return
	}

	installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)

	// oauth2.NewClient create a new http.Client that adds an Authorization header with the token.
	// Transport src use oauth2.ReuseTokenSource to reuse the token.
	// The token will be reused until it expires.
	// The token will be refreshed if it's expired.
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
