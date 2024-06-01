package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/jferrl/go-githubauth"
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

	token, err := installationTokenSource.Token()
	if err != nil {
		fmt.Println("Error generating installation token:", err)
		return
	}

	fmt.Println("Generated installation token:", token.AccessToken)
}
