package githubauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// defaultBaseURL is the default GitHub API base URL.
	defaultBaseURL = "https://api.github.com/"
)

// InstallationTokenOptions specifies options for creating an installation token.
type InstallationTokenOptions struct {
	// Repositories is a list of repository names that the token should have access to.
	Repositories []string `json:"repositories,omitempty"`
	// RepositoryIDs is a list of repository IDs that the token should have access to.
	RepositoryIDs []int64 `json:"repository_ids,omitempty"`
	// Permissions are the permissions granted to the access token.
	Permissions *InstallationPermissions `json:"permissions,omitempty"`
}

// InstallationPermissions represents the permissions granted to an installation token.
type InstallationPermissions struct {
	Actions                         *string `json:"actions,omitempty"`
	Administration                  *string `json:"administration,omitempty"`
	Checks                          *string `json:"checks,omitempty"`
	Contents                        *string `json:"contents,omitempty"`
	ContentReferences               *string `json:"content_references,omitempty"`
	Deployments                     *string `json:"deployments,omitempty"`
	Environments                    *string `json:"environments,omitempty"`
	Issues                          *string `json:"issues,omitempty"`
	Metadata                        *string `json:"metadata,omitempty"`
	Packages                        *string `json:"packages,omitempty"`
	Pages                           *string `json:"pages,omitempty"`
	PullRequests                    *string `json:"pull_requests,omitempty"`
	RepositoryAnnouncementBanners   *string `json:"repository_announcement_banners,omitempty"`
	RepositoryHooks                 *string `json:"repository_hooks,omitempty"`
	RepositoryProjects              *string `json:"repository_projects,omitempty"`
	SecretScanningAlerts            *string `json:"secret_scanning_alerts,omitempty"`
	Secrets                         *string `json:"secrets,omitempty"`
	SecurityEvents                  *string `json:"security_events,omitempty"`
	SingleFile                      *string `json:"single_file,omitempty"`
	Statuses                        *string `json:"statuses,omitempty"`
	VulnerabilityAlerts             *string `json:"vulnerability_alerts,omitempty"`
	Workflows                       *string `json:"workflows,omitempty"`
	Members                         *string `json:"members,omitempty"`
	OrganizationAdministration      *string `json:"organization_administration,omitempty"`
	OrganizationCustomRoles         *string `json:"organization_custom_roles,omitempty"`
	OrganizationAnnouncementBanners *string `json:"organization_announcement_banners,omitempty"`
	OrganizationHooks               *string `json:"organization_hooks,omitempty"`
	OrganizationPlan                *string `json:"organization_plan,omitempty"`
	OrganizationProjects            *string `json:"organization_projects,omitempty"`
	OrganizationPackages            *string `json:"organization_packages,omitempty"`
	OrganizationSecrets             *string `json:"organization_secrets,omitempty"`
	OrganizationSelfHostedRunners   *string `json:"organization_self_hosted_runners,omitempty"`
	OrganizationUserBlocking        *string `json:"organization_user_blocking,omitempty"`
	TeamDiscussions                 *string `json:"team_discussions,omitempty"`
}

// InstallationToken represents a GitHub App installation token.
type InstallationToken struct {
	Token        string                   `json:"token"`
	ExpiresAt    time.Time                `json:"expires_at"`
	Permissions  *InstallationPermissions `json:"permissions,omitempty"`
	Repositories []Repository             `json:"repositories,omitempty"`
}

// Repository represents a GitHub repository.
type Repository struct {
	ID   *int64  `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// githubClient is a simple GitHub API client for creating installation tokens.
type githubClient struct {
	baseURL *url.URL
	client  *http.Client
}

// newGitHubClient creates a new GitHub API client.
func newGitHubClient(httpClient *http.Client) *githubClient {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &githubClient{
		baseURL: baseURL,
		client:  httpClient,
	}
}

// withEnterpriseURL sets the base URL for GitHub Enterprise Server.
func (c *githubClient) withEnterpriseURL(baseURL string) (*githubClient, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	c.baseURL = base

	return c, nil
}

// createInstallationToken creates an installation access token for a GitHub App.
// API documentation: https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
func (c *githubClient) createInstallationToken(ctx context.Context, installationID int64, opts *InstallationTokenOptions) (*InstallationToken, error) {
	endpoint := fmt.Sprintf("app/installations/%d/access_tokens", installationID)
	u, err := c.baseURL.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint URL: %w", err)
	}

	var body io.Reader
	if opts != nil {
		jsonBody, err := json.Marshal(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		body = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var token InstallationToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &token, nil
}

// Ptr is a helper function to create a pointer to a value.
// This is useful when constructing InstallationTokenOptions with permissions.
func Ptr[T any](v T) *T {
	return &v
}
