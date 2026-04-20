package githubauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultBaseURL is the default GitHub API base URL.
	defaultBaseURL = "https://api.github.com/"

	// maxRetrySleep caps sleeps between retries so a misbehaving or hostile
	// server cannot stall callers indefinitely via Retry-After.
	maxRetrySleep = 60 * time.Second

	// defaultThrottleBackoff is the fallback delay when GitHub returns 429
	// without any retry hint header.
	defaultThrottleBackoff = 1 * time.Second
)

// ErrRateLimited wraps errors returned when GitHub has throttled a request
// (HTTP 429 or 403 with rate-limit headers). Callers can branch with errors.Is.
var ErrRateLimited = errors.New("github API rate limited")

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
	baseURL         *url.URL
	client          *http.Client
	retryOnThrottle bool
}

// newGitHubClient creates a new GitHub API client.
func newGitHubClient(httpClient *http.Client) *githubClient {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &githubClient{
		baseURL:         baseURL,
		client:          httpClient,
		retryOnThrottle: true,
	}
}

// withEnterpriseURL sets the base URL for GitHub Enterprise Server.
func (c *githubClient) withEnterpriseURL(baseURL string) (*githubClient, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	if !strings.HasSuffix(base.Path, "/api/v3/") &&
		!strings.HasPrefix(base.Host, "api.") &&
		!strings.Contains(base.Host, ".api.") {
		base.Path += "api/v3/"
	}

	c.baseURL = base

	return c, nil
}

// createInstallationToken creates an installation access token for a GitHub App.
// When retryOnThrottle is enabled, a single retry is performed on 429 or on 403
// responses that carry Retry-After / x-ratelimit-reset headers. The sleep is
// capped at maxRetrySleep and honors ctx cancellation.
//
// API documentation: https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
func (c *githubClient) createInstallationToken(ctx context.Context, installationID int64, opts *InstallationTokenOptions) (*InstallationToken, error) {
	endpoint := fmt.Sprintf("app/installations/%d/access_tokens", installationID)
	u, err := c.baseURL.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint URL: %w", err)
	}

	var bodyBytes []byte
	if opts != nil {
		bodyBytes, err = json.Marshal(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	token, delay, err := c.doCreateInstallationToken(ctx, u.String(), bodyBytes)
	if err == nil {
		return token, nil
	}
	if !c.retryOnThrottle || !errors.Is(err, ErrRateLimited) {
		return nil, err
	}

	if sleepErr := sleepCtx(ctx, delay); sleepErr != nil {
		return nil, sleepErr
	}

	token, _, err = c.doCreateInstallationToken(ctx, u.String(), bodyBytes)
	return token, err
}

// doCreateInstallationToken performs a single POST attempt. On a throttled
// response it returns the desired retry delay in addition to the error so the
// caller can decide whether to retry. A zero delay indicates the error is not
// retryable.
func (c *githubClient) doCreateInstallationToken(ctx context.Context, reqURL string, bodyBytes []byte) (*InstallationToken, time.Duration, error) {
	var body io.Reader
	if bodyBytes != nil {
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var token InstallationToken
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return nil, 0, fmt.Errorf("failed to decode response: %w", err)
		}
		return &token, 0, nil
	}

	bodyResp, _ := io.ReadAll(resp.Body)
	if delay, ok := c.throttleDelay(resp); ok {
		return nil, delay, fmt.Errorf("%w: GitHub API returned status %d: %s", ErrRateLimited, resp.StatusCode, string(bodyResp))
	}

	return nil, 0, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(bodyResp))
}

// throttleDelay inspects a non-2xx response and reports the retry hint from
// GitHub's rate-limit headers. The bool is true when the response is considered
// retryable (429 always, 403 only when a parseable retry header is present).
// The returned duration is capped at maxRetrySleep. An unparseable header is
// treated as absent — a malformed hint must not silently flip a terminal 403
// into a retry.
func (c *githubClient) throttleDelay(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusForbidden {
		return 0, false
	}

	if v := resp.Header.Get("Retry-After"); v != "" {
		if d, ok := parseRetryAfter(v, time.Now()); ok {
			return capDelay(d), true
		}
	}

	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if reset, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return capDelay(time.Until(time.Unix(reset, 0))), true
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return defaultThrottleBackoff, true
	}

	return 0, false
}

// parseRetryAfter accepts either integer seconds ("30") or an HTTP-date
// ("Fri, 31 Dec 1999 23:59:59 GMT"), per RFC 7231 §7.1.3. The bool is false
// when the value is neither form, so callers can distinguish "no hint" from
// "zero seconds".
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(now), true
	}
	return 0, false
}

func capDelay(d time.Duration) time.Duration {
	if d > maxRetrySleep {
		return maxRetrySleep
	}
	if d < 0 {
		return 0
	}
	return d
}

// sleepCtx sleeps for d or until ctx is cancelled, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Ptr is a helper function to create a pointer to a value.
// This is useful when constructing InstallationTokenOptions with permissions.
func Ptr[T any](v T) *T {
	return &v
}
