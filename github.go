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

	// maxErrorBodyBytes caps how much of a non-2xx body is read into the error
	// message, so a misbehaving or hostile server cannot exhaust memory.
	maxErrorBodyBytes = 64 << 10

	// maxRetrySleep caps sleeps between retries so a misbehaving or hostile
	// server cannot stall callers indefinitely via Retry-After.
	maxRetrySleep = 60 * time.Second

	// defaultThrottleBackoff is the fallback delay when GitHub returns 429
	// without any retry hint header.
	defaultThrottleBackoff = 1 * time.Second

	// secondaryRateLimitBackoff is the fallback delay for a 403 identified as a
	// rate limit that carries no usable hint. GitHub's guidance for that case is
	// to wait at least one minute before retrying.
	secondaryRateLimitBackoff = 60 * time.Second
)

// RateLimitError is the concrete error returned when GitHub throttles a
// request. It carries the wait the client computed from GitHub's own hints, so
// a caller running its own backoff does not have to re-parse the headers the
// client already read:
//
//	var rle *githubauth.RateLimitError
//	if errors.As(err, &rle) {
//		time.Sleep(rle.RetryAfter)
//	}
//
// It unwraps to ErrRateLimited, so errors.Is(err, ErrRateLimited) keeps working.
type RateLimitError struct {
	// StatusCode is the HTTP status GitHub returned, 429 or 403.
	StatusCode int

	// RetryAfter is how long to wait before retrying, taken from Retry-After or
	// X-RateLimit-Reset and capped at maxRetrySleep. It falls back to a
	// documented default when GitHub sends no usable hint. It is zero when
	// GitHub says to retry immediately, or when the reset instant has already
	// passed, so callers must treat zero as "retry now" rather than "no hint".
	RetryAfter time.Duration

	// Message is the response body, truncated to maxErrorBodyBytes.
	Message string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s: GitHub API returned status %d: %s", ErrRateLimited.Error(), e.StatusCode, e.Message)
}

// Unwrap reports ErrRateLimited so callers can branch with errors.Is without
// knowing about this type.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// ErrRateLimited wraps errors returned when GitHub has throttled a request:
// any HTTP 429, or a 403 that GitHub identifies as a rate limit rather than a
// permission failure. A 403 counts when it carries Retry-After, reports an
// exhausted budget via X-RateLimit-Remaining: 0, or says so in its message.
//
// A 403 such as "Resource not accessible by integration" is a permission
// failure and is NOT wrapped, even though GitHub attaches rate-limit headers
// to it. Callers can branch with errors.Is.
var ErrRateLimited = errors.New("github API rate limited")

// APIError is the concrete error returned when GitHub rejects a request for a
// reason other than throttling. It carries the status code so a caller can tell
// a credential that GitHub refused (401) from an installation that does not
// exist (404) without matching on the message:
//
//	var apiErr *githubauth.APIError
//	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
//		// the App is not installed on that installation ID
//	}
//
// A throttled request returns RateLimitError instead.
type APIError struct {
	// StatusCode is the HTTP status GitHub returned.
	StatusCode int

	// Message is the response body, truncated to maxErrorBodyBytes.
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API returned status %d: %s", e.StatusCode, e.Message)
}

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
	httpClient      *http.Client
	retryOnThrottle bool
}

// newGitHubClient creates a new GitHub API client.
func newGitHubClient(httpClient *http.Client) *githubClient {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &githubClient{
		baseURL:         baseURL,
		httpClient:      httpClient,
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

// withBaseURL sets the API base URL verbatim, applying none of the GitHub
// Enterprise Server path rewriting that withEnterpriseURL performs. Only a
// trailing slash is appended when missing so that endpoint resolution via
// baseURL.Parse works correctly.
func (c *githubClient) withBaseURL(baseURL string) (*githubClient, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %w", err)
	}

	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	c.baseURL = base

	return c, nil
}

// createInstallationToken creates an installation access token for a GitHub App.
// When retryOnThrottle is enabled, a single retry is performed on 429 or on 403
// responses that are actually throttled — those carrying Retry-After, or
// x-ratelimit-remaining: 0. The sleep is capped at maxRetrySleep and honors ctx
// cancellation.
//
// API documentation: https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
func (c *githubClient) createInstallationToken(ctx context.Context, installationID int64, opts *InstallationTokenOptions) (*InstallationToken, error) {
	// JoinPath appends to the base path and escapes each element, so it cannot
	// fail the way resolving a relative reference can, and an Enterprise base
	// path such as /api/v3/ is preserved rather than resolved against.
	u := c.baseURL.JoinPath("app", "installations", strconv.FormatInt(installationID, 10), "access_tokens")

	var bodyBytes []byte
	if opts != nil {
		var err error
		bodyBytes, err = json.Marshal(opts)
		// Unreachable guard: InstallationTokenOptions holds only strings,
		// int64s and pointers to them, none of which json.Marshal can reject.
		// Kept so a future field that can fail is not silently sent as no body.
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	token, err := c.doCreateInstallationToken(ctx, u.String(), bodyBytes)
	if err == nil {
		return token, nil
	}

	var throttled *RateLimitError
	if !c.retryOnThrottle || !errors.As(err, &throttled) {
		return nil, err
	}

	if sleepErr := sleepCtx(ctx, throttled.RetryAfter); sleepErr != nil {
		return nil, sleepErr
	}

	return c.doCreateInstallationToken(ctx, u.String(), bodyBytes)
}

// doCreateInstallationToken performs a single POST attempt. A throttled
// response yields a *RateLimitError carrying the retry delay, so the caller can
// decide whether to retry without re-reading the response.
func (c *githubClient) doCreateInstallationToken(ctx context.Context, reqURL string, bodyBytes []byte) (*InstallationToken, error) {
	var body io.Reader
	if bodyBytes != nil {
		body = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var token InstallationToken
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		return &token, nil
	}

	bodyResp, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if delay, ok := c.throttleDelay(resp, bodyResp); ok {
		return nil, &RateLimitError{
			StatusCode: resp.StatusCode,
			RetryAfter: delay,
			Message:    string(bodyResp),
		}
	}

	return nil, &APIError{StatusCode: resp.StatusCode, Message: string(bodyResp)}
}

// throttleDelay inspects a non-2xx response and reports the retry hint GitHub
// supplied. The bool is true when the response is considered retryable: any 429,
// and a 403 only when it is a rate limit rather than a permission failure. The
// returned duration is capped at maxRetrySleep. An unparseable header is treated
// as absent — a malformed hint must not silently flip a terminal 403 into a retry.
func (c *githubClient) throttleDelay(resp *http.Response, body []byte) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusForbidden {
		return 0, false
	}

	if v := resp.Header.Get("Retry-After"); v != "" {
		if d, ok := parseRetryAfter(v, time.Now()); ok {
			return capDelay(d), true
		}
	}

	if resp.StatusCode == http.StatusForbidden && !isRateLimit403(resp, body) {
		return 0, false
	}

	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if reset, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return capDelay(time.Until(time.Unix(reset, 0))), true
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return defaultThrottleBackoff, true
	}

	// A 403 that reached here is a rate limit with no usable hint.
	return secondaryRateLimitBackoff, true
}

// isRateLimit403 reports whether a 403 is a rate limit rather than a permission
// failure. GitHub attaches X-RateLimit-Limit / X-RateLimit-Remaining /
// X-RateLimit-Reset to essentially every authenticated response, terminal 403s
// such as "Resource not accessible by integration" included, so the presence of
// those headers proves nothing on its own: a permission failure carries a
// healthy remaining count and a reset epoch up to an hour out.
//
// Two things do distinguish one: an exhausted budget, or GitHub saying so in the
// message. The message matters because a secondary rate limit can arrive with a
// healthy primary budget and no Retry-After, and treating that as terminal would
// strip the ErrRateLimited callers branch on.
func isRateLimit403(resp *http.Response, body []byte) bool {
	if v := strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining")); v != "" {
		if remaining, err := strconv.ParseInt(v, 10, 64); err == nil && remaining <= 0 {
			return true
		}
	}
	return strings.Contains(strings.ToLower(string(body)), "rate limit")
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
