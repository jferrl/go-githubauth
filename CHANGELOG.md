# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Module path.** `github.com/jferrl/go-githubauth` (v1.x) is the supported module. The
> `/v2` path was published by accident and is **permanently retracted**: v2.0.0, v2.0.1
> and v2.0.2 are all covered by the `retract` block in `v2/go.mod` at the `v2.0.2` tag,
> including v2.0.2 itself, so `go get` resolves none of them and `go list -m -versions`
> reports no versions for that path. There will be no v2.
>
> That `v2.0.2` tag is the only thing carrying the retraction — the `v2/` directory no
> longer exists on `main` — so the tag must not be deleted or the retraction is lost.

## [v1.9.0] - 2026-09-19

The library is unchanged. This release is the `githubauth` command line tool and the
machinery to distribute it, so a shell script or CI step can get an installation token
without a Go toolchain.

### Added

- `cmd/githubauth`, a command line tool that prints an installation token or the App JWT,
  so a shell script or CI step can authenticate as a GitHub App without reimplementing
  the JWT-then-exchange chain. Install it with
  `go install github.com/jferrl/go-githubauth/cmd/githubauth@latest`.

  The token is the only thing written to stdout, so `$(githubauth token)` composes with
  `curl` and friends. Every flag falls back to an environment variable, and `--key`
  accepts a file path, the PEM itself, or `-` to read stdin so the key never has to touch
  disk.

  It adds no module dependencies. The CLI is built on the standard library's `flag`, so
  the two-dependency footprint is unchanged for anyone importing the library.

- Prebuilt `githubauth` binaries on each release, for Linux, macOS and Windows on amd64
  and arm64, with a `checksums.txt` to verify them. A tagged release builds them with
  GoReleaser; the library is unaffected and is still consumed with `go get`.

- A Homebrew cask, so the CLI installs without a Go toolchain:

  ```bash
  brew install jferrl/tap/githubauth
  ```

  The cask is generated into [jferrl/homebrew-tap](https://github.com/jferrl/homebrew-tap)
  when a release is tagged.

### Fixed

- `githubauth version` reported a pseudo-version for a binary that was not installed with
  `go install`. A release build now carries its tag, and a build from a checkout falls
  back to the stamped commit.

## [v1.8.0] - 2026-09-18

A correctness release. Two changes alter behaviour callers may depend on; both
are listed under Changed and are worth reading before upgrading.

### Added

- `RateLimitError{StatusCode, RetryAfter, Message}`, the concrete error returned when
  GitHub throttles a request. It carries the wait the client computed from GitHub's own
  headers, so a caller running its own backoff no longer has to re-parse a response it
  never sees. Extract it with `errors.As`; it unwraps to `ErrRateLimited`, so
  `errors.Is` and the rendered error string are unchanged (#65)

### Changed

- **A 403 is no longer treated as rate limiting just because it carries rate-limit
  headers.** GitHub attaches `X-RateLimit-*` to essentially every authenticated
  response, so a terminal `Resource not accessible by integration` was slept on for up
  to 60s, retried, and returned wrapped in `ErrRateLimited`. A 403 now counts as
  throttled only when it carries `Retry-After`, reports an exhausted budget, or says so
  in its message. Callers branching on `errors.Is(err, ErrRateLimited)` will no longer
  match a permission failure (#63)
- **`WithApplicationTokenExpiration` rejects values at or below 90 seconds**, the 60s
  clock-drift backdate plus `DefaultExpirySkew`, falling back to the 10 minute default.
  Below that bound the cache can never hold the token and every call re-signs. The
  README previously documented `1 * time.Minute`, which is affected (#63)
- `WithHTTPClient` reuses the application JWT across requests, matching the default
  transport, instead of re-signing on every installation-token request (#62)

### Security

- **An empty webhook secret is refused instead of used as an HMAC key.** HMAC accepts a
  zero-length key, so a deployment that called `Middleware(nil)` or read a missing
  secret from the environment verified every delivery against a key anyone can
  reproduce, and forged payloads reached the downstream handler as authentic. `Verify`
  now returns the new `ErrMissingSecret`, so a misconfigured deployment fails closed
  (#61)

### Fixed

- Named identifier types are accepted. The `Identifier` constraint is `~int64 | ~string`,
  but the implementation type-switched on the exact dynamic type, so `type AppID int64`
  was rejected with `unsupported identifier type` (#63)
- A short application token expiration no longer mints an already-dead JWT. Issuance is
  backdated 60s for clock drift and only the upper bound was clamped, so a 30 second
  expiration produced a token that had expired 30 seconds earlier (#63)
- A non-positive installation ID fails as a configuration error before any network call,
  rather than as a 404 from GitHub (#62)
- The wait for a response header is bounded. Dial, TLS handshake and idle connections
  were capped, but a server that accepted a connection and then stalled hung `Token()`
  indefinitely, holding the token cache mutex against every concurrent caller (#61)
- The error body of a failed response is capped at 64 KiB (#63)
- Three comments claimed a default application JWT is usable for 9m30s; the backdating
  makes it 8m30s (#63)
- `ErrRateLimited` and `WithRetryOnThrottle` godoc now describe the 403 contract they
  actually implement (#63)
- Examples check the error from `resp.Body.Close` (#54)

### Documentation

- Added godoc examples, package documentation, `llms.txt`, and a comparison with
  `ghinstallation` (#54)
- README reduced from 587 to 148 lines (#54)
- **GitHub stateless installation tokens: no action required.** GitHub is replacing the
  short opaque installation token with a `ghs_`-prefixed JWT of about 520 characters
  ([announcement](https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header/)).
  This library copies the token string into `oauth2.Token.AccessToken` and never parses,
  measures or validates it, and expiry is read from `expires_at`, so both formats work
  unchanged. GitHub Enterprise Server is out of scope; Enterprise Cloud and Data
  Residency endpoints are in scope, as is the Actions `GITHUB_TOKEN`

### Tests

- Both installation token formats, stateless and classic opaque, are pinned for verbatim
  passthrough
- Every reachable branch is covered, and a test that reached `example.com` over the
  network on each CI run was replaced with ones that exercise what their names claim
  (#66)

### Internal

- Dropped two branches no input can reach, and replaced a relative-reference endpoint
  resolution with `url.URL.JoinPath`, which cannot fail and preserves an Enterprise
  `/api/v3/` prefix by construction (#66)

### Dependencies

- Moved to the Go 1.26 toolchain
- Bumped `golang.org/x/oauth2` from 0.36.0 to 0.37.0 (#59)
- Bumped `github/codeql-action` from 4 to 4.38.0 (#53, #55, #56, #57, #58, #60)
- Bumped `actions/setup-go` from 6 to 7 (#52)

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.7.0...v1.8.0>

## [v1.7.0] - 2026-06-30

GitHub Enterprise Cloud support and a more foolproof installation-token configuration.

### Added

- **Custom base URL**: `WithBaseURL` sets the API base URL verbatim, normalizing only a
  trailing slash, mirroring how `go-github` targets a custom endpoint. Unlike
  `WithEnterpriseURL` it does not append `/api/v3/`, which enables GitHub Enterprise
  Cloud with data residency (`https://api.SUBDOMAIN.ghe.com/`) and pointing the client
  at an `httptest` server in tests (#50)

### Changed

- **Order-independent options**: `WithBaseURL`, `WithEnterpriseURL`, `WithHTTPClient` and
  `WithRetryOnThrottle` can be combined in any order. `WithHTTPClient` previously rebuilt
  the client and silently discarded a base URL or retry setting applied before it
- **Fail-loud configuration**: an invalid base URL, or a nil HTTP client, is reported by
  the first call to `Token()` instead of silently falling back to the public GitHub API

### Fixed

- `WithHTTPClient` operates on a shallow copy, so the caller's `*http.Client`, which may
  be shared elsewhere, keeps its original transport
- Passing nil to `WithHTTPClient` yields a clear error instead of panicking

### Maintenance

- Removed the deprecated, no-op `net.Dialer.DualStack` field from the pooled HTTP client
- Renamed the unexported `githubClient.client` field to `httpClient`

### Tests

- Coverage for `WithBaseURL` (GHEC and `httptest` URLs), option order-independence,
  fail-loud misconfiguration, and that the caller's HTTP client is not mutated

### Dependencies

- Bumped `actions/cache` from 5 to 6 (#49)
- Bumped `actions/checkout` from 6 to 7 (#48)
- Bumped `codecov/codecov-action` from 6 to 7 (#46)

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.6.0...v1.7.0>

## [v1.6.0] - 2026-04-20

### Added

- **External key store support**: `NewApplicationTokenSourceFromSigner` accepts any
  `crypto.Signer` with an RSA public key, so the App private key never enters process
  memory. Works with AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit, PKCS#11
  HSMs and ssh-agent. Construction verifies the signer's public key is `*rsa.PublicKey`,
  since GitHub requires RS256
- **Proactive token refresh**: `ReuseTokenSourceWithSkew` refreshes a cached token when
  `time.Until(exp) <= skew` rather than waiting for expiry to pass, closing the window
  where a request starts shortly before expiry and reaches GitHub already expired. Tune
  with `WithExpirySkew` and `WithInstallationExpirySkew`
- **Automatic retry on throttling**: installation token fetches retry once on 429, or on
  403 carrying `Retry-After` / `X-RateLimit-Reset`. The sleep honors context cancellation
  and is capped at 60s, and a terminal throttle wraps `ErrRateLimited` for `errors.Is`.
  Opt out with `WithRetryOnThrottle(false)`
- **`webhook` subpackage**: constant-time HMAC-SHA256 verification of GitHub deliveries.
  `Verify` with sentinel errors (`ErrMissingSignature`, `ErrInvalidSignatureFormat`,
  `ErrSignatureMismatch`), and `Middleware` with body restoration, a 25 MiB default cap
  and 401/413 short-circuits, configurable via `WithMaxPayloadSize` and
  `WithErrorHandler`

### Changed

- **Minimum Go version is 1.25**, transitively required by `golang.org/x/oauth2` v0.36.0.
  The README previously claimed 1.21
- **Token sources refresh 30s before expiry by default.** Pass `WithExpirySkew(0)` or
  `WithInstallationExpirySkew(0)` to restore the previous behaviour

### Dependencies

- Bumped `golang.org/x/oauth2` from 0.34.0 to 0.36.0
- Bumped `codecov/codecov-action` from 5 to 6
- Bumped `styfle/cancel-workflow-action` from 0.13.0 to 0.13.1

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.5.1...v1.6.0>

## [v1.5.1] - 2026-02-09

### Fixed

- **Enterprise URL Handling**: Fixed regression in GitHub Enterprise URL handling (#41)

### Tests

- Tightened test conditions and added more tests for `WithEnterpriseURL`

### Dependencies

- Bumped `github.com/golang-jwt/jwt/v5` from 5.3.0 to 5.3.1 (#39)
- Bumped `golang.org/x/oauth2` from 0.32.0 to 0.34.0 (#34, #36)
- Bumped `actions/checkout` from 5 to 6 (#35)
- Bumped `actions/cache` from 4 to 5 (#37)
- Bumped `golangci/golangci-lint-action` from 8 to 9 (#33)
- Bumped `styfle/cancel-workflow-action` from 0.12.1 to 0.13.0 (#38)

**Contributors**: @luna-veil-8080

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.5.0...v1.5.1>

## [v1.5.0] - 2025-10-28

### 🚨 Breaking Changes

This release removes the `github.com/google/go-github/v74` dependency and implements a lightweight internal GitHub API client. While most users will experience no breaking changes, some API adjustments have been made:

#### API Changes

1. **Enterprise Configuration Simplified**
   - **Before**: `WithEnterpriseURLs(baseURL, uploadURL string)` - required both base and upload URLs
   - **After**: `WithEnterpriseURL(baseURL string)` - single base URL parameter
   - **Migration**: Remove the redundant upload URL parameter

2. **Type Changes** (if you were using these types directly)
   - `github.InstallationTokenOptions` → `githubauth.InstallationTokenOptions`
   - `github.InstallationPermissions` → `githubauth.InstallationPermissions`
   - `github.InstallationToken` → `githubauth.InstallationToken`
   - `github.Repository` → `githubauth.Repository`

### Added

- **Internal GitHub API Client**: New `github.go` file with minimal GitHub API implementation
  - Direct HTTP API calls to GitHub's REST API
  - `InstallationTokenOptions` type for configuring installation token requests
  - `InstallationPermissions` type with comprehensive permission structure
  - `InstallationToken` response type from GitHub API
  - `Repository` type for minimal repository representation
- **Public Helper Function**: Added `Ptr[T]()` generic helper for creating pointers to any type (useful for InstallationTokenOptions)

### Changed

- **Removed Dependency**: Eliminated `github.com/google/go-github/v74` dependency
- **Removed Dependency**: Eliminated `github.com/google/go-querystring` indirect dependency
- **Simplified Enterprise Support**: Streamlined from `WithEnterpriseURLs()` to `WithEnterpriseURL()`
- **Updated Documentation**: Package docs now reflect that the library is built only on `golang.org/x/oauth2`
- **Binary Size Reduction**: Smaller binaries without unused go-github code

### Fixed

- **Documentation**: Fixed GitHub API documentation link for installation token generation

### Migration Guide

#### For Most Users

No action required - if you only use the public `TokenSource` functions, your code will continue to work without changes.

#### For Enterprise GitHub Users

```go
// Before (v1.4.x)
installationTokenSource := githubauth.NewInstallationTokenSource(
    installationID, 
    appTokenSource,
    githubauth.WithEnterpriseURLs("https://github.example.com", "https://github.example.com"),
)

// After (v1.5.0)
installationTokenSource := githubauth.NewInstallationTokenSource(
    installationID, 
    appTokenSource,
    githubauth.WithEnterpriseURL("https://github.example.com"),
)
```

#### For Direct Type Users

```go
// Before (v1.4.x)
import "github.com/google/go-github/v74/github"
opts := &github.InstallationTokenOptions{
    Repositories: []string{"repo1", "repo2"},
    Permissions: &github.InstallationPermissions{
        Contents: github.Ptr("read"),
    },
}

// After (v1.5.0)
import "github.com/jferrl/go-githubauth"
opts := &githubauth.InstallationTokenOptions{
    Repositories: []string{"repo1", "repo2"},
    Permissions: &githubauth.InstallationPermissions{
        Contents: githubauth.Ptr("read"), // Use the new Ptr() helper
    },
}
```

### Benefits

- ✅ **Reduced Dependencies**: 2 fewer dependencies (from 3 to 2 total)
- ✅ **Smaller Binary Size**: No unused go-github code included
- ✅ **Better Control**: Full ownership of GitHub API integration
- ✅ **Easier Debugging**: Simpler code path for troubleshooting
- ✅ **Same Performance**: All token caching and performance optimizations maintained

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.4.2...v1.5.0>

## [v1.4.2] - 2025-09-19

### Changed

- Replace external GitHub mock with local implementation

## [v1.4.1] - 2025-09-19

### Changed

- **Enhanced Token Reuse**: Implemented `ReuseTokenSource` in `NewApplicationTokenSource` for improved token caching efficiency
- **Dependency Updates**: Bumped `golang.org/x/oauth2` from 0.30.0 to 0.31.0
- **CI/CD Improvements**: Updated GitHub Actions dependencies and workflow permissions
  - Bumped `actions/setup-go` from 5 to 6
  - Bumped `actions/checkout` from 4 to 5
- **Library Upgrade**: Upgraded `github.com/google/go-github` to v74

### Fixed

- **Security**: Fixed code scanning alert regarding workflow permissions

### Dependencies

- Bumped `golang.org/x/oauth2` from 0.30.0 to 0.31.0 (#25)
- Bumped `actions/setup-go` from 5 to 6 (#26)
- Bumped `actions/checkout` from 4 to 5 (#28)
- Upgraded `github.com/google/go-github` to v74 (#29)

**Contributors**: @jferrl, @krancour (first contribution)

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.4.0...v1.4.1>

## [v1.4.0] - 2025-08-30

### Added

- **Personal Access Token Support**: New `NewPersonalAccessTokenSource` function for classic and fine-grained personal access tokens
- **Advanced Token Caching**: Implemented dual-layer token caching system using `oauth2.ReuseTokenSource`
  - JWT tokens cached until expiration (up to 10 minutes)
  - Installation tokens cached until expiration (up to 1 hour)
- **High-Performance HTTP Client**: Custom `cleanHTTPClient` implementation with connection pooling
  - Based on HashiCorp's go-cleanhttp patterns for production reliability
  - HTTP/2 support with persistent connections
  - No shared global state to prevent race conditions

### Changed

- **Significant Performance Improvements**: Up to 99% reduction in unnecessary token generation and GitHub API calls
- **Enhanced Documentation**: Added comprehensive examples for personal access token usage
- **Optimized Memory Usage**: Reduced object allocation through intelligent token reuse

### Performance

- **GitHub App JWTs**: Cached and reused until expiration instead of regenerating on every API call
- **Installation Tokens**: Cached until expiration, dramatically reducing GitHub API rate limit consumption  
- **Connection Pooling**: HTTP connections reused across requests for faster GitHub API interactions
- **Production Ready**: Optimized for high-throughput applications and CI/CD systems

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.3.0...v1.4.0>

## [v1.3.0] - 2025-08-16

### Added

- **Go Generics Support**: Introduced generic constraint `Identifier` interface supporting both `int64` App IDs and `string` Client IDs in a single `NewApplicationTokenSource` function
- **Type-Safe Authentication**: Automatic type inference eliminates the need for separate functions while maintaining type safety
- **Enhanced Documentation**: Official GitHub API references and JWT technical details while maintaining godoc compliance

### Changed

- Unified `NewApplicationTokenSource` function now uses Go generics to support both int64 App IDs and string Client IDs
- Go version requirement bumped to 1.21+ (required for generics support)
- Updated Go version to 1.25 in CI workflows and documentation
- Improved CI workflow configurations with updated GitHub Actions

### Fixed

- Eliminated code duplication between App ID and Client ID authentication flows
- Fixed go version usage from go.mod in GitHub Actions build (#12)

### Dependencies

- Added Dependabot configuration to keep dependencies up to date (#13)
- Bumped `styfle/cancel-workflow-action` from 0.10.0 to 0.12.1 (#15)
- Bumped `actions/checkout` from 4 to 5 (#18)
- Bumped `codecov/codecov-action` from 4 to 5 (#19)

**Contributors**: @jferrl, @grinish21

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.2.1...v1.3.0>

## [v1.2.1] - 2025-08-08

### Fixed

- **Security**: Fixed JWT vulnerability GO-2025-3553 by upgrading jwt dependency to v5.3.0 (#9)

**Contributors**: @grinish21

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.2.0...v1.2.1>

## [v1.2.0] - 2025-03-18

### Changed

- Bumped dependencies to latest versions (#8)

**Contributors**: @candiepih (first contribution)

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.1.1...v1.2.0>

## [v1.1.1] - 2024-09-09

### Fixed

- Fixed 404 links in README documentation (#3)

### Changed

- Bumped dependencies to latest versions (#6)
- Upgraded Go version to 1.23 (#7)

**Contributors**: @grinish21 (first contribution), @jferrl

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.1.0...v1.1.1>

## [v1.1.0] - 2024-08-10

### Added

- GitHub Enterprise Server compatibility

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.0.2...v1.1.0>

## [v1.0.2] - 2024-06-07

### Changed

- Minor improvements and bug fixes

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.0.1...v1.0.2>

## [v1.0.1] - 2024-06-01

### Changed

- Minor improvements and bug fixes

**Full Changelog**: <https://github.com/jferrl/go-githubauth/compare/v1.0.0...v1.0.1>

## [v1.0.0] - 2024-06-01

### Added

- **Initial Release**: GitHub authentication utilities for Go applications
- **JWT Generation**: Generate JSON Web Tokens (JWT) for GitHub Apps using `NewApplicationTokenSource`
- **Installation Tokens**: Obtain GitHub App installation tokens using `NewInstallationTokenSource`
- **Security Compliance**:
  - JWT expiration time limited to 10 minutes maximum
  - Clock drift protection with 60-second buffer
- **Configuration Options**:
  - `WithApplicationTokenExpiration`: Customize JWT token expiration
  - `WithHTTPClient`: Set custom HTTP client
  - `WithInstallationTokenOptions`: Configure installation token options
- **OAuth2 Integration**: Full compatibility with `golang.org/x/oauth2.TokenSource` interface

### Documentation

- Comprehensive README with usage examples
- Integration examples with `go-github` library

**Full Changelog**: <https://github.com/jferrl/go-githubauth/commits/v1.0.0>

---

## About This Project

`go-githubauth` is a Go package that provides utilities for GitHub authentication, including generating and using GitHub App tokens, installation tokens, and personal access tokens. It implements the `TokenSource` interface from the `golang.org/x/oauth2` package for seamless integration with existing OAuth2 workflows.

### Key Features

- Generate GitHub Application JWT tokens
- Obtain GitHub App installation tokens  
- Personal Access Token support (classic and fine-grained)
- Advanced token caching with automatic refresh
- High-performance HTTP clients with connection pooling
- RS256-signed JWTs with proper clock drift protection
- Full OAuth2 compatibility
- GitHub Enterprise Server support
- Production-ready performance optimizations

For more information, see the [README](README.md).
