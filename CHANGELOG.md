# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.4.0] - 2025-01-XX

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
