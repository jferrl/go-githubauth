# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

`go-githubauth` is a Go package that provides utilities for GitHub authentication, including generating and using GitHub App tokens and installation tokens. It implements the `TokenSource` interface from the `golang.org/x/oauth2` package for seamless integration with existing OAuth2 workflows.

### Key Features

- Generate GitHub Application JWT tokens
- Obtain GitHub App installation tokens
- RS256-signed JWTs with proper clock drift protection
- Full OAuth2 compatibility
- GitHub Enterprise Server support

For more information, see the [README](README.md).
