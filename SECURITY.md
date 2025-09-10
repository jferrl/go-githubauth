# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions of `go-githubauth`:

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

Please ensure you are using a supported version to receive security updates.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in `go-githubauth`, please report it responsibly.

### How to Report

1. **Email**: Send details to the maintainer via GitHub's private vulnerability reporting feature or create a [security advisory](https://github.com/jferrl/go-githubauth/security/advisories/new)
2. **Do NOT** create a public GitHub issue for security vulnerabilities
3. **Do NOT** discuss the vulnerability publicly until it has been addressed

### What to Include

When reporting a vulnerability, please include:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Affected versions
- Any potential impact assessment
- Suggested fixes (if available)

### Response Timeline

- **Initial Response**: Within 48 hours of receiving the report
- **Initial Assessment**: Within 5 business days
- **Fix Timeline**: Varies based on complexity, but we aim for resolution within 30 days
- **Disclosure**: Coordinated disclosure after fix is available

## Security Considerations

### For Users of This Library

When using `go-githubauth`, please consider the following security best practices:

#### Token Security

- **Never commit tokens to version control** - Use environment variables or secure credential management
- **Rotate tokens regularly** - Especially personal access tokens
- **Use minimal required permissions** - Follow the principle of least privilege
- **Monitor token usage** - Regularly audit GitHub App installations and token access

#### Application Security

```go
// ✅ Good - Using environment variables
privateKey := []byte(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
clientID := os.Getenv("GITHUB_APP_CLIENT_ID")

// ❌ Bad - Hardcoded secrets
privateKey := []byte("-----BEGIN PRIVATE KEY-----\nMIIE...")
```

#### Transport Security

- Always use HTTPS endpoints (default in this library)
- Validate SSL certificates (default behavior)
- Use appropriate timeout values to prevent resource exhaustion

#### Error Handling

- Avoid logging sensitive token information
- Handle authentication failures gracefully
- Implement proper retry logic with exponential backoff

### Library-Specific Considerations

- **Token Caching**: This library caches tokens for performance. Ensure your application handles cached token invalidation appropriately
- **Private Keys**: RSA private keys are stored in memory during operation. Ensure your application follows secure memory management practices
- **HTTP Clients**: The library uses pooled HTTP clients. In containerized environments, ensure proper resource cleanup

## Security Updates

Security updates will be:

- Released as patch versions (e.g., 1.4.1)
- Documented in the [CHANGELOG.md](./CHANGELOG.md)
- Announced in GitHub releases with security labels
- Published to GitHub Security Advisories when applicable

## Dependencies

We regularly audit our dependencies for known vulnerabilities:

- Direct dependencies are kept minimal and up-to-date
- We use `dependabot` and automated security scanning
- Critical security updates to dependencies trigger immediate releases

## Responsible Disclosure

We are committed to working with security researchers and the community to verify and address security vulnerabilities. Researchers who report valid security issues will be:

- Acknowledged in security advisories (unless they prefer to remain anonymous)
- Given credit in release notes
- Provided with updates on the fix timeline

## Security Resources

- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Go Security Checklist](https://github.com/Checkmarx/Go-SCP)

## Contact

For security-related questions that don't involve reporting vulnerabilities, you can:

- Create a regular [GitHub Issue](https://github.com/jferrl/go-githubauth/issues) (for non-sensitive matters)
