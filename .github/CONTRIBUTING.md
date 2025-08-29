# Contributing to go-githubauth

First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to go-githubauth. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming and inclusive environment. Please be respectful and professional in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the [existing issues](https://github.com/jferrl/go-githubauth/issues) as you might find that the problem has already been reported.

When you are creating a bug report, please include as many details as possible:

- Use the bug report template
- Include the version of go-githubauth you're using
- Include your Go version
- Provide a clear description of the problem
- Include code examples if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use the feature request template
- Provide a clear and detailed explanation of the feature
- Include examples of how the feature would be used
- Consider whether this feature would be useful to most users

### Pull Requests

1. Fork the repository and create your branch from `main`
2. Make your changes
3. Add tests if applicable
4. Ensure the test suite passes
5. Update documentation if needed
6. Create a pull request using the provided template

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/go-githubauth.git
   cd go-githubauth
   ```
3. Install dependencies:
   ```bash
   go mod download
   ```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -race -coverprofile=coverage.out -covermode=atomic ./...

# View coverage report
go tool cover -html=coverage.out
```

### Code Style

- Follow standard Go formatting (`gofmt`)
- Use `go vet` to check for common mistakes
- Follow Go naming conventions
- Write clear, self-documenting code
- Add comments for complex logic
- Keep functions focused and small

### Documentation

- Update the README.md if you change functionality
- Add godoc comments to exported functions and types
- Update CHANGELOG.md following the existing format
- Keep documentation concise but comprehensive

## Git Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them:
   ```bash
   git add .
   git commit -m "Add your descriptive commit message"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Create a Pull Request on GitHub

### Commit Messages 

Use Conventional Commits to format your commit messages. This will help us generate a changelog and release notes. See [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for more details.

Examples:

```
feat: Add support for GitHub Enterprise Server
fix: JWT token expiration validation
chore: update dependencies to latest versions
docs: improve installation instructions
```

## Testing

- Write tests for new functionality
- Ensure existing tests pass
- Aim for good test coverage
- Test both success and error cases
- Use table-driven tests for multiple scenarios

## Documentation Guidelines

- Write clear, concise documentation
- Include code examples for new features
- Update existing examples if APIs change
- Follow godoc conventions for comments

## Release Process

This section is primarily for maintainers:

1. Update CHANGELOG.md with new version
2. Update version references in documentation
3. Create a new release on GitHub
4. Verify the release works correctly

## Getting Help

- Check the [documentation](https://pkg.go.dev/github.com/jferrl/go-githubauth)
- Look at [existing issues](https://github.com/jferrl/go-githubauth/issues)
- Create a new issue if your question isn't answered

## Recognition

Contributors will be acknowledged in the CHANGELOG.md file and may be invited to become maintainers based on their contributions.

Thank you for contributing to go-githubauth! 🚀
