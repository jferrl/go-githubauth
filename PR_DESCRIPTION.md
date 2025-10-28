# Remove go-github Dependency and Implement Internal GitHub API Client

## ⚠️ Breaking Change - v1.5.0

## Summary

This PR eliminates the `github.com/google/go-github/v74` dependency by implementing a lightweight internal GitHub API client. The change reduces external dependencies and simplifies the API surface.

**Note**: While most users will experience no breaking changes, this is marked as a breaking change due to API modifications for enterprise configuration and type changes for users directly referencing GitHub types.

## Motivation

- **Reduce dependency footprint**: The go-github library is a comprehensive SDK with many features we don't use
- **Better control**: Direct implementation of the specific API endpoints we need
- **Lighter weight**: Smaller binary size and fewer transitive dependencies
- **Simplified maintenance**: Fewer external dependencies to track and update

## Changes

### New File: `github.go`
- Added internal GitHub API types:
  - `InstallationTokenOptions` - configuration for installation token requests
  - `InstallationPermissions` - comprehensive permission structure
  - `InstallationToken` - GitHub API response type
  - `Repository` - minimal repository representation
- Implemented `githubClient` with:
  - Direct HTTP API calls to GitHub's REST API
  - Proper JSON serialization/deserialization
  - Enterprise GitHub support via `withEnterpriseURL()`
  - Error handling with detailed messages
- Added public `Ptr[T]()` generic helper for creating pointers (useful for InstallationTokenOptions)

### Modified: `auth.go`
- Removed `github.com/google/go-github/v74/github` import
- Updated all type references to use internal types
- Simplified `WithEnterpriseURLs()` to `WithEnterpriseURL()` (single base URL parameter)
- Updated package documentation to reflect new architecture
- Fixed documentation link for installation token generation

### Modified: `auth_test.go`
- Removed `go-github` import from tests
- Updated all test fixtures to use internal types
- Replaced `github.Ptr()` with local `ptr()` helper
- All tests passing without modification to test logic

### Modified: `go.mod` and `go.sum`
- Removed `github.com/google/go-github/v74 v74.0.0`
- Removed indirect dependency `github.com/google/go-querystring v1.1.0`

## Breaking Changes

### API Changes

1. **Enterprise Configuration** (Breaking)
   - `WithEnterpriseURLs(baseURL, uploadURL)` → `WithEnterpriseURL(baseURL)`
   - Simplified to single base URL parameter (upload URL was redundant)

2. **Type Changes** (Breaking for direct type users)
   - `github.InstallationTokenOptions` → `githubauth.InstallationTokenOptions`
   - `github.InstallationPermissions` → `githubauth.InstallationPermissions`
   - `github.InstallationToken` → `githubauth.InstallationToken`
   - `github.Repository` → `githubauth.Repository`

### Unchanged APIs

✅ The following public APIs remain unchanged:
- `NewApplicationTokenSource()` - no changes
- `NewInstallationTokenSource()` - no changes
- `NewPersonalAccessTokenSource()` - no changes
- `WithInstallationTokenOptions()` - signature unchanged (internal type change only)
- `WithHTTPClient()` - no changes
- `WithContext()` - no changes
- `WithApplicationTokenExpiration()` - no changes

## Testing

All existing tests pass without modification:
```
✓ TestNewApplicationTokenSource
✓ TestApplicationTokenSource_Token
✓ Test_installationTokenSource_Token
✓ TestNewPersonalAccessTokenSource
✓ TestPersonalAccessTokenSource_Token
```

## Benefits

1. **Reduced Dependencies**: 2 fewer dependencies in go.mod
2. **Smaller Binary**: No unused go-github code included
3. **Better Performance**: Direct API calls without abstraction overhead
4. **Full Control**: Complete ownership of GitHub API integration
5. **Easier Debugging**: Simpler code path for troubleshooting
6. **Enterprise Support**: Streamlined configuration with single base URL

## Migration Notes for Users

### For Most Users
**No action required** - this change is transparent to existing code.

### For Enterprise GitHub Users
If you were using `WithEnterpriseURLs(baseURL, uploadURL)`:
```go
// Before
installationTokenSource := githubauth.NewInstallationTokenSource(
    installationID, 
    appTokenSource,
    githubauth.WithEnterpriseURLs("https://github.example.com", "https://github.example.com"),
)

// After (uploadURL parameter removed)
installationTokenSource := githubauth.NewInstallationTokenSource(
    installationID, 
    appTokenSource,
    githubauth.WithEnterpriseURL("https://github.example.com"),
)
```

### For Type Users
If you were directly referencing `github.InstallationTokenOptions`:
```go
// Before
import "github.com/google/go-github/v74/github"
opts := &github.InstallationTokenOptions{...}

// After
import "github.com/jferrl/go-githubauth"
opts := &githubauth.InstallationTokenOptions{...}
```

## Verification

- ✅ All unit tests passing
- ✅ No linter errors
- ✅ go mod tidy completed successfully
- ✅ API surface unchanged (except simplified enterprise configuration)
- ✅ Documentation updated

## Related Issues

Closes #[issue-number] (if applicable)

