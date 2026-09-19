# go-githubauth — notes for coding agents

GitHub authentication for Go: GitHub App JWTs, installation tokens, and personal
access tokens, as standard `oauth2.TokenSource` implementations. Ships a library
and a `githubauth` CLI. Read this before reaching for either.

## Getting a credential without leaking it

The CLI prints a live credential to stdout. An installation token is valid for an
hour, and anything that captured your output still has it for that hour: a
transcript, a CI log, a scrollback buffer.

Prefer `--exec`, which puts the token in the child's `$GITHUB_TOKEN` and prints it
nowhere:

```bash
githubauth token --installation 12345 --exec -- gh pr list
```

Print it only when something downstream genuinely needs the string, and prefer a
short-lived scope when you do:

```bash
githubauth token --installation 12345 --repos api,web
```

## The CLI

```
githubauth token [flags]    # an installation access token
githubauth jwt   [flags]    # the App JWT, for the endpoints that take one
githubauth version
githubauth help
```

Flags shared by both commands: `--client-id` (or `--app-id` for a legacy App),
`--key`, `--json`, `--exec`, `--agent`. `token` adds `--installation`, `--repos`,
`--base-url`, `--enterprise-url`. `jwt` adds `--expiry`.

Every flag falls back to an environment variable — `GITHUB_APP_CLIENT_ID`,
`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_INSTALLATION_ID` — so a
configured environment reduces the call to `githubauth token`.

`--key` takes a file path, `-` for stdin, or the PEM itself, which is what lets
the key come from a secret manager without touching disk:

```bash
vault kv get -field=pem secret/github-app | githubauth token --key - --installation 12345
```

### Exit codes

Branch on these rather than on message text. Each one implies a different move:

| Code | Meaning | What to do |
|---|---|---|
| 0 | a credential was printed | continue |
| 1 | something else failed | retrying may help |
| 2 | the invocation is wrong | fix the flags, do not retry unchanged |
| 3 | GitHub refused the key or the App's permissions | fix the credential, do not retry unchanged |
| 4 | rate limited | wait `retry_after_seconds`, then repeat |
| 5 | the App is not installed where it was asked to be | fix `--installation` |

Under `--exec` the exit code is the one the command exited with.

### Machine-readable failures

Under `--json`, or when a coding agent is detected, a failure is one JSON
document on **stdout** and stderr stays empty:

```json
{"type":"githubauth.error","schema_version":"1","error":{"summary":"GitHub API returned status 404: {\"message\":\"Not Found\"}","exit_code":5,"status_code":404,"suggestions":["Check --installation: the App may not be installed on that account."]}}
```

Check `type` and `schema_version` before reading the rest.

Detection reads `CLAUDECODE`, `CLAUDE_CODE`, `CURSOR_AGENT`, `GITHUB_COPILOT`,
`AMAZON_Q`, `OPENCODE`, and `PI_CODING_AGENT`. `GITHUBAUTH_AGENT_MODE` or
`--agent`/`--agent=false` decides on its own. Agent mode never changes the
success output: a bare token stays a bare token, so `$(githubauth token)` means
the same thing everywhere.

**Pin it off in tests.** A test suite that shells out to `githubauth` while
running inside an agent will otherwise find errors on stdout instead of stderr.
Set `GITHUBAUTH_AGENT_MODE=0`.

## The library

```go
appSrc, err := githubauth.NewApplicationTokenSource(clientID, privateKeyPEM)
installSrc := githubauth.NewInstallationTokenSource(installationID, appSrc)
httpClient := oauth2.NewClient(context.Background(), installSrc)
```

`NewApplicationTokenSource` takes a string Client ID or an int64 App ID. The type
is inferred. Both sources cache and refresh 30s before expiry.

Errors worth branching on: `*githubauth.RateLimitError` (carries `RetryAfter`,
unwraps to `ErrRateLimited`) and `*githubauth.APIError` (carries `StatusCode`).
Match with `errors.As`, never on the message.

Full API surface: [`llms.txt`](llms.txt). Runnable examples: pkg.go.dev.

## Working in this repo

| Path | What |
|---|---|
| `auth.go` | token sources and their options |
| `github.go` | the installation token exchange, retries, error types |
| `http.go` | the shared HTTP client |
| `webhook/` | `X-Hub-Signature-256` verification and middleware |
| `cmd/githubauth/` | the CLI: `main.go` commands, `errors.go` exit codes, `exec.go`, `agent.go` |

- `go test ./...` and `golangci-lint run ./...` both have to pass. Tests are
  table-driven. Follow the shape already in the file you are editing.
- **Scope**: this library authenticates and stops there. API coverage belongs to
  [go-github](https://github.com/google/go-github), which it pairs with — do not
  add installation, repository, or organization helpers here.
- Exported symbols keep a doc comment opening with the symbol name. Comments say
  why, in a sentence or two.
- The exit codes and the `githubauth.error` envelope are a public contract.
  Adding a code or a field is fine. Changing what an existing one means is not,
  without bumping `schema_version`.
