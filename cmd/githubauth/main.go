// Command githubauth mints GitHub App credentials from the command line.
//
// It prints an installation token, or the App JWT used to obtain one, so that
// shell scripts and CI steps can authenticate as a GitHub App without
// reimplementing the JWT-then-exchange dance.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jferrl/go-githubauth"
	"golang.org/x/oauth2"
)

const rootHelp = `githubauth mints GitHub App credentials for your shell.

USAGE
  githubauth <command> [flags]

COMMANDS
  token      Print an installation access token
  jwt        Print the App JWT used to obtain one
  version    Print the version
  help       Print this help

EXAMPLES
  # An installation token, App identified by its client ID.
  githubauth token --client-id Iv1.abc --key app.pem --installation 12345

  # The same, with everything taken from the environment.
  export GITHUB_APP_CLIENT_ID=Iv1.abc
  export GITHUB_APP_PRIVATE_KEY="$(cat app.pem)"
  export GITHUB_APP_INSTALLATION_ID=12345
  githubauth token

  # Authenticate a request without storing the token anywhere.
  curl -H "Authorization: Bearer $(githubauth token)" \
    https://api.github.com/installation/repositories

  # Read the key from a secret manager, so it never touches disk.
  vault kv get -field=pem secret/github-app |
    githubauth token --key - --installation 12345

  # Run a command with the token in $GITHUB_TOKEN and $GH_TOKEN, printing it nowhere.
  # The token is revoked when the command exits.
  githubauth token --installation 12345 --exec -- gh pr list

EXIT CODES
  0  a credential was printed
  1  something else failed, retrying may help
  2  the invocation is wrong, fix the flags
  3  GitHub refused the key or the App's permissions
  4  rate limited, wait and repeat
  5  the App is not installed where it was asked to be

  Under --exec the exit code is the one the command exited with.

Run "githubauth <command> --help" for the flags of a command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Agent mode is read before the flags, so a flag parse error is still
	// reported as JSON when an agent is running.
	out := output{agent: agentModeEnv()}

	if len(args) == 0 {
		if out.agent {
			return report(usagef("missing command; run \"githubauth help\" for usage"), stdout, stderr, out)
		}
		_, _ = fmt.Fprint(stderr, rootHelp)
		return exitUsage
	}

	var err error
	switch args[0] {
	case "token":
		err = tokenCmd(args[1:], stdin, stdout, stderr, &out)
	case "jwt":
		err = jwtCmd(args[1:], stdin, stdout, stderr, &out)
	case "version", "--version", "-version", "-v":
		_, err = fmt.Fprintln(stdout, version())
	case "help", "--help", "-help", "-h":
		_, err = fmt.Fprint(stdout, rootHelp)
	default:
		err = unknownCommand(args[0])
	}

	if err != nil && !errors.Is(err, flag.ErrHelp) {
		return report(err, stdout, stderr, out)
	}
	return exitOK
}

// output is where the result and any failure go. Both commands fill it in
// while parsing flags, so run can report an error the way the command would
// have reported a success.
type output struct {
	json  bool
	agent bool
}

// unknownCommand keeps the typo hint on one line. Three stderr paragraphs read
// well to a person and badly to everything else.
func unknownCommand(name string) error {
	if near := nearest(name); near != "" {
		return usagef("unknown command %q; did you mean \"githubauth %s\"?", name, near)
	}
	return usagef("unknown command %q; run \"githubauth help\" for usage", name)
}

// usageError is CLI misuse — an unknown flag, or a missing or conflicting
// value. It exits 2, leaving 1 for a request that was well-formed but failed.
type usageError struct {
	err error
	// reported is set when the flag package has already written the message,
	// so run does not print it twice.
	reported bool
}

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error {
	return usageError{err: fmt.Errorf(format, args...)}
}

// appFlags are the flags shared by every command, since each one has to
// identify the App and find its signing key before it can do anything.
type appFlags struct {
	clientID string
	appID    int64
	key      string
	exec     bool
	out      *output
	fs       *flag.FlagSet
	// host is the instance the credential is for, as gh names it, or empty for
	// github.com.
	host string
}

func (a *appFlags) bind(fs *flag.FlagSet, out *output) {
	a.out = out
	a.fs = fs

	fs.StringVar(&a.clientID, "client-id", os.Getenv("GITHUB_APP_CLIENT_ID"), "App client ID, e.g. Iv1.1234567890abcdef ($GITHUB_APP_CLIENT_ID)")
	fs.Int64Var(&a.appID, "app-id", envInt64("GITHUB_APP_ID"), "legacy numeric App ID, for an App with no client ID ($GITHUB_APP_ID)")
	fs.StringVar(&a.key, "key", os.Getenv("GITHUB_APP_PRIVATE_KEY"), "PEM private key: file path, \"-\" for stdin, or the PEM, best from $GITHUB_APP_PRIVATE_KEY since argv is visible to other users")
	fs.BoolVar(&out.json, "json", false, "print {\"token\":...,\"expires_at\":...} instead of the bare token, with the permissions and repositories GitHub granted an installation token")
	fs.BoolVar(&a.exec, "exec", false, "run the command after -- with the credential in $GITHUB_TOKEN and $GH_TOKEN, printing it nowhere; $GH_HOST is set for an Enterprise or data residency host")
	fs.BoolVar(&out.agent, "agent", out.agent, "report failures as one JSON document on stdout (on when a coding agent is detected)")
}

// checkExec validates the trailing arguments against --exec. Arguments without
// --exec are usually a forgotten flag, and --exec with --json would format a
// token that --exec exists to keep unprinted.
func (a *appFlags) checkExec(argv []string) error {
	switch {
	case a.exec && len(argv) == 0:
		return usagef("--exec needs a command: githubauth token --exec -- gh pr list")
	case a.exec && a.out.json:
		return usagef("--exec prints no credential, so --json has nothing to format")
	case !a.exec && len(argv) > 0:
		return usagef("unexpected argument %q: pass --exec to run a command with the credential", argv[0])
	}
	return nil
}

// checkGHHost refuses an exported GH_HOST that names another instance than
// the one an installation token is for, before anything is minted: gh would
// send the token there. The JWT is not checked: it is signed locally, and only
// the caller knows which instance its App lives on. A caller whose proxy really serves it sets GH_HOST inside
// the command instead, where nothing else in the environment can choose it.
func (a *appFlags) checkGHHost() error {
	want := cmp.Or(a.host, "github.com")
	// Compared exactly: gh treats github.com:443 as another host than github.com.
	if h := os.Getenv("GH_HOST"); a.exec && h != "" && !strings.EqualFold(h, want) {
		return usagef("$GH_HOST is %s but the credential is for %s, so gh would send it to %s: unset GH_HOST, or set it inside the command, --exec -- env GH_HOST=%s gh ..., if %s serves this credential", h, want, h, h, h)
	}
	return nil
}

// emit delivers the credential: into a child process under --exec, otherwise
// to stdout.
func (a *appFlags) emit(tok *oauth2.Token, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if a.exec {
		return runWithToken(argv, tok, a.host, stdin, stdout, stderr)
	}
	if err := write(stdout, tok, a.out.json); err != nil {
		return err
	}
	if a.out.agent {
		_, _ = fmt.Fprint(stderr, agentTokenHint)
	}
	return nil
}

// source builds the App JWT token source the other commands start from.
func (a *appFlags) source(stdin io.Reader, opts ...githubauth.ApplicationTokenOpt) (oauth2.TokenSource, error) {
	switch {
	case a.clientID != "" && a.appID != 0:
		return nil, usagef("set --client-id or --app-id, not both")
	case a.clientID == "" && a.appID == 0:
		if err := badEnvNumber(a.fs, "app-id", "GITHUB_APP_ID"); err != nil {
			return nil, err
		}
		return nil, usagef("missing App identifier: set --client-id, or --app-id for a legacy App")
	case a.key == "":
		return nil, usagef("missing private key: set --key to a file path, %q for stdin, or the PEM itself", "-")
	}

	pem, err := readKey(a.key, stdin)
	if err != nil {
		return nil, err
	}

	if a.clientID != "" {
		return asCredential(githubauth.NewApplicationTokenSource(a.clientID, pem, opts...))
	}
	return asCredential(githubauth.NewApplicationTokenSource(a.appID, pem, opts...))
}

// asCredential labels a constructor failure. The key is parsed before any
// request, so a failure here is the credential, not GitHub's answer about it.
func asCredential(src oauth2.TokenSource, err error) (oauth2.TokenSource, error) {
	if err != nil {
		return nil, credentialError{err}
	}
	return src, nil
}

func tokenCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, out *output) error {
	fs := newFlagSet("token", "Print an installation access token.", `  # Find the installation from the account it is on.
  githubauth token --owner acme

  # Inside a clone, with no installation named: a token for that repository alone.
  githubauth token --exec -- gh pr merge 7

  # Scope the token to two repositories, with read access to their contents.
  githubauth token --installation 12345 --repos api,web --permissions contents:read

  # Keep the token out of the terminal: it only ever reaches the child, and is
  # revoked when the child exits.
  githubauth token --installation 12345 --exec -- gh pr list

  # Push as the App, once git uses gh for credentials (gh auth setup-git).
  githubauth token --installation 12345 --exec -- git push

  # GitHub Enterprise Server. Under --exec, $GH_HOST points gh at it.
  githubauth token --installation 12345 --enterprise-url https://github.example.com`)

	var app appFlags
	app.bind(fs, out)

	installation := fs.Int64("installation", envInt64("GITHUB_APP_INSTALLATION_ID"), "installation ID to mint the token for ($GITHUB_APP_INSTALLATION_ID)")
	repos := fs.String("repos", "", "comma-separated repository names to scope the token to; owner/repo also finds the installation, like --owner")
	owner := fs.String("owner", "", "user or organization the App is installed on, to look up the installation instead of passing --installation")
	permissions := fs.String("permissions", "", "comma-separated name:level pairs to scope the token to, e.g. contents:read,pull_requests:write")
	keep := fs.Bool("keep", false, "under --exec, leave the token valid when the command exits instead of revoking it")
	baseURL := fs.String("base-url", "", "API base URL, used verbatim (Enterprise Cloud with data residency)")
	enterpriseURL := fs.String("enterprise-url", "", "GitHub Enterprise Server URL, normalized the way GHES expects")

	if err := parseFlags(fs, args, out, stdout, stderr); err != nil {
		return err
	}
	if err := app.checkExec(fs.Args()); err != nil {
		return err
	}
	if *keep && !app.exec {
		return usagef("--keep applies only under --exec, which revokes the token when the command exits")
	}
	// An empty scope is no scope: GitHub would mint a token for every
	// repository, the opposite of what passing --repos asked for.
	names, repoOwner, err := splitOwner(splitRepos(*repos))
	if err != nil {
		return err
	}
	if isSet(fs, "repos") && len(names) == 0 {
		return usagef("--repos names no repository; omit it for a token covering the whole installation")
	}
	// An owner/repo name finds the installation the way --owner does.
	if repoOwner != "" {
		switch {
		case isSet(fs, "installation"):
			return usagef("--repos names the owner %s, which finds the installation: drop --installation, or the %s/ prefix", repoOwner, repoOwner)
		case *owner != "" && !strings.EqualFold(*owner, repoOwner):
			return usagef("--repos names repositories of %s, but --owner is %s", repoOwner, *owner)
		}
		*owner = repoOwner
	}
	if *baseURL != "" && *enterpriseURL != "" {
		return usagef("set --base-url or --enterprise-url, not both")
	}
	if err := checkURL("--base-url", *baseURL); err != nil {
		return err
	}
	if err := checkURL("--enterprise-url", *enterpriseURL); err != nil {
		return err
	}
	app.host = ghHost(*baseURL + *enterpriseURL) // at most one is set
	if err := app.checkGHHost(); err != nil {
		return err
	}
	// Nothing names the installation, so the clone the command runs in does,
	// the way actions/create-github-app-token defaults to the current
	// repository. The token covers that repository alone.
	// An --owner given empty, as from an unset script variable, is not
	// nothing: falling back would mint for a repository the script never named.
	if !isSet(fs, "owner") && !isSet(fs, "installation") && !isSet(fs, "repos") && os.Getenv("GITHUB_APP_INSTALLATION_ID") == "" {
		if o, r, ok := originRepo(app.host); ok {
			*owner, names = o, []string{r}
		}
	}
	switch {
	case *owner != "" && isSet(fs, "installation"):
		return usagef("set --installation or --owner, not both")
	case strings.Contains(*owner, "/"):
		return usagef("--owner %q is a repository: pass its account as --owner and the repository as --repos", *owner)
	case *owner == "." || *owner == "..":
		return usagef("--owner %q is not an account: pass a user or organization login", *owner)
	case *owner == "" && *installation <= 0:
		if err := badEnvNumber(fs, "installation", "GITHUB_APP_INSTALLATION_ID"); err != nil {
			return err
		}
		return usagef("missing installation ID: set --installation, --owner to look it up, or run inside a clone of a repository the App is installed on")
	}
	perms, err := parsePermissions(*permissions)
	if err != nil {
		return err
	}
	if isSet(fs, "permissions") && perms == nil {
		return usagef("--permissions names no permission; omit it for a token with every permission the App has")
	}

	appSrc, err := app.source(stdin)
	if err != nil {
		return err
	}

	var urlOpts []githubauth.InstallationTokenSourceOpt
	switch {
	case *baseURL != "":
		urlOpts = append(urlOpts, githubauth.WithBaseURL(*baseURL))
	case *enterpriseURL != "":
		urlOpts = append(urlOpts, githubauth.WithEnterpriseURL(*enterpriseURL))
	}

	id := *installation
	if *owner != "" {
		if id, err = githubauth.FindInstallationID(context.Background(), appSrc, *owner, urlOpts...); err != nil {
			return err
		}
	}

	opts := slices.Clone(urlOpts)
	if len(names) > 0 || perms != nil {
		opts = append(opts, githubauth.WithInstallationTokenOptions(&githubauth.InstallationTokenOptions{
			Repositories: names,
			Permissions:  perms,
		}))
	}

	tok, err := githubauth.NewInstallationTokenSource(id, appSrc, opts...).Token()
	if err != nil {
		return err
	}
	if app.exec && !*keep {
		defer holdSignals()()
	}
	err = app.emit(tok, fs.Args(), stdin, stdout, stderr)
	// Even a command that failed to start leaves a minted token behind.
	if app.exec && !*keep {
		err = revoke(err, tok, urlOpts, stderr)
	}
	return err
}

func jwtCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, out *output) error {
	fs := newFlagSet("jwt", "Print the App JWT, for the few endpoints that take one.", `  # A JWT valid for five minutes instead of ten.
  githubauth jwt --client-id Iv1.abc --key app.pem --expiry 5m

  # List the App's installations without the JWT reaching the terminal.
  # gh needs the header spelled out: it sends "token", and a JWT is only taken as "Bearer".
  githubauth jwt --exec -- sh -c 'gh api -H "Authorization: Bearer $GITHUB_TOKEN" /app/installations'`)

	var app appFlags
	app.bind(fs, out)

	expiry := fs.Duration("expiry", 0, "JWT lifetime, over 90s and up to 10m (default 10m)")

	if err := parseFlags(fs, args, out, stdout, stderr); err != nil {
		return err
	}
	if err := app.checkExec(fs.Args()); err != nil {
		return err
	}
	// The library falls back to 10m for anything out of range, which would
	// hand a caller who asked for a short-lived JWT a long-lived one.
	if isSet(fs, "expiry") && (*expiry <= 90*time.Second || *expiry > githubauth.DefaultApplicationTokenExpiration) {
		return usagef("--expiry %s is out of range: it must be over 90s and at most 10m", *expiry)
	}

	var opts []githubauth.ApplicationTokenOpt
	if *expiry > 0 {
		opts = append(opts, githubauth.WithApplicationTokenExpiration(*expiry))
	}

	src, err := app.source(stdin, opts...)
	if err != nil {
		return err
	}

	tok, err := src.Token()
	if err != nil {
		return err
	}
	return app.emit(tok, fs.Args(), stdin, stdout, stderr)
}

// newFlagSet gives every command the same help layout: what it does, how it is
// called, its flags, then examples, which is the part people actually read.
func newFlagSet(name, summary, examples string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		w := fs.Output()
		_, _ = fmt.Fprintf(w, "%s\n\nUSAGE\n  githubauth %s [flags]\n\nFLAGS\n", summary, name)
		printFlags(w, fs)
		_, _ = fmt.Fprintf(w, "\nEXAMPLES\n%s\n", examples)
	}
	return fs
}

// parseFlags holds back the flag package's own messages: under --json or agent
// mode the JSON document must be the only rendering of a failure. A help
// request is not a failure, so it goes to stdout like "githubauth help" and
// returns flag.ErrHelp for run to exit 0 on.
func parseFlags(fs *flag.FlagSet, args []string, out *output, stdout, stderr io.Writer) error {
	var diag bytes.Buffer
	fs.SetOutput(&diag)

	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		if _, werr := diag.WriteTo(stdout); werr != nil {
			return werr
		}
		return err
	case err != nil:
		scanOutputFlags(fs, args, out)
		if !out.json && !out.agent {
			_, _ = diag.WriteTo(stderr)
		}
		return usageError{err: err, reported: true}
	}
	return nil
}

// scanOutputFlags sets --json and --agent from the arguments the flag package
// never reached, because one before them failed to parse, so the failure is
// still rendered the way the caller asked. It stops where flag parsing would:
// at "--" or the first argument that is not a flag.
func scanOutputFlags(fs *flag.FlagSet, args []string, out *output) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			return
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
			// Its value is the next argument, whatever it looks like.
			if !hasValue {
				i++
			}
			continue
		}
		on := true
		if hasValue {
			// An explicit --json= is as invalid here as to the flag package.
			b, err := strconv.ParseBool(value)
			if err != nil {
				continue
			}
			on = b
		}
		switch name {
		case "json":
			out.json = on
		case "agent":
			out.agent = on
		}
	}
}

// badEnvNumber explains a missing numeric flag whose environment fallback was
// set but malformed, which would otherwise read as never set at all.
func badEnvNumber(fs *flag.FlagSet, name, key string) error {
	if isSet(fs, name) {
		return nil
	}
	if v := os.Getenv(key); v != "" {
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return usagef("$%s=%q is not a number", key, v)
		}
	}
	return nil
}

// isSet reports whether name was given on the command line.
func isSet(fs *flag.FlagSet, name string) bool {
	var set bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// checkURL rejects a base URL the library could only fail on after the key is
// read, which would exit 1 and suggest retrying an invocation that cannot work.
func checkURL(name, v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return usagef("%s %q must be an absolute http(s) URL", name, v)
	}
	return nil
}

// printFlags lists flags as "--name type", the spelling used everywhere else
// here, which flag.PrintDefaults renders with a single dash.
//
// Defaults are deliberately omitted: every flag defaults to an environment
// variable, so printing them would spill $GITHUB_APP_PRIVATE_KEY into the help
// output of anyone who has it set.
func printFlags(w io.Writer, fs *flag.FlagSet) {
	type row struct{ name, usage string }

	var rows []row
	var width int

	fs.VisitAll(func(f *flag.Flag) {
		placeholder, usage := flag.UnquoteUsage(f)

		name := "--" + f.Name
		if placeholder != "" {
			name += " " + placeholder
		}
		width = max(width, len(name))
		rows = append(rows, row{name, usage})
	})

	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %-*s   %s\n", width, r.name, r.usage)
	}
}

// maxKeyPathLen is the longest --key value repeated in an error. A private
// key, PEM or base64, is well over it.
const maxKeyPathLen = 256

// readKey resolves --key, which is a file path, "-" for stdin, or the PEM
// itself so that $GITHUB_APP_PRIVATE_KEY can be passed straight through.
func readKey(v string, stdin io.Reader) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	if v == "-" {
		return io.ReadAll(stdin)
	}
	pem, err := os.ReadFile(v)
	if err != nil {
		// The flag was well-formed but points nowhere, which is the caller's
		// invocation to fix rather than anything GitHub was asked about. A key
		// that is not PEM, such as base64 from a CI secret, lands here too, so
		// the value is named only when it is short enough to be a path.
		var pe *os.PathError
		if errors.As(err, &pe) && len(v) > maxKeyPathLen {
			return nil, usagef("reading private key: --key is neither PEM, %q, nor a file it can open (%w); a base64-encoded key needs decoding first", "-", pe.Err)
		}
		return nil, usagef("reading private key: %w", err)
	}
	return pem, nil
}

func write(w io.Writer, tok *oauth2.Token, asJSON bool) error {
	if !asJSON {
		_, err := fmt.Fprintln(w, tok.AccessToken)
		return err
	}
	// What GitHub granted, so a caller can check the scope it got. A JWT
	// carries neither.
	perms, _ := tok.Extra(githubauth.ExtraPermissions).(map[string]string)
	repos, _ := tok.Extra(githubauth.ExtraRepositories).([]string)
	return json.NewEncoder(w).Encode(struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions,omitempty"`
		Repositories []string          `json:"repositories,omitempty"`
	}{tok.AccessToken, tok.Expiry, perms, repos})
}

func splitRepos(v string) []string {
	var out []string
	for name := range strings.SplitSeq(v, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// splitOwner strips the owner from names written owner/repo, the form
// actions/create-github-app-token takes, and returns the owner they share.
// GitHub scopes a token by bare repository names.
func splitOwner(names []string) ([]string, string, error) {
	var owner string
	out := make([]string, len(names))
	for i, name := range names {
		o, repo, ok := strings.Cut(name, "/")
		if !ok {
			out[i] = name
			continue
		}
		if o == "" || repo == "" || strings.Contains(repo, "/") {
			return nil, "", usagef("--repos %q is neither a repository name nor owner/repo", name)
		}
		if owner != "" && !strings.EqualFold(owner, o) {
			return nil, "", usagef("--repos names repositories of %s and of %s; a token covers one installation", owner, o)
		}
		owner, out[i] = o, repo
	}
	return out, owner, nil
}

// originRepo names the repository the working directory is a clone of, from
// its origin remote, when that remote is on host, as gh names it: empty for
// github.com. A clone of another host says nothing about this one.
func originRepo(host string) (owner, repo string, ok bool) {
	git := exec.Command("git", "remote", "get-url", "origin")
	git.Env = childEnviron()
	out, err := git.Output()
	if err != nil {
		return "", "", false
	}
	remoteHost, owner, repo, ok := parseRemote(strings.TrimSpace(string(out)))
	want := cmp.Or(host, "github.com")
	// An http(s) remote is served by the instance itself, so its port has to
	// agree too, git push would hand the token to it; gh's port is 443 unless
	// the API names another. An ssh remote's port says nothing about the
	// API's, so only the host is compared.
	wantHost, wantPort, err := net.SplitHostPort(want)
	if err != nil {
		wantHost, wantPort = strings.Trim(want, "[]"), "443"
	}
	if h, p, err := net.SplitHostPort(remoteHost); err == nil {
		ok = ok && strings.EqualFold(h, wantHost) && p == wantPort
	} else {
		ok = ok && strings.EqualFold(remoteHost, wantHost)
	}
	if !ok {
		return "", "", false
	}
	return owner, repo, true
}

// parseRemote splits a GitHub remote, in its https, ssh:// or scp-like
// git@host:owner/repo form, into its host, owner and repository.
func parseRemote(remote string) (host, owner, repo string, ok bool) {
	var path string
	if u, err := url.Parse(remote); err == nil && u.Scheme != "" && u.Host != "" {
		host, path = u.Hostname(), u.Path
		// An http(s) remote is served by the instance itself, so it carries its
		// port, default included; see originRepo.
		if u.Scheme == "http" || u.Scheme == "https" {
			host = net.JoinHostPort(host, cmp.Or(u.Port(), map[string]string{"http": "80", "https": "443"}[u.Scheme]))
		}
	} else if userHost, p, found := strings.Cut(remote, ":"); found && !strings.Contains(userHost, "/") {
		_, host, _ = strings.Cut(userHost, "@")
		host = cmp.Or(host, userHost)
		path = p
	} else {
		return "", "", "", false
	}

	owner, repo, found := strings.Cut(strings.TrimSuffix(strings.Trim(path, "/"), ".git"), "/")
	if !found || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", "", false
	}
	// GitHub's SSH over port 443.
	if strings.EqualFold(host, "ssh.github.com") {
		host = "github.com"
	}
	return host, owner, repo, true
}

// parsePermissions reads --permissions into GitHub's permission object, or nil
// when it names none. Every name goes through Other, so a permission GitHub
// adds works before the library has a field for it. GitHub answers a name it
// does not know with a 422, even beside valid ones, rather than ignoring it and
// minting a token with every permission.
func parsePermissions(v string) (*githubauth.InstallationPermissions, error) {
	pairs := splitRepos(v)
	if len(pairs) == 0 {
		return nil, nil
	}
	levels := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		name, level, ok := strings.Cut(pair, ":")
		name, level = strings.TrimSpace(name), strings.TrimSpace(level)
		if !ok || name == "" || level == "" {
			return nil, usagef("--permissions %q is not name:level, e.g. contents:read", pair)
		}
		levels[name] = level
	}
	return &githubauth.InstallationPermissions{Other: levels}, nil
}

// envInt64 ignores a malformed value here, before the flags are parsed;
// badEnvNumber reports it where the value would have been used.
func envInt64(key string) int64 {
	n, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		// ParseInt returns the nearest int64 on overflow; that is no ID either.
		return 0
	}
	return n
}

// buildVersion is set by the release build with -ldflags. It stays empty for
// a binary built any other way, which then falls back to the build info.
var buildVersion string

// version reports where the binary came from. A release build carries the tag
// in buildVersion; go install stamps the module version into the build info;
// a local build has neither and reports the revision instead.
func version() string {
	if buildVersion != "" {
		return buildVersion
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	// A build from a checkout: report the commit Go stamped, if any.
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return "(devel)"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return "(devel) " + revision
}

// nearest suggests a command for a typo, matching on a shared prefix or at most
// two edits, which covers the realistic slips, transpositions included.
func nearest(in string) string {
	for _, cmd := range []string{"token", "jwt", "version", "help"} {
		if strings.HasPrefix(cmd, in) || strings.HasPrefix(in, cmd) || editDistance(in, cmd) <= 2 {
			return cmd
		}
	}
	return ""
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr := make([]int, len(b)+1)
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev = curr
	}
	return prev[len(b)]
}
