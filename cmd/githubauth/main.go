// Command githubauth mints GitHub App credentials from the command line.
//
// It prints an installation token, or the App JWT used to obtain one, so that
// shell scripts and CI steps can authenticate as a GitHub App without
// reimplementing the JWT-then-exchange dance.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
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

  # Run a command with the token in $GITHUB_TOKEN, printing it nowhere.
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
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, rootHelp)
		return exitUsage
	}

	// Agent mode is read before the flags, so a flag parse error is still
	// reported as JSON when an agent is running.
	out := output{agent: agentModeEnv()}

	var err error
	switch args[0] {
	case "token":
		err = tokenCmd(args[1:], stdin, stdout, stderr, &out)
	case "jwt":
		err = jwtCmd(args[1:], stdin, stdout, stderr, &out)
	case "version", "--version", "-version", "-v":
		_, _ = fmt.Fprintln(stdout, version())
		return exitOK
	case "help", "--help", "-help", "-h":
		_, _ = fmt.Fprint(stdout, rootHelp)
		return exitOK
	default:
		err = unknownCommand(args[0])
	}

	if err != nil {
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
}

func (a *appFlags) bind(fs *flag.FlagSet, out *output) {
	a.out = out

	fs.StringVar(&a.clientID, "client-id", os.Getenv("GITHUB_APP_CLIENT_ID"), "App client ID, e.g. Iv1.1234567890abcdef ($GITHUB_APP_CLIENT_ID)")
	fs.Int64Var(&a.appID, "app-id", envInt64("GITHUB_APP_ID"), "legacy numeric App ID, for an App with no client ID ($GITHUB_APP_ID)")
	fs.StringVar(&a.key, "key", os.Getenv("GITHUB_APP_PRIVATE_KEY"), "PEM private key: file path, \"-\" for stdin, or the PEM ($GITHUB_APP_PRIVATE_KEY)")
	fs.BoolVar(&out.json, "json", false, "print {\"token\":...,\"expires_at\":...} instead of the bare token")
	fs.BoolVar(&a.exec, "exec", false, "run the command after -- with the credential in $GITHUB_TOKEN, printing it nowhere")
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

// emit delivers the credential: into a child process under --exec, otherwise
// to stdout.
func (a *appFlags) emit(tok *oauth2.Token, argv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if a.exec {
		return runWithToken(argv, tok, stdin, stdout, stderr)
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
	fs := newFlagSet("token", "Print an installation access token.", stderr, `  # Scope the token to two repositories.
  githubauth token --installation 12345 --repos api,web

  # Keep the token out of the terminal: it only ever reaches the child.
  githubauth token --installation 12345 --exec -- gh pr list

  # GitHub Enterprise Server.
  githubauth token --installation 12345 --enterprise-url https://github.example.com`)

	var app appFlags
	app.bind(fs, out)

	installation := fs.Int64("installation", envInt64("GITHUB_APP_INSTALLATION_ID"), "installation ID to mint the token for ($GITHUB_APP_INSTALLATION_ID)")
	repos := fs.String("repos", "", "comma-separated repository names to scope the token to")
	baseURL := fs.String("base-url", "", "API base URL, used verbatim (Enterprise Cloud with data residency)")
	enterpriseURL := fs.String("enterprise-url", "", "GitHub Enterprise Server URL, normalized the way GHES expects")

	if err := fs.Parse(args); err != nil {
		return usageError{err: err, reported: true}
	}
	if err := app.checkExec(fs.Args()); err != nil {
		return err
	}
	if *installation <= 0 {
		return usagef("missing installation ID: set --installation")
	}
	if *baseURL != "" && *enterpriseURL != "" {
		return usagef("set --base-url or --enterprise-url, not both")
	}

	appSrc, err := app.source(stdin)
	if err != nil {
		return err
	}

	var opts []githubauth.InstallationTokenSourceOpt
	switch {
	case *baseURL != "":
		opts = append(opts, githubauth.WithBaseURL(*baseURL))
	case *enterpriseURL != "":
		opts = append(opts, githubauth.WithEnterpriseURL(*enterpriseURL))
	}
	if names := splitRepos(*repos); len(names) > 0 {
		opts = append(opts, githubauth.WithInstallationTokenOptions(&githubauth.InstallationTokenOptions{
			Repositories: names,
		}))
	}

	tok, err := githubauth.NewInstallationTokenSource(*installation, appSrc, opts...).Token()
	if err != nil {
		return err
	}
	return app.emit(tok, fs.Args(), stdin, stdout, stderr)
}

func jwtCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, out *output) error {
	fs := newFlagSet("jwt", "Print the App JWT, for the few endpoints that take one.", stderr, `  # A JWT valid for five minutes instead of ten.
  githubauth jwt --client-id Iv1.abc --key app.pem --expiry 5m

  # List the App's installations without the JWT reaching the terminal.
  githubauth jwt --exec -- sh -c 'curl -sH "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/app/installations'`)

	var app appFlags
	app.bind(fs, out)

	expiry := fs.Duration("expiry", 0, "JWT lifetime, over 90s and up to 10m (default 10m)")

	if err := fs.Parse(args); err != nil {
		return usageError{err: err, reported: true}
	}
	if err := app.checkExec(fs.Args()); err != nil {
		return err
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
func newFlagSet(name, summary string, stderr io.Writer, examples string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "%s\n\nUSAGE\n  githubauth %s [flags]\n\nFLAGS\n", summary, name)
		printFlags(stderr, fs)
		_, _ = fmt.Fprintf(stderr, "\nEXAMPLES\n%s\n", examples)
	}
	return fs
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
		// invocation to fix rather than anything GitHub was asked about.
		return nil, usagef("reading private key: %v", err)
	}
	return pem, nil
}

func write(w io.Writer, tok *oauth2.Token, asJSON bool) error {
	if !asJSON {
		_, err := fmt.Fprintln(w, tok.AccessToken)
		return err
	}
	return json.NewEncoder(w).Encode(struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{tok.AccessToken, tok.Expiry})
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

// envInt64 ignores a malformed value so the flag's own error reporting
// handles it, rather than failing before the flags are parsed.
func envInt64(key string) int64 {
	n, _ := strconv.ParseInt(os.Getenv(key), 10, 64)
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

// nearest suggests a command for a typo, matching on a shared prefix or a
// single edit, which covers the realistic slips.
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
