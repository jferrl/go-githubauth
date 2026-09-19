package main

import (
	"os"
	"strings"
)

// agentTokenHint goes to stderr, where it cannot corrupt $(githubauth token).
// A printed credential outlives the command in the transcript.
const agentTokenHint = "hint: this credential is now in the session transcript; --exec passes it to a command without printing it\n"

// agentEnv are the variables coding agents set in the shells they run commands
// in. Detecting them means no agent has to be told to pass a flag. The list
// follows the convention gcx established.
var agentEnv = []string{
	"CLAUDECODE",
	"CLAUDE_CODE",
	"CURSOR_AGENT",
	"GITHUB_COPILOT",
	"AMAZON_Q",
	"OPENCODE",
	"PI_CODING_AGENT",
}

// agentModeEnv reports whether an agent is running this command.
// GITHUBAUTH_AGENT_MODE decides on its own when set, in either direction, so a
// CI job that inherits an agent's environment can still turn it off.
func agentModeEnv() bool {
	if on, ok := truthy(os.Getenv("GITHUBAUTH_AGENT_MODE")); ok {
		return on
	}
	for _, key := range agentEnv {
		if on, ok := truthy(os.Getenv(key)); ok && on {
			return true
		}
	}
	return false
}

// truthy reads a flag-shaped environment variable. A value that is set to
// something unrecognized counts as on: agents spell these differently
// ("CURSOR_AGENT=cursor"), and only an explicit denial should mean off.
func truthy(v string) (on, set bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return false, false
	case "0", "false", "no", "off":
		return false, true
	}
	return true, true
}
