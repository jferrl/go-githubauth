package main

import "testing"

func TestAgentModeEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{
			name: "no agent in sight",
			want: false,
		},
		{
			name: "Claude Code sets CLAUDECODE",
			env:  map[string]string{"CLAUDECODE": "1"},
			want: true,
		},
		{
			name: "a name rather than a flag still counts",
			env:  map[string]string{"CURSOR_AGENT": "cursor"},
			want: true,
		},
		{
			name: "an explicit denial from the agent variable itself",
			env:  map[string]string{"CLAUDECODE": "0"},
			want: false,
		},
		{
			name: "the override wins over a detected agent",
			env:  map[string]string{"CLAUDECODE": "1", "GITHUBAUTH_AGENT_MODE": "0"},
			want: false,
		},
		{
			name: "the override turns it on with no agent present",
			env:  map[string]string{"GITHUBAUTH_AGENT_MODE": "yes"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The suite usually runs inside an agent, so every variable the
			// detection reads has to be cleared before the case sets its own.
			for _, key := range agentEnv {
				t.Setenv(key, "")
			}
			t.Setenv("GITHUBAUTH_AGENT_MODE", "")
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			if got := agentModeEnv(); got != tt.want {
				t.Errorf("agentModeEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTruthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		wantOn  bool
		wantSet bool
	}{
		{in: "", wantOn: false, wantSet: false},
		{in: "  ", wantOn: false, wantSet: false},
		{in: "1", wantOn: true, wantSet: true},
		{in: "true", wantOn: true, wantSet: true},
		{in: "TRUE", wantOn: true, wantSet: true},
		{in: "yes", wantOn: true, wantSet: true},
		{in: "0", wantOn: false, wantSet: true},
		{in: "false", wantOn: false, wantSet: true},
		{in: " No ", wantOn: false, wantSet: true},
		{in: "off", wantOn: false, wantSet: true},
		{in: "cursor", wantOn: true, wantSet: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			on, set := truthy(tt.in)
			if on != tt.wantOn || set != tt.wantSet {
				t.Errorf("truthy(%q) = (%v, %v), want (%v, %v)", tt.in, on, set, tt.wantOn, tt.wantSet)
			}
		})
	}
}
