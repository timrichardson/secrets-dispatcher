package approval

import (
	"testing"
)

func TestMatchProcess_LSMContext_Direct(t *testing.T) {
	senderInfo := SenderInfo{
		SecurityLabel: "snap.firefox.firefox",
		ProcessChain: []ProcessInfo{
			{Name: "firefox", PID: 1000, Exe: "/snap/firefox/current/firefox", LSMContext: "snap.firefox.firefox (enforce)"},
		},
	}

	tests := []struct {
		name    string
		matcher ProcessMatcher
		want    bool
	}{
		{
			name:    "direct LSM match exact",
			matcher: ProcessMatcher{Direct: true, LSMContext: "snap.firefox.firefox (enforce)"},
			want:    true,
		},
		{
			name:    "direct LSM match glob",
			matcher: ProcessMatcher{Direct: true, LSMContext: "snap.*"},
			want:    true,
		},
		{
			name:    "direct LSM no match different label",
			matcher: ProcessMatcher{Direct: true, LSMContext: "snap.chromium.chromium (enforce)"},
			want:    false,
		},
		{
			name:    "direct LSM no match empty chain label",
			matcher: ProcessMatcher{Direct: true, LSMContext: "nonexistent (enforce)"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchProcess(&tt.matcher, senderInfo)
			if got != tt.want {
				t.Errorf("matchProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchProcess_LSMContext_NonDirect(t *testing.T) {
	senderInfo := SenderInfo{
		SecurityLabel: "hermes",
		ProcessChain: []ProcessInfo{
			{Name: "hermes", PID: 1000, Exe: "/home/user/.local/bin/hermes", LSMContext: "hermes (enforce)"},
			{Name: "bash", PID: 900, Exe: "/bin/bash"},
		},
	}

	tests := []struct {
		name    string
		matcher ProcessMatcher
		want    bool
	}{
		{
			name:    "non-direct LSM match via SecurityLabel",
			matcher: ProcessMatcher{LSMContext: "hermes"},
			want:    true,
		},
		{
			name:    "non-direct LSM match via chain raw context",
			matcher: ProcessMatcher{LSMContext: "hermes (enforce)"},
			want:    true,
		},
		{
			name:    "non-direct LSM glob match",
			matcher: ProcessMatcher{LSMContext: "her*"},
			want:    true,
		},
		{
			name:    "non-direct LSM no match",
			matcher: ProcessMatcher{LSMContext: "nonexistent"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchProcess(&tt.matcher, senderInfo)
			if got != tt.want {
				t.Errorf("matchProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchProcess_LSMContext_SELinux(t *testing.T) {
	senderInfo := SenderInfo{
		SecurityLabel: "hermes_t",
		ProcessChain: []ProcessInfo{
			{Name: "hermes", PID: 1000, Exe: "/usr/local/bin/hermes",
				LSMContext: "system_u:system_r:hermes_t:s0:c42"},
		},
	}

	tests := []struct {
		name    string
		matcher ProcessMatcher
		want    bool
	}{
		{
			name:    "selinux match normalised label",
			matcher: ProcessMatcher{Direct: true, LSMContext: "hermes_t"},
			want:    false, // Direct matches on raw context in chain, not normalised label
		},
		{
			name:    "selinux match raw context",
			matcher: ProcessMatcher{Direct: true, LSMContext: "system_u:system_r:hermes_t:s0:c42"},
			want:    true,
		},
		{
			name:    "selinux glob on raw context",
			matcher: ProcessMatcher{Direct: true, LSMContext: "*:hermes_t:*"},
			want:    true, // path.Match treats * as glob — but ":" is a literal, so this tests format
		},
	}

	// Fix: for Direct matching, we match against the raw LSMContext in ProcessChain[0],
	// not the normalised SecurityLabel.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchProcess(&tt.matcher, senderInfo)
			if got != tt.want {
				t.Errorf("matchProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchProcess_LSMContext_Unconfined(t *testing.T) {
	// Process with no LSM confinement
	senderInfo := SenderInfo{
		SecurityLabel: "",
		ProcessChain: []ProcessInfo{
			{Name: "myapp", PID: 1000, Exe: "/usr/bin/myapp", LSMContext: "unconfined"},
		},
	}

	// A rule requiring a specific LSM label should NOT match an unconfined process
	matcher := ProcessMatcher{Direct: true, LSMContext: "myapp (enforce)"}
	if matchProcess(&matcher, senderInfo) {
		t.Error("expected unconfined process to not match labelled rule")
	}

	// A rule with no LSM constraint should match (unaffected by LSM)
	matcher2 := ProcessMatcher{Direct: true, Exe: "/usr/bin/myapp"}
	if !matchProcess(&matcher2, senderInfo) {
		t.Error("expected exe-only rule to match regardless of LSM")
	}
}

func TestMatchProcess_LSMContext_EmptyContext(t *testing.T) {
	// Process with no LSM at all (empty context field)
	senderInfo := SenderInfo{
		SecurityLabel: "",
		ProcessChain: []ProcessInfo{
			{Name: "myapp", PID: 1000, Exe: "/usr/bin/myapp"},
		},
	}

	// Rule with LSM constraint should not match (empty != required label)
	matcher := ProcessMatcher{Direct: true, LSMContext: "myapp (enforce)"}
	if matchProcess(&matcher, senderInfo) {
		t.Error("expected empty LSM context to not match labelled rule")
	}
}
