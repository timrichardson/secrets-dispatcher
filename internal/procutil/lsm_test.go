package procutil

import (
	"os"
	"testing"
)

func TestReadLSMContext_Self(t *testing.T) {
	ctx := ReadLSMContext(int32(os.Getpid()))
	// On many systems the value will be "unconfined" or an AppArmor/SELinux
	// label; on systems without an LSM it may be empty. Just verify we don't
	// crash and log what we got.
	t.Logf("self LSM context = %q", ctx)
}

func TestReadLSMContext_InvalidPID(t *testing.T) {
	ctx := ReadLSMContext(-1)
	if ctx != "" {
		t.Errorf("expected empty string for invalid PID, got %q", ctx)
	}
}

func TestParseLSMLabel_AppArmor(t *testing.T) {
	tests := []struct {
		name string
		ctx  string
		want string
	}{
		{"snap confined", "snap.firefox.firefox (enforce)", "snap.firefox.firefox"},
		{"custom profile", "hermes (enforce)", "hermes"},
		{"profile with namespace", "flatpak-org.mozilla.Firefox (enforce)", "flatpak-org.mozilla.Firefox"},
		{"complain mode", "myapp (complain)", "myapp"},
		{"audit mode", "myapp (audit)", "myapp"},
		{"unconfined bare", "unconfined", ""},
		{"unconfined with mode", "unconfined (not a profile)", ""},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"apparmor no mode", "my-profile-name", "my-profile-name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseLSMLabel(tt.ctx)
			if got != tt.want {
				t.Errorf("ParseLSMLabel(%q) = %q, want %q", tt.ctx, got, tt.want)
			}
		})
	}
}

func TestParseLSMLabel_SELinux(t *testing.T) {
	tests := []struct {
		name string
		ctx  string
		want string
	}{
		{"confined service", "system_u:system_r:httpd_t:s0", "httpd_t"},
		{"with MLS levels", "system_u:system_r:myapp_t:s0:c123,c456", "myapp_t"},
		{"unconfined user", "unconfined_u:unconfined_r:unconfined_t:s0", ""},
		{"user domain", "user_u:user_r:user_t:s0", "user_t"},
		{"custom domain", "system_u:system_r:hermes_t:s0:c42", "hermes_t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseLSMLabel(tt.ctx)
			if got != tt.want {
				t.Errorf("ParseLSMLabel(%q) = %q, want %q", tt.ctx, got, tt.want)
			}
		})
	}
}

func TestIsLSMLabelled(t *testing.T) {
	labelled := []string{
		"snap.firefox.firefox (enforce)",
		"hermes (enforce)",
		"system_u:system_r:httpd_t:s0",
	}
	for _, ctx := range labelled {
		if !IsLSMLabelled(ctx) {
			t.Errorf("IsLSMLabelled(%q) = false, want true", ctx)
		}
	}

	unlabelled := []string{
		"",
		"unconfined",
		"unconfined_u:unconfined_r:unconfined_t:s0",
		"unconfined (not a profile)",
	}
	for _, ctx := range unlabelled {
		if IsLSMLabelled(ctx) {
			t.Errorf("IsLSMLabelled(%q) = true, want false", ctx)
		}
	}
}
