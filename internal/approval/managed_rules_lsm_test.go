package approval

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagedTrustRuleFromRequest_WithLSMContext(t *testing.T) {
	req := &Request{
		ID:   "test-req",
		Type: RequestTypeGetSecret,
		Items: []ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Label:      "GitHub token",
			Attributes: map[string]string{"service": "github"},
		}},
		SenderInfo: SenderInfo{
			PID: 101,
			ProcessChain: []ProcessInfo{{
				Name:       "gh",
				PID:        101,
				Exe:        "/usr/bin/gh",
				Args:       []string{"/usr/bin/gh"},
				LSMContext: "gh (enforce)",
			}},
		},
	}

	rule, err := managedTrustRuleFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, "gh (enforce)", rule.Process.LSMContext,
		"saved rule should include the raw LSM context")
	assert.True(t, rule.Process.Direct)
}

func TestManagedTrustRuleFromRequest_WithoutLSMContext(t *testing.T) {
	req := &Request{
		ID:   "test-req",
		Type: RequestTypeGetSecret,
		Items: []ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Label:      "GitHub token",
			Attributes: map[string]string{"service": "github"},
		}},
		SenderInfo: SenderInfo{
			PID: 101,
			ProcessChain: []ProcessInfo{{
				Name: "gh",
				PID:  101,
				Exe:  "/usr/bin/gh",
				Args: []string{"/usr/bin/gh"},
				// No LSMContext — unconfined or no LSM
			}},
		},
	}

	rule, err := managedTrustRuleFromRequest(req)
	require.NoError(t, err)
	assert.Empty(t, rule.Process.LSMContext,
		"rule should have empty LSM context when caller has none")
}

func TestManagedTrustRuleFromRequest_SnapLSMContext(t *testing.T) {
	exe := "/snap/bin/firefox"
	req := &Request{
		ID:   "test-req",
		Type: RequestTypeGetSecret,
		Items: []ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Label:      "Firefox Sync token",
			Attributes: map[string]string{"service": "mozilla"},
		}},
		SenderInfo: SenderInfo{
			PID: 200,
			ProcessChain: []ProcessInfo{{
				Name:       "firefox",
				PID:        200,
				Exe:        exe,
				Args:       []string{exe},
				LSMContext: "snap.firefox.firefox (enforce)",
			}},
		},
	}

	rule, err := managedTrustRuleFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, "snap.firefox.firefox (enforce)", rule.Process.LSMContext)
}

func TestManagedTrustRuleFromRequest_SELinuxContext(t *testing.T) {
	exe := "/usr/local/bin/hermes"
	req := &Request{
		ID:   "test-req",
		Type: RequestTypeGetSecret,
		Items: []ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Label:      "API Key",
			Attributes: map[string]string{"service": "api"},
		}},
		SenderInfo: SenderInfo{
			PID: 300,
			ProcessChain: []ProcessInfo{{
				Name:       "hermes",
				PID:        300,
				Exe:        exe,
				Args:       []string{exe},
				LSMContext: "system_u:system_r:hermes_t:s0:c42",
			}},
		},
	}

	rule, err := managedTrustRuleFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, "system_u:system_r:hermes_t:s0:c42", rule.Process.LSMContext)
}

func TestValidateManagedTrustRule_WithLSMContext(t *testing.T) {
	rule := validManagedRule()
	rule.Process.LSMContext = "gh (enforce)"
	require.NoError(t, ValidateManagedTrustRule(&rule),
		"LSM context should be accepted by validation")
}

func TestValidateManagedTrustRule_LSMContextWithWildcards(t *testing.T) {
	rule := validManagedRule()
	rule.Process.LSMContext = "snap.*"
	require.Error(t, ValidateManagedTrustRule(&rule),
		"wildcards should be rejected in managed rules")
}

func TestManagedTrustRuleFromRequest_UnconfinedLSM(t *testing.T) {
	// "unconfined" should be treated as no meaningful label
	req := &Request{
		ID:   "test-req",
		Type: RequestTypeGetSecret,
		Items: []ItemInfo{{
			Path:       "/org/freedesktop/secrets/collection/login/item1",
			Label:      "Token",
			Attributes: map[string]string{"service": "api"},
		}},
		SenderInfo: SenderInfo{
			PID: 400,
			ProcessChain: []ProcessInfo{{
				Name:       "myapp",
				PID:        400,
				Exe:        filepath.Join("/", "usr", "bin", "myapp"),
				Args:       []string{"/usr/bin/myapp"},
				LSMContext: "unconfined",
			}},
		},
	}

	rule, err := managedTrustRuleFromRequest(req)
	require.NoError(t, err)
	// "unconfined" is still saved — it's the raw context. The matcher will
	// correctly handle it: another unconfined process will match, which is
	// the right behavior (if you approved it once, approve again).
	assert.Equal(t, "unconfined", rule.Process.LSMContext)
}
