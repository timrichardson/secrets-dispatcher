package proxy

import (
	"testing"

	"github.com/nikicat/secrets-dispatcher/internal/approval"
	"github.com/stretchr/testify/assert"
)

func TestSecurityLabelFromChain_PIDFound(t *testing.T) {
	chain := []approval.ProcessInfo{
		{Name: "firefox", PID: 5000, LSMContext: "snap.firefox.firefox (enforce)"},
		{Name: "bash", PID: 4000, LSMContext: "unconfined"},
	}

	// Find by PID, return normalised label
	label := securityLabelFromChain(chain, 5000)
	assert.Equal(t, "snap.firefox.firefox", label)
}

func TestSecurityLabelFromChain_PIDNotFoundFallbackToFirst(t *testing.T) {
	chain := []approval.ProcessInfo{
		{Name: "hermes", PID: 5000, LSMContext: "hermes (enforce)"},
	}

	// PID not in chain — fall back to first entry
	label := securityLabelFromChain(chain, 9999)
	assert.Equal(t, "hermes", label)
}

func TestSecurityLabelFromChain_EmptyChain(t *testing.T) {
	label := securityLabelFromChain(nil, 5000)
	assert.Equal(t, "", label)
}

func TestSecurityLabelFromChain_EmptyLSMContext(t *testing.T) {
	chain := []approval.ProcessInfo{
		{Name: "myapp", PID: 5000}, // no LSMContext
	}

	label := securityLabelFromChain(chain, 5000)
	assert.Equal(t, "", label)
}

func TestSecurityLabelFromChain_Unconfined(t *testing.T) {
	chain := []approval.ProcessInfo{
		{Name: "myapp", PID: 5000, LSMContext: "unconfined"},
	}

	label := securityLabelFromChain(chain, 5000)
	assert.Equal(t, "", label, "unconfined should normalise to empty label")
}

func TestSecurityLabelFromChain_SELinux(t *testing.T) {
	chain := []approval.ProcessInfo{
		{Name: "myapp", PID: 5000, LSMContext: "system_u:system_r:myapp_t:s0:c42"},
	}

	label := securityLabelFromChain(chain, 5000)
	assert.Equal(t, "myapp_t", label)
}

func TestSecurityLabelFromChain_FallbackEntryHasNoLSM(t *testing.T) {
	chain := []approval.ProcessInfo{
		{Name: "bash", PID: 4000, LSMContext: "unconfined"},
		{Name: "target", PID: 5000, LSMContext: "hermes (enforce)"},
	}

	// PID 5000 found in chain, use its label
	label := securityLabelFromChain(chain, 5000)
	assert.Equal(t, "hermes", label)

	// PID 9999 not in chain, fall back to first entry which is unconfined
	label = securityLabelFromChain(chain, 9999)
	assert.Equal(t, "", label, "fallback to unconfined entry should be empty")
}
