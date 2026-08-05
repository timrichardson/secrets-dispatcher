// Package approval manages pending secret access requests requiring user approval.
package approval

// ProcessInfo represents a single process in the process chain.
type ProcessInfo struct {
	Name       string   `json:"name"`
	PID        uint32   `json:"pid"`
	Exe        string   `json:"exe,omitempty"`
	Args       []string `json:"args,omitempty"`
	CWD        string   `json:"cwd,omitempty"`
	LSMContext string   `json:"lsm_context,omitempty"` // Raw kernel LSM label (AppArmor/SELinux)
}

// TrustRule defines a persistent declarative rule from config for auto-approving, ignoring, or denying requests.
type TrustRule struct {
	Name             string            `json:"name,omitempty"`
	Action           string            `json:"action,omitempty"`
	RequestTypes     []string          `json:"request_types,omitempty"`
	Process          *ProcessMatcher   `json:"process,omitempty"`
	Secret           *SecretMatcher    `json:"secret,omitempty"`
	SearchAttributes map[string]string `json:"search_attributes,omitempty"`
}

// ProcessMatcher matches against sender process attributes.
type ProcessMatcher struct {
	Exe        string `json:"exe,omitempty"`
	Name       string `json:"name,omitempty"`
	Args       string `json:"args,omitempty"`
	CWD        string `json:"cwd,omitempty"`
	Unit       string `json:"unit,omitempty"`
	LSMContext string `json:"lsm_context,omitempty"` // Kernel LSM label (strong identity: snap.*, flatpak.*, custom profile)
	Direct     bool   `json:"direct,omitempty"`
}

// SecretMatcher matches against secret/item attributes.
type SecretMatcher struct {
	Collection string            `json:"collection,omitempty"`
	Label      string            `json:"label,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// SenderInfo contains information about the D-Bus sender process.
type SenderInfo struct {
	Sender       string        `json:"sender"`                  // D-Bus unique name (":1.123")
	PID          uint32        `json:"pid"`                     // Process ID
	UID          uint32        `json:"uid"`                     // User ID
	UserName     string        `json:"user_name"`               // Username (may be empty if lookup fails)
	InvokerName  string        `json:"invoker_name"`            // Invoker process comm (display); spoofable — NOT the systemd unit
	SystemdUnit  string        `json:"systemd_unit,omitempty"`  // Real systemd unit (from GetUnitByPID); authoritative, matched by the `unit` rule
	ProcessChain []ProcessInfo `json:"process_chain,omitempty"` // Full process chain from requestor to init
	// SecurityLabel is the normalised LSM application label of the direct caller
	// (ProcessChain[0]), extracted from /proc/PID/attr/current. Unlike InvokerName
	// (which is attacker-controllable via prctl(PR_SET_NAME)), this is a
	// kernel-enforced label assigned by AppArmor or SELinux policy at exec time
	// and cannot be spoofed by the process. Examples: "snap.firefox.firefox",
	// "hermes", "httpd_t". Empty when no LSM is active or the process is
	// unconfined — in that case fall back to /proc/PID/exe path matching.
	SecurityLabel string `json:"security_label,omitempty"`
	// PeerTrusted reports whether the process that opened the connection is a
	// trusted transport for this request — one whose self-reported, server-
	// unverifiable fields (repo name, changed files, commit object) we can rely
	// on because our own code produced them. Today the only trusted transport is our
	// gpg-sign thin client (the peer's exe is our own binary); the field is named
	// generally so other trusted transports can set it later. It gates the silent
	// trusted-signer path — see Manager.CheckTrustedSigner. Unset for requests that
	// speak the socket protocol directly.
	PeerTrusted bool `json:"peer_trusted,omitempty"`
}
