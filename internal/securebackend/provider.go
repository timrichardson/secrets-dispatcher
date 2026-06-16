package securebackend

import "fmt"

const ProviderGnomeKeyring = "gnome-keyring"

type LockState string

const (
	LockStateUnknown  LockState = "unknown"
	LockStateUnlocked LockState = "unlocked"
	LockStateLocked   LockState = "locked"
)

// Command describes a provider process invocation. Sensitive values must be passed on Stdin only.
type Command struct {
	Path string
	Args []string
	Env  []string
}

// RuntimeConfig contains provider runtime paths for one secure-local instance.
type RuntimeConfig struct {
	BusAddress string
	HomeDir    string
	RuntimeDir string
}

// Provider describes a pluggable Secret Service backend usable by secure-local mode.
type Provider interface {
	Name() string
	StartCommand(RuntimeConfig) Command
	UnlockCommand(RuntimeConfig) Command
	LockedStateSignals() []string
}

// NewProvider returns the configured secure backend provider.
func NewProvider(name string) (Provider, error) {
	switch name {
	case ProviderGnomeKeyring:
		return GnomeKeyringProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported secure backend provider %q", name)
	}
}

// GnomeKeyringProvider implements the initial secure-local Secret Service backend.
type GnomeKeyringProvider struct{}

func (GnomeKeyringProvider) Name() string { return ProviderGnomeKeyring }

func (GnomeKeyringProvider) StartCommand(cfg RuntimeConfig) Command {
	return Command{
		Path: "gnome-keyring-daemon",
		Args: []string{
			"--foreground",
			"--components=secrets",
			"--control-directory=" + cfg.RuntimeDir + "/keyring-control",
		},
		Env: providerEnv(cfg),
	}
}

func (GnomeKeyringProvider) UnlockCommand(cfg RuntimeConfig) Command {
	return Command{
		Path: "gnome-keyring-daemon",
		Args: []string{"--unlock"},
		Env:  providerEnv(cfg),
	}
}

func (GnomeKeyringProvider) LockedStateSignals() []string {
	return []string{
		"collection Locked property",
		"SearchItems locked result set",
		"Unlock prompt object",
		"GetSecrets locked or empty response",
	}
}

func providerEnv(cfg RuntimeConfig) []string {
	return []string{
		"DBUS_SESSION_BUS_ADDRESS=" + cfg.BusAddress,
		"HOME=" + cfg.HomeDir,
		"XDG_RUNTIME_DIR=" + cfg.RuntimeDir,
	}
}
