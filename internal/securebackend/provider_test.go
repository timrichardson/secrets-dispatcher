package securebackend

import (
	"strings"
	"testing"
)

func TestNewProviderGnomeKeyring(t *testing.T) {
	provider, err := NewProvider(ProviderGnomeKeyring)
	if err != nil {
		t.Fatalf("NewProvider() error: %v", err)
	}
	if provider.Name() != ProviderGnomeKeyring {
		t.Fatalf("provider.Name() = %q, want %q", provider.Name(), ProviderGnomeKeyring)
	}
}

func TestNewProviderRejectsUnknown(t *testing.T) {
	if _, err := NewProvider("unknown"); err == nil {
		t.Fatal("NewProvider() error = nil, want unsupported provider error")
	}
}

func TestGnomeKeyringCommands(t *testing.T) {
	provider := GnomeKeyringProvider{}
	cfg := RuntimeConfig{
		BusAddress: "unix:path=/run/secrets-dispatcher/tim/backend-bus.sock",
		HomeDir:    "/var/lib/secret-companion/tim",
		RuntimeDir: "/run/secrets-dispatcher/tim",
	}

	start := provider.StartCommand(cfg)
	if start.Path != "gnome-keyring-daemon" {
		t.Fatalf("StartCommand().Path = %q, want gnome-keyring-daemon", start.Path)
	}
	if !containsArg(start.Args, "--foreground") || !containsArg(start.Args, "--components=secrets") {
		t.Fatalf("StartCommand().Args = %v, want foreground secrets daemon", start.Args)
	}
	if !containsPrefix(start.Args, "--control-directory=/run/secrets-dispatcher/tim/keyring-control") {
		t.Fatalf("StartCommand().Args = %v, want private control directory", start.Args)
	}

	unlock := provider.UnlockCommand(cfg)
	if unlock.Path != "gnome-keyring-daemon" || !containsArg(unlock.Args, "--unlock") {
		t.Fatalf("UnlockCommand() = %+v, want gnome-keyring-daemon --unlock", unlock)
	}
	joined := strings.Join(append(unlock.Args, unlock.Env...), " ")
	if strings.Contains(strings.ToLower(joined), "password") {
		t.Fatalf("UnlockCommand() must not put password material in argv/env: %+v", unlock)
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func containsPrefix(args []string, want string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, want) {
			return true
		}
	}
	return false
}
