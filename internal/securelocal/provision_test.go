package securelocal

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func saveProvisionFuncs(t *testing.T) {
	t.Helper()
	origGeteuid := geteuidFunc
	origLookup := userLookupFunc
	origUserAdd := userAddFunc
	origMkdirAll := mkdirAllFunc
	origChown := chownFunc
	origChmod := chmodFunc
	origWriteFile := writeFileFunc
	origSystemctl := systemctlFunc
	t.Cleanup(func() {
		geteuidFunc = origGeteuid
		userLookupFunc = origLookup
		userAddFunc = origUserAdd
		mkdirAllFunc = origMkdirAll
		chownFunc = origChown
		chmodFunc = origChmod
		writeFileFunc = origWriteFile
		systemctlFunc = origSystemctl
	})
}

func stubProvisionSideEffects() {
	geteuidFunc = func() int { return 0 }
	mkdirAllFunc = func(path string, perm os.FileMode) error { return nil }
	chownFunc = func(path string, uid, gid int) error { return nil }
	chmodFunc = func(path string, mode os.FileMode) error { return nil }
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error { return nil }
	systemctlFunc = func(args ...string) error { return nil }
	userAddFunc = func(username, homeDir, shell string) error { return nil }
}

func TestProvisionSecureLocalCreatesBackendUserAndUnit(t *testing.T) {
	saveProvisionFuncs(t)
	stubProvisionSideEffects()

	var addedUser, addedHome, addedShell string
	var unitContent string
	var systemctlCalls []string
	lookupCount := map[string]int{}
	userLookupFunc = func(username string) (*user.User, error) {
		lookupCount[username]++
		switch username {
		case "tim":
			return &user.User{Username: "tim", Uid: "1000", Gid: "1000", HomeDir: "/home/tim"}, nil
		case "secrets-tim":
			if lookupCount[username] == 1 {
				return nil, user.UnknownUserError(username)
			}
			return &user.User{Username: "secrets-tim", Uid: "900", Gid: "900"}, nil
		default:
			return nil, user.UnknownUserError(username)
		}
	}
	userAddFunc = func(username, homeDir, shell string) error {
		addedUser = username
		addedHome = homeDir
		addedShell = shell
		return nil
	}
	writeFileFunc = func(path string, data []byte, perm os.FileMode) error {
		if path == SystemUnitPath {
			unitContent = string(data)
		}
		return nil
	}
	systemctlFunc = func(args ...string) error {
		systemctlCalls = append(systemctlCalls, strings.Join(args, " "))
		return nil
	}

	err := Provision(ProvisionConfig{DesktopUser: "tim", BinaryPath: "/usr/local/bin/secrets-dispatcher"})
	if err != nil {
		t.Fatalf("Provision() error: %v", err)
	}
	if addedUser != "secrets-tim" || addedHome != "/var/lib/secret-companion/tim" || addedShell != "/usr/sbin/nologin" {
		t.Fatalf("userAdd = (%q, %q, %q), want secrets-tim home nologin", addedUser, addedHome, addedShell)
	}
	if !strings.Contains(unitContent, "secure-launch --user %i --backend gnome-keyring") {
		t.Fatalf("secure unit missing secure-launch ExecStart, got:\n%s", unitContent)
	}
	if !strings.Contains(unitContent, "--config /etc/secrets-dispatcher/secure/%i.yaml") {
		t.Fatalf("secure unit should pass root-owned trusted config path, got:\n%s", unitContent)
	}
	if strings.Contains(unitContent, "SECRETS_DISPATCHER_BACKEND_FD") {
		t.Fatalf("secure unit must not pass backend FD to a desktop-user process, got:\n%s", unitContent)
	}
	if !strings.Contains(unitContent, "ReadWritePaths=/run/secrets-dispatcher /var/lib/secret-companion /var/lib/secrets-dispatcher/secure") {
		t.Fatalf("secure unit missing required write paths, got:\n%s", unitContent)
	}
	if strings.Contains(unitContent, "/home/") || strings.Contains(unitContent, "/tmp/") {
		t.Fatalf("secure unit should not reference user-writable paths, got:\n%s", unitContent)
	}
	if strings.Contains(unitContent, "user@%i.service") {
		t.Fatalf("secure unit must not use username as a user@.service instance, got:\n%s", unitContent)
	}
	if len(systemctlCalls) != 1 || systemctlCalls[0] != "daemon-reload" {
		t.Fatalf("systemctl calls = %v, want [daemon-reload]", systemctlCalls)
	}
}

func TestProvisionSecureLocalDirs(t *testing.T) {
	saveProvisionFuncs(t)
	stubProvisionSideEffects()
	userLookupFunc = func(username string) (*user.User, error) {
		return &user.User{Username: username, Uid: "900", Gid: "900", HomeDir: "/home/" + username}, nil
	}

	var dirs []string
	mkdirAllFunc = func(path string, perm os.FileMode) error {
		dirs = append(dirs, path)
		return nil
	}

	err := Provision(ProvisionConfig{DesktopUser: "tim", BinaryPath: "/usr/local/bin/secrets-dispatcher"})
	if err != nil {
		t.Fatalf("Provision() error: %v", err)
	}
	want := []string{
		filepath.Join("/var/lib/secret-companion", "tim"),
		filepath.Join("/var/lib/secret-companion", "tim", ".config"),
		filepath.Join("/var/lib/secret-companion", "tim", ".cache"),
		filepath.Join("/var/lib/secret-companion", "tim", ".local"),
		filepath.Join("/var/lib/secret-companion", "tim", ".local", "share"),
		filepath.Join("/var/lib/secret-companion", "tim", ".local", "share", "keyrings"),
		DefaultSecureConfigBase,
		DefaultSecureStateBase,
		filepath.Join(DefaultSecureStateBase, "tim"),
	}
	for _, path := range want {
		if !containsString(dirs, path) {
			t.Fatalf("mkdirAll paths = %v, missing %s", dirs, path)
		}
	}
}

func TestProvisionSecureLocalRejectsUserWritableBinary(t *testing.T) {
	saveProvisionFuncs(t)
	stubProvisionSideEffects()
	err := Provision(ProvisionConfig{DesktopUser: "tim", BinaryPath: "/home/tim/bin/secrets-dispatcher"})
	if err == nil {
		t.Fatal("Provision() error = nil, want user-writable binary rejection")
	}
	if !strings.Contains(err.Error(), "user-writable") {
		t.Fatalf("error should mention user-writable path, got: %v", err)
	}
}

func TestProvisionSecureLocalRequiresRoot(t *testing.T) {
	saveProvisionFuncs(t)
	geteuidFunc = func() int { return 1000 }
	err := Provision(ProvisionConfig{DesktopUser: "tim", BinaryPath: "/usr/local/bin/secrets-dispatcher"})
	if err == nil {
		t.Fatal("Provision() error = nil, want root error")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
