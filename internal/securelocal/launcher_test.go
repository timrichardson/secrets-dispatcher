package securelocal

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunLauncherRejectsBackendRoot(t *testing.T) {
	saveProvisionFuncs(t)
	stubProvisionSideEffects()
	userLookupFunc = func(username string) (*user.User, error) {
		switch username {
		case "tim":
			return &user.User{Username: "tim", Uid: "1000", Gid: "1000", HomeDir: "/home/tim"}, nil
		case "root-backend":
			return &user.User{Username: "root-backend", Uid: "0", Gid: "0"}, nil
		default:
			return nil, user.UnknownUserError(username)
		}
	}

	err := RunLauncher(context.Background(), LaunchConfig{DesktopUser: "tim", BackendUser: "root-backend"})
	if err == nil {
		t.Fatal("RunLauncher() error = nil, want root backend rejection")
	}
	if !strings.Contains(err.Error(), "must not be root") {
		t.Fatalf("error should mention root backend, got: %v", err)
	}
}

func TestRunLauncherRejectsBackendDesktopUID(t *testing.T) {
	saveProvisionFuncs(t)
	stubProvisionSideEffects()
	userLookupFunc = func(username string) (*user.User, error) {
		switch username {
		case "tim":
			return &user.User{Username: "tim", Uid: "1000", Gid: "1000", HomeDir: "/home/tim"}, nil
		case "secrets-tim":
			return &user.User{Username: "secrets-tim", Uid: "1000", Gid: "1000"}, nil
		default:
			return nil, user.UnknownUserError(username)
		}
	}

	err := RunLauncher(context.Background(), LaunchConfig{DesktopUser: "tim"})
	if err == nil {
		t.Fatal("RunLauncher() error = nil, want same-UID backend rejection")
	}
	if !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("error should mention distinct users, got: %v", err)
	}
}

func TestPrepareRuntimeDirCreatesSearchableParent(t *testing.T) {
	saveProvisionFuncs(t)
	var mkdirs []string
	var chmods []string
	mkdirAllFunc = func(path string, perm os.FileMode) error {
		mkdirs = append(mkdirs, path+":"+perm.String())
		return nil
	}
	chownFunc = func(path string, uid, gid int) error { return nil }
	chmodFunc = func(path string, mode os.FileMode) error {
		chmods = append(chmods, path+":"+mode.String())
		return nil
	}

	runtimeDir := filepath.Join("/run", "secrets-dispatcher", "tim")
	if err := prepareRuntimeDir(runtimeDir, 900, 900); err != nil {
		t.Fatalf("prepareRuntimeDir() error: %v", err)
	}
	if !containsString(mkdirs, "/run/secrets-dispatcher:-rwx--x--x") {
		t.Fatalf("mkdirs = %v, want searchable parent", mkdirs)
	}
	if !containsString(mkdirs, "/run/secrets-dispatcher/tim:-rwx------") {
		t.Fatalf("mkdirs = %v, want private leaf", mkdirs)
	}
	if !containsString(chmods, "/run/secrets-dispatcher:-rwx--x--x") {
		t.Fatalf("chmods = %v, want searchable parent", chmods)
	}
}

func TestLaunchConfigSecurePaths(t *testing.T) {
	cfg := LaunchConfig{DesktopUser: "tim"}
	if got := cfg.secureConfigPath(); got != filepath.Join(DefaultSecureConfigBase, "tim.yaml") {
		t.Fatalf("secureConfigPath() = %q", got)
	}
	if got := cfg.secureStateDir(); got != filepath.Join(DefaultSecureStateBase, "tim") {
		t.Fatalf("secureStateDir() = %q", got)
	}
}
