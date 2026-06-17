package securelocal

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/nikicat/secrets-dispatcher/internal/securebackend"
)

const (
	DefaultHomeBase = "/var/lib/secret-companion"
	DefaultProvider = securebackend.ProviderGnomeKeyring
	SystemUnitPath  = "/etc/systemd/system/secrets-dispatcher-secure@.service"
)

type ProvisionConfig struct {
	DesktopUser string
	BackendUser string
	HomeBase    string
	Provider    string
	BinaryPath  string
}

var (
	geteuidFunc    = os.Geteuid
	userLookupFunc = user.Lookup
	userAddFunc    = defaultUserAdd
	mkdirAllFunc   = os.MkdirAll
	chownFunc      = os.Lchown
	chmodFunc      = os.Chmod
	writeFileFunc  = os.WriteFile
	systemctlFunc  = defaultSystemctl
)

func (c *ProvisionConfig) defaults() {
	if c.HomeBase == "" {
		c.HomeBase = DefaultHomeBase
	}
	if c.Provider == "" {
		c.Provider = DefaultProvider
	}
	if c.DesktopUser == "" {
		c.DesktopUser = os.Getenv("SUDO_USER")
	}
	if c.BackendUser == "" && c.DesktopUser != "" {
		c.BackendUser = "secrets-" + c.DesktopUser
	}
	if c.BinaryPath == "" {
		c.BinaryPath = "/usr/local/bin/secrets-dispatcher"
	}
}

func (c ProvisionConfig) backendHome() string {
	return filepath.Join(c.HomeBase, c.DesktopUser)
}

func Provision(cfg ProvisionConfig) error {
	cfg.defaults()
	if geteuidFunc() != 0 {
		return fmt.Errorf("secure-local provisioning requires root; run with sudo")
	}
	if cfg.DesktopUser == "" {
		return fmt.Errorf("no desktop user specified: use --user or run via sudo")
	}
	if _, err := securebackend.NewProvider(cfg.Provider); err != nil {
		return err
	}
	if err := validateRootUnitBinaryPath(cfg.BinaryPath); err != nil {
		return err
	}
	if err := validateRootUnitHomeBase(cfg.HomeBase); err != nil {
		return err
	}
	if _, err := userLookupFunc(cfg.DesktopUser); err != nil {
		return fmt.Errorf("lookup desktop user %q: %w", cfg.DesktopUser, err)
	}

	homeDir := cfg.backendHome()
	if err := ensureBackendUser(cfg.BackendUser, homeDir); err != nil {
		return err
	}
	u, err := userLookupFunc(cfg.BackendUser)
	if err != nil {
		return fmt.Errorf("lookup backend user %q: %w", cfg.BackendUser, err)
	}
	uid, gid, err := parseUserIDs(u)
	if err != nil {
		return err
	}
	if err := ensureBackendDirs(homeDir, uid, gid); err != nil {
		return err
	}
	if err := ensureRootDir(DefaultSecureConfigBase, 0755); err != nil {
		return err
	}
	if err := ensureRootDir(DefaultSecureRuntimeBase, 0711); err != nil {
		return err
	}
	if err := ensureRootDir(DefaultSecureStateBase, 0755); err != nil {
		return err
	}
	if err := ensureRootDir(filepath.Join(DefaultSecureStateBase, cfg.DesktopUser), 0700); err != nil {
		return err
	}
	if err := writeSecureSystemUnit(cfg); err != nil {
		return err
	}
	if err := systemctlFunc("daemon-reload"); err != nil {
		return err
	}
	return nil
}

func ensureBackendUser(username, homeDir string) error {
	if _, err := userLookupFunc(username); err == nil {
		return nil
	}
	if err := mkdirAllFunc(filepath.Dir(homeDir), 0755); err != nil {
		return fmt.Errorf("create backend home parent: %w", err)
	}
	if err := userAddFunc(username, homeDir, "/usr/sbin/nologin"); err != nil {
		return fmt.Errorf("create backend user %q: %w", username, err)
	}
	return nil
}

func ensureRootDir(path string, mode os.FileMode) error {
	if err := mkdirAllFunc(path, mode); err != nil {
		return fmt.Errorf("create root-owned dir %s: %w", path, err)
	}
	if err := chownFunc(path, 0, 0); err != nil {
		return fmt.Errorf("chown root-owned dir %s: %w", path, err)
	}
	if err := chmodFunc(path, mode); err != nil {
		return fmt.Errorf("chmod root-owned dir %s: %w", path, err)
	}
	return nil
}

func ensureBackendDirs(homeDir string, uid, gid int) error {
	dirs := []string{
		homeDir,
		filepath.Join(homeDir, ".config"),
		filepath.Join(homeDir, ".cache"),
		filepath.Join(homeDir, ".local"),
		filepath.Join(homeDir, ".local", "share"),
		filepath.Join(homeDir, ".local", "share", "keyrings"),
	}
	for _, dir := range dirs {
		if err := mkdirAllFunc(dir, 0700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := chownFunc(dir, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
		if err := chmodFunc(dir, 0700); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}
	return nil
}

func writeSecureSystemUnit(cfg ProvisionConfig) error {
	vars := struct {
		BinaryPath string
		HomeBase   string
		Provider   string
		StateBase  string
	}{
		BinaryPath: cfg.BinaryPath,
		HomeBase:   cfg.HomeBase,
		Provider:   cfg.Provider,
		StateBase:  DefaultSecureStateBase,
	}
	tmpl, err := template.New("secure-unit").Parse(secureSystemUnitTemplate)
	if err != nil {
		return fmt.Errorf("parse secure system unit template: %w", err)
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, vars); err != nil {
		return fmt.Errorf("render secure system unit: %w", err)
	}
	if err := writeFileFunc(SystemUnitPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write %s: %w", SystemUnitPath, err)
	}
	return nil
}

func validateRootUnitBinaryPath(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("secure-local binary path must be absolute")
	}
	if strings.ContainsAny(path, " \t\r\n") {
		return fmt.Errorf("secure-local binary path must not contain whitespace")
	}
	for _, prefix := range []string{"/home/", "/tmp/", "/var/tmp/", "/run/user/"} {
		if strings.HasPrefix(path, prefix) {
			return fmt.Errorf("secure-local system unit must not reference user-writable binary path %q", path)
		}
	}
	return nil
}

func validateRootUnitHomeBase(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("secure-local home base must be absolute")
	}
	if strings.ContainsAny(path, " \t\r\n") {
		return fmt.Errorf("secure-local home base must not contain whitespace")
	}
	return nil
}

func parseUserIDs(u *user.User) (int, int, error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse UID %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse GID %q: %w", u.Gid, err)
	}
	return uid, gid, nil
}

func defaultUserAdd(username, homeDir, shell string) error {
	cmd := exec.Command("useradd", "--system", "--home-dir", homeDir, "--no-create-home", "--shell", shell, username)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("useradd: %w", err)
	}
	return nil
}

func defaultSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return nil
}

const secureSystemUnitTemplate = `[Unit]
Description=Secrets Dispatcher secure local Secret Service proxy for %i
Documentation=https://github.com/nikicat/secrets-dispatcher
After=systemd-user-sessions.service

[Service]
Type=simple
ExecStart={{.BinaryPath}} secure-launch --user %i --backend {{.Provider}} --backend-home-base {{.HomeBase}} --config ` + DefaultSecureConfigBase + `/%i.yaml
Restart=on-failure
RestartSec=5

# Keep the root-owned launcher and per-user backend isolated from the desktop user.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=` + DefaultSecureRuntimeBase + ` {{.HomeBase}} {{.StateBase}}

[Install]
WantedBy=multi-user.target
`
