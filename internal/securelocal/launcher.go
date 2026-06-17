package securelocal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nikicat/secrets-dispatcher/internal/securebackend"
)

type LaunchConfig struct {
	DesktopUser    string
	BackendUser    string
	HomeBase       string
	Provider       string
	ConfigPath     string
	DBusDaemonPath string
}

type childProcess struct {
	name string
	cmd  *exec.Cmd
}

func (c *LaunchConfig) defaults() error {
	if c.HomeBase == "" {
		c.HomeBase = DefaultHomeBase
	}
	if c.Provider == "" {
		c.Provider = DefaultProvider
	}
	if c.BackendUser == "" && c.DesktopUser != "" {
		c.BackendUser = "secrets-" + c.DesktopUser
	}
	if c.DBusDaemonPath == "" {
		c.DBusDaemonPath = "dbus-daemon"
	}
	return nil
}

func (c LaunchConfig) backendHome() string {
	return filepath.Join(c.HomeBase, c.DesktopUser)
}

func (c LaunchConfig) runtimeDir() string {
	return filepath.Join(DefaultSecureRuntimeBase, c.DesktopUser)
}

func (c LaunchConfig) backendBusPath() string {
	return filepath.Join(c.runtimeDir(), "backend-bus.sock")
}

func RunLauncher(ctx context.Context, cfg LaunchConfig) error {
	if err := cfg.defaults(); err != nil {
		return err
	}
	if geteuidFunc() != 0 {
		return fmt.Errorf("secure-launch requires root")
	}
	if cfg.DesktopUser == "" {
		return fmt.Errorf("--user is required")
	}
	provider, err := securebackend.NewProvider(cfg.Provider)
	if err != nil {
		return err
	}

	desktop, err := userLookupFunc(cfg.DesktopUser)
	if err != nil {
		return fmt.Errorf("lookup desktop user %q: %w", cfg.DesktopUser, err)
	}
	backend, err := userLookupFunc(cfg.BackendUser)
	if err != nil {
		return fmt.Errorf("lookup backend user %q: %w", cfg.BackendUser, err)
	}
	desktopUID, _, err := parseUserIDs(desktop)
	if err != nil {
		return err
	}
	backendUID, backendGID, err := parseUserIDs(backend)
	if err != nil {
		return err
	}
	if backendUID == 0 {
		return fmt.Errorf("backend user %q must not be root", cfg.BackendUser)
	}
	if backendUID == desktopUID {
		return fmt.Errorf("backend user %q must be distinct from desktop user %q", cfg.BackendUser, cfg.DesktopUser)
	}

	if err := prepareRuntimeDir(cfg.runtimeDir(), backendUID, backendGID); err != nil {
		return err
	}
	_ = os.Remove(cfg.backendBusPath())

	busAddress := "unix:path=" + cfg.backendBusPath()
	var children []*childProcess
	defer terminateChildren(children)

	dbusCmd := exec.Command(cfg.DBusDaemonPath, "--session", "--nofork", "--nopidfile", "--address="+busAddress)
	dbusCmd.Stdout = os.Stdout
	dbusCmd.Stderr = os.Stderr
	dbusCmd.Env = backendEnv(cfg.backendHome(), cfg.runtimeDir(), "")
	setCommandCredential(dbusCmd, backendUID, backendGID)
	if err := dbusCmd.Start(); err != nil {
		return fmt.Errorf("start private dbus-daemon: %w", err)
	}
	children = append(children, &childProcess{name: "dbus-daemon", cmd: dbusCmd})
	if err := waitForUnixSocket(ctx, cfg.backendBusPath(), 5*time.Second); err != nil {
		return err
	}

	providerCfg := securebackend.RuntimeConfig{
		BusAddress: busAddress,
		HomeDir:    cfg.backendHome(),
		RuntimeDir: cfg.runtimeDir(),
	}
	providerCmdSpec := provider.StartCommand(providerCfg)
	providerPath, err := exec.LookPath(providerCmdSpec.Path)
	if err != nil {
		return fmt.Errorf("find %s: %w", providerCmdSpec.Path, err)
	}
	providerCmd := exec.Command(providerPath, providerCmdSpec.Args...)
	providerCmd.Stdout = os.Stdout
	providerCmd.Stderr = os.Stderr
	providerCmd.Env = minimalEnv(providerCmdSpec.Env...)
	setCommandCredential(providerCmd, backendUID, backendGID)
	if err := providerCmd.Start(); err != nil {
		return fmt.Errorf("start %s backend: %w", provider.Name(), err)
	}
	children = append(children, &childProcess{name: provider.Name(), cmd: providerCmd})

	return waitForBrokerOrChild(ctx, children, func(ctx context.Context) error {
		return runBroker(ctx, cfg, desktop, backend, cfg.backendBusPath())
	})
}

func prepareRuntimeDir(path string, uid, gid int) error {
	parent := filepath.Dir(path)
	if err := mkdirAllFunc(parent, 0711); err != nil {
		return fmt.Errorf("create runtime parent dir %s: %w", parent, err)
	}
	if err := chownFunc(parent, 0, 0); err != nil {
		return fmt.Errorf("chown runtime parent dir %s: %w", parent, err)
	}
	if err := chmodFunc(parent, 0711); err != nil {
		return fmt.Errorf("chmod runtime parent dir %s: %w", parent, err)
	}
	if err := mkdirAllFunc(path, 0700); err != nil {
		return fmt.Errorf("create runtime dir %s: %w", path, err)
	}
	if err := chownFunc(path, uid, gid); err != nil {
		return fmt.Errorf("chown runtime dir %s: %w", path, err)
	}
	if err := chmodFunc(path, 0700); err != nil {
		return fmt.Errorf("chmod runtime dir %s: %w", path, err)
	}
	return nil
}

func backendEnv(homeDir, runtimeDir, busAddress string) []string {
	env := []string{
		"HOME=" + homeDir,
		"XDG_RUNTIME_DIR=" + runtimeDir,
	}
	if busAddress != "" {
		env = append(env, "DBUS_SESSION_BUS_ADDRESS="+busAddress)
	}
	return minimalEnv(env...)
}

func setCommandCredential(cmd *exec.Cmd, uid, gid int) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
}

func waitForUnixSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for backend bus socket %s", path)
		case <-tick.C:
			if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
				return nil
			}
		}
	}
}

func waitForBrokerOrChild(ctx context.Context, children []*childProcess, run func(context.Context) error) error {
	type result struct {
		name string
		err  error
	}
	resultCh := make(chan result, len(children))
	for _, child := range children {
		go func(child *childProcess) {
			resultCh <- result{name: child.name, err: child.cmd.Wait()}
		}(child)
	}
	brokerCh := make(chan error, 1)
	go func() {
		brokerCh <- run(ctx)
	}()
	select {
	case <-ctx.Done():
		terminateChildren(children)
		return ctx.Err()
	case err := <-brokerCh:
		terminateChildren(children)
		return err
	case result := <-resultCh:
		terminateChildren(children)
		if result.err != nil {
			return fmt.Errorf("%s exited: %w", result.name, result.err)
		}
		return fmt.Errorf("%s exited", result.name)
	}
}

func terminateChildren(children []*childProcess) {
	for _, child := range children {
		if child.cmd.Process != nil {
			_ = child.cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	time.Sleep(100 * time.Millisecond)
	for _, child := range children {
		if child.cmd.Process != nil {
			_ = child.cmd.Process.Kill()
		}
	}
}
