package securelocal

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/nikicat/secrets-dispatcher/internal/dbusconn"
	"github.com/nikicat/secrets-dispatcher/internal/securebackend"
)

type LaunchConfig struct {
	DesktopUser    string
	BackendUser    string
	HomeBase       string
	Provider       string
	ConfigPath     string
	BinaryPath     string
	DBusDaemonPath string
	BackendAuthUID string
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
	if c.BinaryPath == "" {
		path, err := executableFunc()
		if err != nil {
			return fmt.Errorf("find current executable: %w", err)
		}
		if resolved, err := evalSymlinksFunc(path); err == nil {
			path = resolved
		}
		c.BinaryPath = path
	}
	if c.DBusDaemonPath == "" {
		c.DBusDaemonPath = "dbus-daemon"
	}
	if c.BackendAuthUID == "" {
		c.BackendAuthUID = strconv.Itoa(geteuidFunc())
	}
	return nil
}

func (c LaunchConfig) backendHome() string {
	return filepath.Join(c.HomeBase, c.DesktopUser)
}

func (c LaunchConfig) runtimeDir() string {
	return filepath.Join("/run", "secrets-dispatcher", c.DesktopUser)
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
	desktopUID, desktopGID, err := parseUserIDs(desktop)
	if err != nil {
		return err
	}
	backendUID, backendGID, err := parseUserIDs(backend)
	if err != nil {
		return err
	}

	if cfg.ConfigPath == "" {
		cfg.ConfigPath = filepath.Join(desktop.HomeDir, ".config", "secrets-dispatcher", "config.yaml")
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
	providerCmd.Env = mergeEnv(os.Environ(), providerCmdSpec.Env)
	setCommandCredential(providerCmd, backendUID, backendGID)
	if err := providerCmd.Start(); err != nil {
		return fmt.Errorf("start %s backend: %w", provider.Name(), err)
	}
	children = append(children, &childProcess{name: provider.Name(), cmd: providerCmd})

	backendFD, backendConn, err := dialBackendFD(ctx, cfg.backendBusPath(), 5*time.Second)
	if err != nil {
		return err
	}
	defer backendFD.Close()
	defer backendConn.Close()

	proxyCmd := exec.Command(cfg.BinaryPath, "serve", "--config", cfg.ConfigPath)
	proxyCmd.Stdout = os.Stdout
	proxyCmd.Stderr = os.Stderr
	proxyCmd.Env = mergeEnv(os.Environ(), []string{
		"HOME=" + desktop.HomeDir,
		"XDG_RUNTIME_DIR=/run/user/" + desktop.Uid,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + desktop.Uid + "/bus",
		dbusconn.BackendFDEnv + "=3",
		dbusconn.BackendAuthUIDEnv + "=" + cfg.BackendAuthUID,
	})
	proxyCmd.ExtraFiles = []*os.File{backendFD}
	setCommandCredential(proxyCmd, desktopUID, desktopGID)
	if err := proxyCmd.Start(); err != nil {
		return fmt.Errorf("start secure-local proxy: %w", err)
	}
	children = append(children, &childProcess{name: "proxy", cmd: proxyCmd})
	backendFD.Close()
	backendConn.Close()

	return waitForChildren(ctx, children)
}

func prepareRuntimeDir(path string, uid, gid int) error {
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
	return mergeEnv(os.Environ(), env)
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

func dialBackendFD(ctx context.Context, path string, timeout time.Duration) (*os.File, net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("connect private backend bus: %w", err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("backend connection is %T, want Unix socket", conn)
	}
	file, err := unixConn.File()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("convert backend connection to file: %w", err)
	}
	return file, conn, nil
}

func waitForChildren(ctx context.Context, children []*childProcess) error {
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
	select {
	case <-ctx.Done():
		terminateChildren(children)
		return ctx.Err()
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

func mergeEnv(base, overrides []string) []string {
	merged := append([]string{}, base...)
	index := make(map[string]int, len(merged))
	for i, entry := range merged {
		if key, _, ok := splitEnv(entry); ok {
			index[key] = i
		}
	}
	for _, entry := range overrides {
		key, _, ok := splitEnv(entry)
		if !ok {
			continue
		}
		if i, exists := index[key]; exists {
			merged[i] = entry
		} else {
			index[key] = len(merged)
			merged = append(merged, entry)
		}
	}
	return merged
}

func splitEnv(entry string) (string, string, bool) {
	for i, r := range entry {
		if r == '=' {
			return entry[:i], entry[i+1:], true
		}
	}
	return "", "", false
}
