package securelocal

import (
	"context"
	"fmt"
	"log/slog"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/nikicat/secrets-dispatcher/internal/api"
	"github.com/nikicat/secrets-dispatcher/internal/approval"
	"github.com/nikicat/secrets-dispatcher/internal/config"
	"github.com/nikicat/secrets-dispatcher/internal/proxy"
)

const (
	DefaultSecureConfigBase  = "/etc/secrets-dispatcher/secure"
	DefaultSecureRuntimeBase = "/run/secrets-dispatcher"
	DefaultSecureStateBase   = "/var/lib/secrets-dispatcher/secure"
)

type brokerClientProvider struct{}

func (brokerClientProvider) Clients() []proxy.ClientInfo {
	return []proxy.ClientInfo{{Name: "secure-local", SocketPath: "session_bus"}}
}

func (c LaunchConfig) secureConfigPath() string {
	if c.ConfigPath != "" {
		return c.ConfigPath
	}
	return filepath.Join(DefaultSecureConfigBase, c.DesktopUser+".yaml")
}

func (c LaunchConfig) secureStateDir() string {
	return filepath.Join(DefaultSecureStateBase, c.DesktopUser)
}

func runBroker(ctx context.Context, cfg LaunchConfig, desktop, backend *user.User, backendBusPath string) error {
	trustedCfg, err := config.Load(cfg.secureConfigPath())
	if err != nil {
		return fmt.Errorf("load secure-local trusted config: %w", err)
	}
	trustedCfg = trustedCfg.WithDefaults()
	if err := trustedCfg.Validate(); err != nil {
		return fmt.Errorf("secure-local trusted config: %w", err)
	}

	stateDir := cfg.secureStateDir()
	if err := ensureRootStateDir(stateDir); err != nil {
		return err
	}

	level := parseBrokerLogLevel(trustedCfg.Serve.LogLevel)
	approvalMgr, err := newBrokerApprovalManager(trustedCfg, stateDir)
	if err != nil {
		return err
	}

	auth, err := api.NewAuth(stateDir)
	if err != nil {
		return fmt.Errorf("create secure-local API auth: %w", err)
	}

	frontConn, err := connectDesktopSessionBus(desktop)
	if err != nil {
		return fmt.Errorf("connect desktop session bus: %w", err)
	}
	backendConn, err := connectPrivateBackendBus(backend, backendBusPath)
	if err != nil {
		frontConn.Close()
		return fmt.Errorf("connect private backend bus: %w", err)
	}

	upstreamSlowThreshold := time.Duration(*trustedCfg.Serve.UpstreamSlowThreshold)
	p := proxy.New(proxy.Config{
		ClientName:            "secure-local",
		LogLevel:              level,
		Approval:              approvalMgr,
		TrimProcessChain:      *trustedCfg.Serve.TrimProcessChain,
		UpstreamSlowThreshold: upstreamSlowThreshold,
	})
	if err := p.ConnectWith(frontConn, backendConn); err != nil {
		p.Close()
		return err
	}
	defer p.Close()

	apiSocket := filepath.Join(cfg.runtimeDir(), "api.sock")
	apiServer, err := api.NewServerWithProviderAndUnixPeerUIDs("", approvalMgr, brokerClientProvider{}, auth, apiSocket, *trustedCfg.Serve.TrimProcessChain, nil, upstreamSlowThreshold, []uint32{0})
	if err != nil {
		return fmt.Errorf("create secure-local API server: %w", err)
	}
	apiServer.WSHandler().SetNotificationDelay(int(time.Duration(trustedCfg.Serve.NotificationDelay).Milliseconds()))
	if err := apiServer.Start(); err != nil {
		return fmt.Errorf("start secure-local API server: %w", err)
	}
	slog.Info("secure-local API server started", "socket", apiServer.UnixSocketPath, "cookie_file", apiServer.CookieFilePath())
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		apiServer.Shutdown(shutdownCtx)
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- p.Run(ctx)
	}()

	select {
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	case err := <-errCh:
		if err == context.Canceled {
			return err
		}
		return err
	}
}

func ensureRootStateDir(path string) error {
	if err := mkdirAllFunc(path, 0o700); err != nil {
		return fmt.Errorf("create secure-local state dir: %w", err)
	}
	if err := chownFunc(path, 0, 0); err != nil {
		return fmt.Errorf("chown secure-local state dir: %w", err)
	}
	if err := chmodFunc(path, 0o700); err != nil {
		return fmt.Errorf("chmod secure-local state dir: %w", err)
	}
	return nil
}

func newBrokerApprovalManager(cfg *config.Config, stateDir string) (*approval.Manager, error) {
	var trustedSigners []approval.TrustedSigner
	for _, ts := range cfg.Serve.TrustedSigners {
		trustedSigners = append(trustedSigners, approval.TrustedSigner{
			ExePath:    ts.ExePath,
			RepoPath:   ts.RepoPath,
			FilePrefix: ts.FilePrefix,
		})
	}

	var trustRules []approval.TrustRule
	for _, r := range cfg.Serve.Rules {
		tr := approval.TrustRule{
			Name:             r.Name,
			Action:           r.Action,
			RequestTypes:     r.RequestTypes,
			SearchAttributes: r.SearchAttributes,
		}
		if r.Process != nil {
			tr.Process = &approval.ProcessMatcher{
				Exe:  r.Process.Exe,
				Name: r.Process.Name,
				CWD:  r.Process.CWD,
				Unit: r.Process.Unit,
			}
		}
		if r.Secret != nil {
			tr.Secret = &approval.SecretMatcher{
				Collection: r.Secret.Collection,
				Label:      r.Secret.Label,
				Attributes: r.Secret.Attributes,
			}
		}
		trustRules = append(trustRules, tr)
	}

	savedRuleStore := approval.NewFileSavedApprovalRuleStore(stateDir)
	savedRules, err := savedRuleStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load secure-local approval rules: %w", err)
	}

	return approval.NewManager(approval.ManagerConfig{
		Timeout:             time.Duration(cfg.Serve.Timeout),
		HistoryMax:          cfg.Serve.HistoryLimit,
		ApprovalWindow:      time.Duration(cfg.Serve.ApprovalWindow),
		AutoApproveDuration: time.Duration(cfg.Serve.AutoApproveDuration),
		TrustedSigners:      trustedSigners,
		IgnoreChromeDummy:   *cfg.Serve.IgnoreChromeDummySecret,
		TrustRules:          trustRules,
		SavedApprovalRules:  savedRules,
		SavedRulesStore:     savedRuleStore,
	}), nil
}

func parseBrokerLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func minimalEnv(entries ...string) []string {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return append(env, entries...)
}
