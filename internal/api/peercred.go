package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/nikicat/secrets-dispatcher/internal/approval"
	"github.com/nikicat/secrets-dispatcher/internal/procutil"
)

type connContextKey struct{}

// connContext returns a ConnContext function for http.Server that stores
// the net.Conn in the request context. This allows handlers to retrieve
// the underlying connection (e.g., for Unix socket peer credentials).
func connContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connContextKey{}, c)
}

func unixPeerCredentials(ctx context.Context) (*unix.Ucred, bool) {
	c, ok := ctx.Value(connContextKey{}).(net.Conn)
	if !ok || c == nil {
		return nil, false
	}

	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, false
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, false
	}

	var cred *unix.Ucred
	var credErr error
	raw.Control(func(fd uintptr) { //nolint:errcheck
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if credErr != nil || cred == nil {
		return nil, false
	}
	return cred, true
}

func requireUnixPeerUIDs(next http.Handler, allowedUIDs []uint32) http.Handler {
	allowed := make(map[uint32]struct{}, len(allowedUIDs))
	for _, uid := range allowedUIDs {
		allowed[uid] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, ok := unixPeerCredentials(r.Context())
		if !ok {
			writeError(w, "Unix peer credentials required", http.StatusForbidden)
			return
		}
		if _, ok := allowed[uint32(cred.Uid)]; !ok {
			writeError(w, "Unix peer UID not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolvePeerInfo extracts peer credentials from a Unix socket connection
// in the request context and resolves the user-facing process that invoked
// git commit.
//
// Process chain example: claude → zsh → git → secrets-dispatcher → (HTTP)
// We walk up from the peer PID, skip the thin client and git, then skip
// any intermediate shells to find the real invoker (e.g., "claude").
func resolvePeerInfo(ctx context.Context, trimAtSessionLeader bool) approval.SenderInfo {
	cred, ok := unixPeerCredentials(ctx)
	if !ok {
		return approval.SenderInfo{}
	}

	// Build the process chain from peer up to init.
	chain := procutil.ReadProcessChain(cred.Pid, trimAtSessionLeader)

	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		labels := make([]string, len(chain))
		for i, p := range chain {
			labels[i] = fmt.Sprintf("%s[%d]", p.Comm, p.PID)
		}
		slog.Debug("process chain", "chain", strings.Join(labels, " → "))
	}

	// chain[0] = thin client, chain[1] = git, chain[2+] = ancestors.
	// Start from git's parent and skip shells.
	invoker := chain[0] // fallback to peer
	for i := 2; i < len(chain); i++ {
		invoker = chain[i]
		if !procutil.IsShell(chain[i].Comm) {
			break
		}
	}

	// Convert the full chain to ProcessChain for the API,
	// filtering out our own binary (the thin client).
	selfExe, _ := os.Executable()

	// The peer (chain[0]) is the process that opened the socket. When it is our
	// own binary, the request came through our gpg-sign thin client, so the
	// repo/changed-file fields it reported were computed by our trusted code —
	// see approval.SenderInfo.PeerTrusted / Manager.CheckTrustedSigner.
	peerTrusted := len(chain) > 0 && selfExe != "" && chain[0].Exe == selfExe

	processChain := make([]approval.ProcessInfo, 0, len(chain))
	for _, p := range chain {
		if selfExe != "" && p.Exe == selfExe {
			continue
		}
		processChain = append(processChain, approval.ProcessInfo{
			Name: p.Comm,
			PID:  uint32(p.PID),
			Exe:  p.Exe,
			Args: p.Args,
			CWD:  p.CWD,
		})
	}

	return approval.SenderInfo{
		PID:          uint32(invoker.PID),
		UID:          uint32(cred.Uid),
		InvokerName:  invoker.Comm,
		ProcessChain: processChain,
		PeerTrusted:  peerTrusted,
	}
}
