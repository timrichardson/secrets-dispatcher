package dbusconn

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/godbus/dbus/v5"
)

const (
	// BackendFDEnv names the inherited file descriptor used for secure-local upstream D-Bus traffic.
	BackendFDEnv = "SECRETS_DISPATCHER_BACKEND_FD"
	// BackendAuthUIDEnv optionally overrides the EXTERNAL auth UID sent on the inherited connection.
	BackendAuthUIDEnv = "SECRETS_DISPATCHER_BACKEND_AUTH_UID"
)

// ConnectInheritedEnv opens a D-Bus connection using the file descriptor named by BackendFDEnv.
func ConnectInheritedEnv() (*dbus.Conn, error) {
	fd, err := inheritedFDFromEnv()
	if err != nil {
		return nil, err
	}
	return ConnectInheritedFD(fd, os.Getenv(BackendAuthUIDEnv))
}

func inheritedFDFromEnv() (int, error) {
	raw := os.Getenv(BackendFDEnv)
	if raw == "" {
		return -1, fmt.Errorf("%s is not set", BackendFDEnv)
	}
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 0 {
		return -1, fmt.Errorf("%s must be a non-negative integer", BackendFDEnv)
	}
	return fd, nil
}

// ConnectInheritedFD wraps an already-connected Unix socket FD as a D-Bus connection.
func ConnectInheritedFD(fd int, authUID string) (*dbus.Conn, error) {
	file := os.NewFile(uintptr(fd), fmt.Sprintf("inherited-dbus-fd-%d", fd))
	if file == nil {
		return nil, fmt.Errorf("invalid inherited fd %d", fd)
	}
	defer file.Close()

	netConn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("wrap inherited fd %d: %w", fd, err)
	}

	unixConn, ok := netConn.(*net.UnixConn)
	if !ok {
		netConn.Close()
		return nil, fmt.Errorf("inherited fd %d is %T, want Unix socket", fd, netConn)
	}

	var opts []dbus.ConnOption
	if authUID != "" {
		opts = append(opts, dbus.WithAuth(dbus.AuthExternal(authUID)))
	}
	conn, err := dbus.ConnectUnix(unixConn, opts...)
	if err != nil {
		unixConn.Close()
		return nil, fmt.Errorf("connect inherited D-Bus fd %d: %w", fd, err)
	}
	return conn, nil
}
