package securelocal

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	BusFDHelperCommand = "secure-launch-connect-bus"
	busFDHelperFD      = 3
)

func connectDesktopSessionBus(desktop *user.User) (*dbus.Conn, error) {
	uid, gid, err := parseUserIDs(desktop)
	if err != nil {
		return nil, err
	}
	busPath := "/run/user/" + desktop.Uid + "/bus"
	return connectUnixBusAsUser(busPath, uid, gid)
}

func connectPrivateBackendBus(backend *user.User, busPath string) (*dbus.Conn, error) {
	uid, gid, err := parseUserIDs(backend)
	if err != nil {
		return nil, err
	}
	return connectUnixBusAsUser(busPath, uid, gid)
}

func connectUnixBusAsUser(busPath string, uid, gid int) (*dbus.Conn, error) {
	uconn, err := dialUnixBusAsUser(busPath, uid, gid)
	if err != nil {
		return nil, err
	}
	conn, err := dbus.ConnectUnix(uconn)
	if err != nil {
		_ = uconn.Close()
		return nil, err
	}
	return conn, nil
}

func dialUnixBusAsUser(busPath string, uid, gid int) (*net.UnixConn, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create helper socketpair: %w", err)
	}
	parentFD := pair[0]
	childFD := pair[1]
	defer unix.Close(parentFD)

	childFile := os.NewFile(uintptr(childFD), "bus-fd-helper")
	defer childFile.Close()

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable for bus helper: %w", err)
	}
	cmd := exec.Command(exe, BusFDHelperCommand, busPath)
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start bus helper: %w", err)
	}
	_ = childFile.Close()

	fd, recvErr := recvUnixFD(parentFD)
	waitErr := cmd.Wait()
	if recvErr != nil {
		return nil, helperProcessError("receive bus fd", recvErr, waitErr, stderr.String())
	}
	if waitErr != nil {
		_ = unix.Close(fd)
		return nil, helperProcessError("bus helper failed", waitErr, nil, stderr.String())
	}

	uconn, err := unixConnFromFD(fd)
	if err != nil {
		return nil, fmt.Errorf("wrap bus fd: %w", err)
	}
	return uconn, nil
}

func helperProcessError(action string, primary, secondary error, stderr string) error {
	msg := strings.TrimSpace(stderr)
	if secondary != nil {
		if msg != "" {
			return fmt.Errorf("%s: %w; helper exited: %v: %s", action, primary, secondary, msg)
		}
		return fmt.Errorf("%s: %w; helper exited: %v", action, primary, secondary)
	}
	if msg != "" {
		return fmt.Errorf("%s: %w: %s", action, primary, msg)
	}
	return fmt.Errorf("%s: %w", action, primary)
}

func RunBusFDHelper(busPath string) error {
	if busPath == "" {
		return fmt.Errorf("bus path is required")
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create bus socket: %w", err)
	}
	defer unix.Close(fd)

	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: busPath}); err != nil {
		return fmt.Errorf("connect bus %s: %w", busPath, err)
	}
	if err := sendUnixFD(busFDHelperFD, fd); err != nil {
		return fmt.Errorf("send bus fd: %w", err)
	}
	return nil
}

func sendUnixFD(sockFD, fd int) error {
	return unix.Sendmsg(sockFD, []byte{0}, unix.UnixRights(fd), nil, 0)
}

func recvUnixFD(sockFD int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, msg := range msgs {
		fds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			continue
		}
		if len(fds) == 0 {
			continue
		}
		for _, extraFD := range fds[1:] {
			_ = unix.Close(extraFD)
		}
		return fds[0], nil
	}
	return -1, fmt.Errorf("helper did not send a file descriptor")
}

func unixConnFromFD(fd int) (*net.UnixConn, error) {
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "dbus-bus")
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("fd is %T, want *net.UnixConn", conn)
	}
	return uconn, nil
}
