//go:build linux

package sys

import (
	"errors"
	"sync"
	"syscall"

	"github.com/brickingsoft/rio/pkg/liburing"
	"golang.org/x/sys/unix"
)

const (
	_MPTCP_INFO = 0x1
)

var (
	mptcpOnce      sync.Once
	mptcpAvailable bool
	hasSOLMPTCP    bool
)

func TryGetMultipathTCPProto() (int, bool) {
	if supportsMultipathTCP() {
		return unix.IPPROTO_MPTCP, true
	}
	return 0, false
}

func supportsMultipathTCP() bool {
	mptcpOnce.Do(initMPTCPavailable)
	return mptcpAvailable
}

func initMPTCPavailable() {
	family := syscall.AF_INET
	if !supportsIPv4() {
		family = syscall.AF_INET6
	}
	s, err := syscall.Socket(family, syscall.SOCK_STREAM, unix.IPPROTO_MPTCP)
	switch {
	case errors.Is(err, syscall.EPROTONOSUPPORT):
	case errors.Is(err, syscall.EINVAL):
	case err == nil:
		_ = syscall.Close(s)
		fallthrough
	default:
		mptcpAvailable = true
	}
	hasSOLMPTCP = liburing.VersionEnable(5, 16, 0)
}

func hasFallenBack(fd int) bool {
	_, err := syscall.GetsockoptInt(fd, unix.SOL_MPTCP, _MPTCP_INFO)
	return err == syscall.EOPNOTSUPP || err == syscall.ENOPROTOOPT
}

func isUsingMPTCPProto(fd int) bool {
	proto, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
	return proto == unix.IPPROTO_MPTCP
}

func IsUsingMultipathTCP(fd int) bool {
	if hasSOLMPTCP {
		return !hasFallenBack(fd)
	}
	return isUsingMPTCPProto(fd)
}
