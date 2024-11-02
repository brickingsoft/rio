//go:build windows

package sockets

import (
	"golang.org/x/sys/windows"
	"os"
	"syscall"
)

func setDefaultSockopts(s windows.Handle, family, sotype int, ipv6only bool) error {
	if family == syscall.AF_INET6 && sotype != syscall.SOCK_RAW {
		// Allow both IP versions even if the OS default
		// is otherwise. Note that some operating systems
		// never admit this option.
		_ = windows.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolint(ipv6only))
	}
	if (sotype == syscall.SOCK_DGRAM || sotype == syscall.SOCK_RAW) && family != syscall.AF_UNIX && family != syscall.AF_INET6 {
		// Allow broadcast.
		return os.NewSyscallError("setsockopt", windows.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1))
	}
	return nil
}