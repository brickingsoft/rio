//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package aio

import "net"

func connect(network string, family int, sotype int, proto int, raddr net.Addr, laddr net.Addr, cb OperationCallback) {

	return
}
