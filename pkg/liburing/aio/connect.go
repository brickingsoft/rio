//go:build linux

package aio

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

func Connect(
	ctx context.Context, deadline time.Time,
	network string, proto int, laddr net.Addr, raddr net.Addr,
	control Control,
) (conn *Conn, err error) {
	// addr
	if laddr != nil && reflect.ValueOf(laddr).IsNil() {
		laddr = nil
	}
	if raddr != nil && reflect.ValueOf(raddr).IsNil() {
		raddr = nil
	}
	if laddr == nil && raddr == nil {
		err = errors.New("missing address")
		return
	}
	// network
	sotype := 0
	switch network {
	case "tcp", "tcp4", "tcp6":
		sotype = syscall.SOCK_STREAM
		break
	case "udp", "udp4", "udp6":
		sotype = syscall.SOCK_DGRAM
		break
	case "unix":
		sotype = syscall.SOCK_STREAM
		break
	case "unixpacket":
		sotype = syscall.SOCK_SEQPACKET
		break
	case "unixgram":
		sotype = syscall.SOCK_DGRAM
		break
	default:
		err = errors.New("unsupported network")
		return
	}
	// poller
	if pinErr := Pin(); pinErr != nil {
		err = pinErr
		return
	}
	// family
	family, ipv6only := sys.FavoriteAddrFamily(network, laddr, raddr, "dial")
	// sock
	var (
		sock = -1
	)
	op := AcquireOperation()
	op.PrepareSocket(family, sotype, proto)
	sock, _, err = poller.SubmitAndWait(op)
	ReleaseOperation(op)
	if err != nil {
		Unpin()
		return
	}
	// conn
	conn = &Conn{
		NetFd: NetFd{
			Fd: Fd{
				locker:        sync.Mutex{},
				regular:       -1,
				direct:        sock,
				isStream:      sotype == syscall.SOCK_STREAM,
				zeroReadIsEOF: sotype != syscall.SOCK_DGRAM && sotype != syscall.SOCK_RAW,
				readDeadline:  time.Time{},
				writeDeadline: time.Time{},
			},
			kind:   ConnectedNetFd,
			family: family,
			sotype: sotype,
			net:    network,
			laddr:  nil,
			raddr:  nil,
		},
	}
	if family == syscall.AF_INET || family == syscall.AF_INET6 {
		// ipv6
		if ipv6only {
			if err = conn.SetIpv6only(true); err != nil {
				_ = conn.Close()
				return
			}
		}
		// zero copy
		if err = conn.SetZeroCopy(true); err != nil {
			_ = conn.Close()
			return
		}
		//  broadcast
		if err = conn.SetBroadcast(true); err != nil {
			_ = conn.Close()
			return
		}
	}
	// control
	if control != nil {
		raw, rawErr := conn.SyscallConn()
		if rawErr != nil {
			_ = conn.Close()
			err = rawErr
			return
		}
		var ctrlAddr string
		if raddr != nil {
			ctrlAddr = raddr.String()
		} else if laddr != nil {
			ctrlAddr = laddr.String()
		}
		if err = control(ctx, conn.CtrlNetwork(), ctrlAddr, raw); err != nil {
			_ = conn.Close()
			return
		}
	}
	// bind
	if laddr != nil {
		if err = conn.Bind(laddr); err != nil {
			_ = conn.Close()
			return
		}
	}
	// connect
	if raddr != nil {
		var (
			sa     syscall.Sockaddr
			rsa    *syscall.RawSockaddrAny
			rsaLen int32
		)
		if sa, err = sys.AddrToSockaddr(raddr); err != nil {
			return
		}
		if rsa, rsaLen, err = sys.SockaddrToRawSockaddrAny(sa); err != nil {
			return
		}

		op = AcquireOperationWithDeadline(deadline)
		op.PrepareConnect(conn, rsa, int(rsaLen))
		_, _, err = poller.SubmitAndWait(op)
		ReleaseOperation(op)
		if err != nil {
			_ = conn.Close()
			return
		}
	}
	return
}
