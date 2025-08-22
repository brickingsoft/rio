//go:build linux

package aio

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

type Control func(ctx context.Context, network string, address string, raw syscall.RawConn) error

func Listen(ctx context.Context, network string, proto int, addr net.Addr, reusePort bool, control Control) (ln *Listener, err error) {
	// addr
	if addr != nil && reflect.ValueOf(addr).IsNil() {
		addr = nil
	}
	if addr == nil {
		err = errors.New("missing address")
		return
	}
	// network
	tcpDeferAccept := false
	sotype := 0
	addrPort := 0
	switch network {
	case "tcp", "tcp4", "tcp6":
		sotype = syscall.SOCK_STREAM
		tcpDeferAccept = true
		tcpAddr := addr.(*net.TCPAddr)
		addrPort = tcpAddr.Port
		break
	case "unix":
		sotype = syscall.SOCK_STREAM
		break
	case "unixpacket":
		sotype = syscall.SOCK_SEQPACKET
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
	family, ipv6only := sys.FavoriteAddrFamily(network, addr, nil, "listen")
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

	// backlog
	backlog := sys.MaxListenerBacklog()
	// ln
	ln = &Listener{
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
			kind:   ListenedNetFd,
			family: family,
			sotype: sotype,
			net:    network,
			laddr:  addr,
			raddr:  nil,
		},
	}
	if family == syscall.AF_INET || family == syscall.AF_INET6 {
		// reuse addr
		if err = ln.SetReuseAddr(true); err != nil {
			_ = ln.Close()
			return
		}
		// reuse port
		if reusePort && addrPort > 0 {
			if err = ln.SetReusePort(true); err != nil {
				_ = ln.Close()
				return
			}
			// todo: fix cbpf enabled will disable reuse port
			//if err = ln.SetCBPF(runtime.NumCPU()); err != nil {
			//	_ = ln.Close()
			//	return
			//}
		}
		// ipv6
		if ipv6only {
			if err = ln.SetIpv6only(true); err != nil {
				_ = ln.Close()
				return
			}
		}
		// zero copy
		if err = ln.SetZeroCopy(true); err != nil {
			_ = ln.Close()
			return
		}
		// tcp defer acceptOneshot
		if tcpDeferAccept {
			if err = ln.SetTCPDeferAccept(true); err != nil {
				_ = ln.Close()
				return
			}
		}

	}
	// control
	if control != nil {
		raw, rawErr := ln.SyscallConn()
		if rawErr != nil {
			_ = ln.Close()
			err = rawErr
			return
		}
		if err = control(ctx, ln.CtrlNetwork(), addr.String(), raw); err != nil {
			_ = ln.Close()
			return
		}
	}
	// bind
	if err = ln.Bind(addr); err != nil {
		_ = ln.Close()
		return
	}
	// listen
	op = AcquireOperation()
	op.PrepareListen(ln, backlog)
	_, _, err = poller.SubmitAndWait(op)
	ReleaseOperation(op)
	if err != nil {
		_ = ln.Close()
		return
	}
	return
}

func ListenPacket(ctx context.Context, network string, proto int, addr net.Addr, ifi *net.Interface, reusePort bool, control Control) (conn *Conn, err error) {
	// addr
	if addr != nil && reflect.ValueOf(addr).IsNil() {
		addr = nil
	}
	if addr == nil {
		err = errors.New("missing address")
		return
	}
	// network
	sotype := 0
	addrPort := 0
	switch network {
	case "udp", "udp4", "udp6":
		sotype = syscall.SOCK_DGRAM
		udpAddr := addr.(*net.UDPAddr)
		addrPort = udpAddr.Port
		if udpAddr.IP != nil && udpAddr.IP.IsMulticast() {
			localUdpAddr := *udpAddr
			if strings.HasSuffix(network, "6") {
				localUdpAddr.IP = net.IPv6zero
			} else {
				localUdpAddr.IP = net.IPv4zero.To4()
			}
			addr = &localUdpAddr
		}
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
	family, ipv6only := sys.FavoriteAddrFamily(network, addr, nil, "listen")
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
			kind:   ListenedNetFd,
			family: family,
			sotype: sotype,
			net:    network,
			laddr:  addr,
			raddr:  nil,
		},
	}
	if family == syscall.AF_INET || family == syscall.AF_INET6 {
		// reuse addr
		if err = conn.SetReuseAddr(true); err != nil {
			_ = conn.Close()
			return
		}
		// reuse port
		if reusePort && addrPort > 0 {
			if err = conn.SetReusePort(true); err != nil {
				_ = conn.Close()
				return
			}
			// todo: fix cbpf enabled will disable reuse port
			//if err = conn.SetCBPF(runtime.NumCPU()); err != nil {
			//	_ = conn.Close()
			//	return
			//}
		}
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

		// multicast
		if ifi != nil {
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				_ = conn.Close()
				err = errors.New("has ifi but addr is not udp addr")
				return
			}
			if ip4 := udpAddr.IP.To4(); ip4 != nil {
				if err = conn.SetIPv4MulticastInterface(ifi); err != nil {
					_ = conn.Close()
					return
				}
				if err = conn.SetIPv4MulticastLoopback(false); err != nil {
					_ = conn.Close()
					return
				}
				if err = conn.JoinIPv4Group(ifi, ip4); err != nil {
					_ = conn.Close()
					return
				}
			} else {
				if err = conn.SetIPv6MulticastInterface(ifi); err != nil {
					_ = conn.Close()
					return
				}
				if err = conn.SetIPv6MulticastLoopback(false); err != nil {
					_ = conn.Close()
					return
				}
				if err = conn.JoinIPv6Group(ifi, udpAddr.IP); err != nil {
					_ = conn.Close()
					return
				}
			}
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
		if err = control(ctx, conn.CtrlNetwork(), addr.String(), raw); err != nil {
			_ = conn.Close()
			return
		}
	}
	// bind
	if err = conn.Bind(addr); err != nil {
		_ = conn.Close()
		return
	}
	return
}
