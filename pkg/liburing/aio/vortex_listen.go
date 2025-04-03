//go:build linux

package aio

import (
	"context"
	"errors"
	"github.com/brickingsoft/rio/pkg/liburing"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
)

func (vortex *Vortex) Listen(ctx context.Context, network string, proto int, addr net.Addr, reusePort bool, control Control) (ln *Listener, err error) {
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
	case "unixpacket":
		sotype = syscall.SOCK_SEQPACKET
		break
	default:
		err = errors.New("unsupported network")
		return
	}

	// family
	family, ipv6only := sys.FavoriteAddrFamily(network, addr, nil, "listen")
	// sock
	var (
		regular = -1
		direct  = -1
	)
	if vortex.directAllocEnabled {
		op := vortex.acquireOperation()
		op.WithDirectAlloc(true).PrepareSocket(family, sotype, proto)
		direct, _, err = vortex.submitAndWait(op)
		vortex.releaseOperation(op)
	} else {
		regular, err = sys.NewSocket(family, sotype, proto)
	}
	if err != nil {
		return
	}
	// backlog
	backlog := sys.MaxListenerBacklog()
	// ln
	ln = &Listener{
		NetFd: NetFd{
			Fd: Fd{
				regular:       regular,
				direct:        direct,
				isStream:      sotype == syscall.SOCK_STREAM,
				zeroReadIsEOF: sotype != syscall.SOCK_DGRAM && sotype != syscall.SOCK_RAW,
				vortex:        vortex,
			},
			family: family,
			sotype: sotype,
			net:    network,
			laddr:  addr,
			raddr:  nil,
		},
		backlog:  backlog,
		acceptFn: nil,
		handler:  nil,
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
	// reuse addr
	if err = ln.SetReuseAddr(true); err != nil {
		_ = ln.Close()
		return
	}
	// tcp defer accept
	if tcpDeferAccept {
		if err = ln.SetTCPDeferAccept(true); err != nil {
			_ = ln.Close()
			return
		}
	}
	// reuse port
	if reusePort && addrPort > 0 {
		if err = ln.SetReusePort(addrPort); err != nil {
			_ = ln.Close()
			return
		}
		if err = ln.SetCBPF(runtime.NumCPU()); err != nil {
			_ = ln.Close()
			return
		}
	}
	// control
	if control != nil {
		if regular == -1 {
			if regular, err = vortex.fixedFdInstall(direct); err == nil {
				_ = ln.Close()
				return
			}
			ln.regular = regular
		}
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
	if liburing.VersionEnable(6, 11, 0) && ln.Registered() {
		op := ln.vortex.acquireOperation()
		op.PrepareListen(ln, backlog)
		_, _, err = ln.vortex.submitAndWait(op)
		ln.vortex.releaseOperation(op)
		if err != nil {
			_ = ln.Close()
			return
		}
	} else {
		if !ln.Installed() {
			if err = ln.Install(); err != nil {
				_ = ln.Close()
				return
			}
		}
		if err = syscall.Listen(ln.regular, backlog); err != nil {
			_ = ln.Close()
			err = os.NewSyscallError("listen", err)
			return
		}
	}
	// init
	ln.init()
	return
}

func (vortex *Vortex) ListenPacket(ctx context.Context, network string, proto int, addr net.Addr, ifi *net.Interface, reusePort bool, control Control) (conn *Conn, err error) {
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

	// family
	family, ipv6only := sys.FavoriteAddrFamily(network, addr, nil, "listen")
	// sock
	var (
		regular = -1
		direct  = -1
	)
	if vortex.directAllocEnabled {
		op := vortex.acquireOperation()
		op.WithDirectAlloc(true).PrepareSocket(family, sotype, proto)
		direct, _, err = vortex.submitAndWait(op)
		vortex.releaseOperation(op)
	} else {
		regular, err = sys.NewSocket(family, sotype, proto)
	}
	if err != nil {
		return
	}
	// conn
	conn = &Conn{
		NetFd: NetFd{
			Fd: Fd{
				regular:       regular,
				direct:        direct,
				isStream:      sotype == syscall.SOCK_STREAM,
				zeroReadIsEOF: sotype != syscall.SOCK_DGRAM && sotype != syscall.SOCK_RAW,
				vortex:        vortex,
			},
			family: family,
			sotype: sotype,
			net:    network,
			laddr:  addr,
			raddr:  nil,
		},
		sendZCEnabled:    vortex.sendZCEnabled,
		sendMSGZCEnabled: vortex.sendMSGZCEnabled,
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
	// reuse addr
	if err = conn.SetReuseAddr(true); err != nil {
		_ = conn.Close()
		return
	}
	//  broadcast
	if err = conn.SetBroadcast(true); err != nil {
		_ = conn.Close()
		return
	}
	// reuse port
	if reusePort && addrPort > 0 {
		if err = conn.SetReusePort(addrPort); err != nil {
			_ = conn.Close()
			return
		}
		if err = conn.SetCBPF(runtime.NumCPU()); err != nil {
			_ = conn.Close()
			return
		}
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
	// control
	if control != nil {
		if regular == -1 {
			if regular, err = vortex.fixedFdInstall(direct); err == nil {
				_ = conn.Close()
				return
			}
			conn.regular = regular
		}
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
	// init
	conn.init()
	return
}
