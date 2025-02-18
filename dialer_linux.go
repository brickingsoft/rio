//go:build linux

package rio

import (
	"context"
	"errors"
	"github.com/brickingsoft/rio/pkg/iouring"
	"github.com/brickingsoft/rio/pkg/iouring/aio"
	"github.com/brickingsoft/rio/pkg/sys"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func Dial(network string, address string) (net.Conn, error) {
	ctx := context.Background()
	return DialContext(ctx, network, address)
}

func DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	return DefaultDialer().Dial(ctx, network, address)
}

var (
	defaultDialer     = &Dialer{}
	defaultDialerOnce = sync.Once{}
)

func DefaultDialer() *Dialer {
	defaultDialerOnce.Do(func() {
		vortexes, vortexesErr := aio.New(aio.WithEntries(iouring.DefaultEntries))
		if vortexesErr != nil {
			panic(vortexesErr)
		}
		vortexes.Start(context.Background())

		defaultDialer = &Dialer{}
		defaultDialer.Timeout = 15 * time.Second
		defaultDialer.KeepAliveConfig.Enable = true
		defaultDialer.UseSendZC = defaultUseSendZC.Load()
		defaultDialer.SetFastOpen(256)
		defaultDialer.SetVortexes(vortexes)

		runtime.SetFinalizer(defaultDialer, func(d *Dialer) {
			_ = d.vortexes.Close()
		})
	})
	return defaultDialer
}

type Dialer struct {
	Timeout         time.Duration
	Deadline        time.Time
	KeepAlive       time.Duration
	KeepAliveConfig net.KeepAliveConfig
	MultipathTCP    bool
	FastOpen        int
	UseSendZC       bool
	vortexes        *aio.Vortexes
}

func (d *Dialer) SetFastOpen(n int) {
	if n < 1 {
		return
	}
	if n > 999 {
		n = 256
	}
	d.FastOpen = n
}

func (d *Dialer) SetMultipathTCP(use bool) {
	d.MultipathTCP = use
}

func (d *Dialer) SetVortexes(v *aio.Vortexes) {
	d.vortexes = v
	return
}

func (d *Dialer) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.Timeout != 0 {
		earliest = now.Add(d.Timeout)
	}
	if deadline, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, deadline)
	}
	return minNonzeroTime(earliest, d.Deadline)
}

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func (d *Dialer) Dial(ctx context.Context, network string, address string) (conn net.Conn, err error) {
	addr, _, _, addrErr := sys.ResolveAddr(network, address)
	if addrErr != nil {
		err = &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: addrErr}
		return
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		conn, err = d.DialTCP(ctx, network, nil, a)
		break
	case *net.UDPAddr:
		conn, err = d.DialUDP(ctx, network, nil, a)
		break
	case *net.UnixAddr:
		conn, err = d.DialUnix(ctx, network, nil, a)
		break
	case *net.IPAddr:
		conn, err = d.DialIP(ctx, network, nil, a)
		break
	default:
		err = &net.OpError{Op: "dial", Net: network, Source: nil, Addr: addr, Err: &net.AddrError{Err: "unexpected address type", Addr: address}}
		break
	}
	return
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*TCPConn, error) {
	ctx := context.Background()
	return DefaultDialer().DialTCP(ctx, network, laddr, raddr)
}

func (d *Dialer) DialTCP(ctx context.Context, network string, laddr, raddr *net.TCPAddr) (*TCPConn, error) {
	// fd
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: net.UnknownNetworkError(network)}
	}
	if raddr == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: errors.New("missing address")}
	}
	proto := syscall.IPPROTO_TCP
	if d.MultipathTCP {
		if mp, ok := sys.TryGetMultipathTCPProto(); ok {
			proto = mp
		}
	}
	fd, fdErr := newDialerFd(network, laddr, raddr, syscall.SOCK_STREAM, proto, d.FastOpen)
	if fdErr != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: fdErr}
	}

	// connect
	sa, saErr := sys.AddrToSockaddr(raddr)
	if saErr != nil {
		_ = fd.Close()
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: saErr}
	}
	rsa, rsaLen, rsaErr := sys.SockaddrToRawSockaddrAny(sa)
	if rsaErr != nil {
		_ = fd.Close()
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: rsaErr}
	}
	vortex := d.vortexes.Center()
	future := vortex.PrepareConnect(ctx, fd.Socket(), rsa, int(rsaLen))
	_, err := future.Await(ctx)
	if err != nil {
		_ = fd.Close()
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: err}
	}
	// local addr
	if laddr != nil {
		fd.SetLocalAddr(laddr)
	} else {
		sa, saErr = sys.RawSockaddrAnyToSockaddr(rsa)
		if saErr != nil {
			_ = fd.LoadLocalAddr()
		} else {
			la := sys.SockaddrToAddr(network, sa)
			if la != nil {
				fd.SetLocalAddr(la)
			} else {
				_ = fd.LoadLocalAddr()
			}
		}
	}
	// remote addr
	if raddrErr := fd.LoadRemoteAddr(); raddrErr != nil {
		fd.SetRemoteAddr(raddr)
	}
	// conn
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)

	side := d.vortexes.Center()

	useSendZC := d.UseSendZC
	if useSendZC {
		useSendZC = aio.CheckSendZCEnable()
	}

	conn := &TCPConn{
		connection{
			ctx:          ctx,
			cancel:       cancel,
			fd:           fd,
			vortex:       side,
			readTimeout:  atomic.Int64{},
			writeTimeout: atomic.Int64{},
			useZC:        useSendZC,
		},
	}
	_ = conn.SetNoDelay(true)
	// keepalive
	keepAliveConfig := d.KeepAliveConfig
	if !keepAliveConfig.Enable && d.KeepAlive >= 0 {
		keepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   d.KeepAlive,
		}
	}
	if keepAliveConfig.Enable {
		_ = conn.SetKeepAliveConfig(keepAliveConfig)
	}
	return conn, nil
}

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*UDPConn, error) {
	ctx := context.Background()
	return DefaultDialer().DialUDP(ctx, network, laddr, raddr)
}

func (d *Dialer) DialUDP(ctx context.Context, network string, laddr, raddr *net.UDPAddr) (*UDPConn, error) {
	return nil, nil
}

func DialUnix(network string, laddr, raddr *net.UnixAddr) (*UnixConn, error) {
	ctx := context.Background()
	return DefaultDialer().DialUnix(ctx, network, laddr, raddr)
}

func (d *Dialer) DialUnix(ctx context.Context, network string, laddr, raddr *net.UnixAddr) (*UnixConn, error) {
	return nil, nil
}

func DialIP(network string, laddr, raddr *net.IPAddr) (*IPConn, error) {
	ctx := context.Background()
	return DefaultDialer().DialIP(ctx, network, laddr, raddr)
}

func (d *Dialer) DialIP(ctx context.Context, network string, laddr, raddr *net.IPAddr) (*IPConn, error) {
	return nil, nil
}

func newDialerFd(network string, laddr net.Addr, raddr net.Addr, sotype int, proto int, fastOpen int) (fd *sys.Fd, err error) {
	if raddr == nil && laddr == nil {
		err = errors.New("missing address")
		return
	}
	addr := raddr
	if raddr == nil {
		addr = laddr
	}
	resolveAddr, family, ipv6only, addrErr := sys.ResolveAddr(network, addr.String())
	if addrErr != nil {
		err = addrErr
		return
	}
	// fd
	sock, sockErr := sys.NewSocket(family, sotype, proto)
	if sockErr != nil {
		err = sockErr
		return
	}
	fd = sys.NewFd(network, sock, family, sotype)
	// ipv6
	if ipv6only {
		if err = fd.SetIpv6only(true); err != nil {
			_ = fd.Close()
			return
		}
	}
	// reuse addr
	if err = fd.AllowReuseAddr(); err != nil {
		_ = fd.Close()
		return
	}
	// broadcast
	if err = fd.AllowBroadcast(); err != nil {
		_ = fd.Close()
		return
	}
	// fast open
	if err = fd.AllowFastOpen(fastOpen); err != nil {
		_ = fd.Close()
		return
	}
	// bind
	if !reflect.ValueOf(laddr).IsNil() {
		if err = fd.Bind(resolveAddr); err != nil {
			_ = fd.Close()
			return
		}
		// set socket addr
		if sn, getSockNameErr := syscall.Getsockname(sock); getSockNameErr == nil {
			if sockname := sys.SockaddrToAddr(network, sn); sockname != nil {
				fd.SetLocalAddr(sockname)
			} else {
				fd.SetLocalAddr(resolveAddr)
			}
		} else {
			fd.SetLocalAddr(resolveAddr)
		}
	}
	return
}
