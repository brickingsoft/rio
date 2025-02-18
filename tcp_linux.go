//go:build linux

package rio

import (
	"context"
	"github.com/brickingsoft/rio/pkg/iouring/aio"
	"github.com/brickingsoft/rio/pkg/kernel"
	"github.com/brickingsoft/rio/pkg/sys"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

func ListenTCP(network string, addr *net.TCPAddr) (*TCPListener, error) {
	config := ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{Enable: true},
		UseSendZC:       defaultUseSendZC.Load(),
	}
	ctx := context.Background()
	return config.ListenTCP(ctx, network, addr)
}

func (lc *ListenConfig) ListenTCP(ctx context.Context, network string, addr *net.TCPAddr) (*TCPListener, error) {
	// fd
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: net.UnknownNetworkError(network)}
	}
	if addr == nil {
		addr = &net.TCPAddr{}
	}
	fd, fdErr := newTCPListenerFd(network, addr, lc.FastOpen, lc.MultipathTCP)
	if fdErr != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: fdErr}
	}
	// vortexes
	vortexes, vortexesErr := aio.New(lc.VortexesOptions...)
	if vortexesErr != nil {
		_ = fd.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: vortexesErr}
	}
	// ctx
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	// vortexes start
	vortexes.Start(ctx)
	// sendzc
	useSendZC := lc.UseSendZC
	if useSendZC {
		useSendZC = aio.CheckSendZCEnable()
	}
	// ln
	ln := &TCPListener{
		ctx:             ctx,
		cancel:          cancel,
		fd:              fd,
		vortexes:        vortexes,
		useSendZC:       useSendZC,
		keepAlive:       lc.KeepAlive,
		keepAliveConfig: lc.KeepAliveConfig,
	}
	return ln, nil
}

type TCPListener struct {
	ctx             context.Context
	cancel          context.CancelFunc
	fd              *sys.Fd
	vortexes        *aio.Vortexes
	useSendZC       bool
	keepAlive       time.Duration
	keepAliveConfig net.KeepAliveConfig
}

func (ln *TCPListener) Accept() (conn net.Conn, err error) {
	ctx := ln.ctx
	fd := ln.fd.Socket()
	vortexes := ln.vortexes
	center := vortexes.Center()
	addr := &syscall.RawSockaddrAny{}
	addrLen := syscall.SizeofSockaddrAny
	future := center.PrepareAccept(ctx, fd, addr, addrLen)
	accepted, acceptErr := future.Await(ctx)
	if acceptErr != nil {
		err = &net.OpError{Op: "accept", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: acceptErr}
		return
	}

	cfd := sys.NewFd(ln.fd.Net(), accepted, ln.fd.Family(), ln.fd.SocketType())
	// local addr
	if err = cfd.LoadLocalAddr(); err != nil {
		_ = cfd.Close()
		err = &net.OpError{Op: "accept", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: err}
		return
	}
	// remote addr
	sa, saErr := sys.RawSockaddrAnyToSockaddr(addr)
	if saErr != nil {
		if err = cfd.LoadRemoteAddr(); err != nil {
			_ = cfd.Close()
			err = &net.OpError{Op: "accept", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: err}
			return
		}
	}
	localAddr := sys.SockaddrToAddr(ln.fd.Net(), sa)
	cfd.SetRemoteAddr(localAddr)

	// tcp conn
	side := vortexes.Side()
	cc, cancel := context.WithCancel(ctx)
	tcpConn := &TCPConn{
		connection{
			ctx:          cc,
			cancel:       cancel,
			fd:           cfd,
			useZC:        ln.useSendZC,
			vortex:       side,
			readTimeout:  atomic.Int64{},
			writeTimeout: atomic.Int64{},
		},
	}
	// no delay
	_ = tcpConn.SetNoDelay(true)
	// keepalive
	keepAliveConfig := ln.keepAliveConfig
	if !keepAliveConfig.Enable && ln.keepAlive >= 0 {
		keepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   ln.keepAlive,
		}
	}
	if keepAliveConfig.Enable {
		_ = tcpConn.SetKeepAliveConfig(keepAliveConfig)
	}
	// conn
	conn = tcpConn
	return
}

func (ln *TCPListener) Close() error {
	defer ln.cancel()
	defer func(vortexes *aio.Vortexes) {
		_ = vortexes.Close()
	}(ln.vortexes)
	if err := ln.fd.Close(); err != nil {
		return &net.OpError{Op: "close", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: err}
	}
	return nil
}

func (ln *TCPListener) Addr() net.Addr {
	return ln.fd.LocalAddr()
}

func (ln *TCPListener) checkUseSendZC() {
	if ln.useSendZC {
		ver, verErr := kernel.GetKernelVersion()
		if verErr != nil {
			ln.useSendZC = false
			return
		}
		target := kernel.Version{
			Kernel: ver.Kernel,
			Major:  6,
			Minor:  0,
			Flavor: ver.Flavor,
		}
		if kernel.CompareKernelVersion(*ver, target) < 0 {
			ln.useSendZC = false
		}
	}
}

func newTCPListenerFd(network string, addr *net.TCPAddr, fastOpen int, multipathTCP bool) (fd *sys.Fd, err error) {
	resolveAddr, family, ipv6only, addrErr := sys.ResolveAddr(network, addr.String())
	if addrErr != nil {
		err = addrErr
		return
	}
	// proto
	proto := syscall.IPPROTO_TCP
	if multipathTCP {
		if mp, ok := sys.TryGetMultipathTCPProto(); ok {
			proto = mp
		}
	}
	// fd
	sock, sockErr := sys.NewSocket(family, syscall.SOCK_STREAM, proto)
	if sockErr != nil {
		err = sockErr
		return
	}
	fd = sys.NewFd(network, sock, family, syscall.SOCK_STREAM)
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
	// fast open
	if err = fd.AllowFastOpen(fastOpen); err != nil {
		_ = fd.Close()
		return
	}
	// defer accept
	if err = syscall.SetsockoptInt(sock, syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, 1); err != nil {
		_ = fd.Close()
		err = os.NewSyscallError("setsockopt", err)
		return
	}
	// bind
	if err = fd.Bind(resolveAddr); err != nil {
		_ = fd.Close()
		return
	}
	// listen
	backlog := sys.MaxListenerBacklog()
	if err = syscall.Listen(sock, backlog); err != nil {
		_ = fd.Close()
		err = os.NewSyscallError("listen", err)
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
	return
}

type TCPConn struct {
	connection
}

func (conn *TCPConn) SyscallConn() (syscall.RawConn, error) {
	return newRawConnection(conn.fd), nil
}

func (conn *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	return 0, &net.OpError{Op: "readfrom", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: nil}
}

func (conn *TCPConn) WriteTo(w io.Writer) (int64, error) {
	return 0, &net.OpError{Op: "writeto", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: nil}
}

func (conn *TCPConn) CloseRead() error {
	if err := conn.fd.CloseRead(); err != nil {
		return &net.OpError{Op: "close", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) CloseWrite() error {
	if err := conn.fd.CloseWrite(); err != nil {
		return &net.OpError{Op: "close", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) SetLinger(sec int) error {
	if err := conn.fd.SetLinger(sec); err != nil {
		return &net.OpError{Op: "set", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) SetNoDelay(noDelay bool) error {
	if err := conn.fd.SetNoDelay(noDelay); err != nil {
		return &net.OpError{Op: "set", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) SetKeepAlive(keepalive bool) error {
	if err := conn.fd.SetKeepAlive(keepalive); err != nil {
		return &net.OpError{Op: "set", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) SetKeepAlivePeriod(period time.Duration) error {
	if err := conn.fd.SetKeepAlivePeriod(period); err != nil {
		return &net.OpError{Op: "set", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	if err := conn.fd.SetKeepAliveConfig(config); err != nil {
		return &net.OpError{Op: "set", Net: conn.fd.Net(), Source: conn.fd.LocalAddr(), Addr: conn.fd.RemoteAddr(), Err: err}
	}
	return nil
}

func (conn *TCPConn) MultipathTCP() (bool, error) {
	ok := sys.IsUsingMultipathTCP(conn.fd)
	return ok, nil
}
