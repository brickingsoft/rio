//go:build linux

package rio

import (
	"context"
	"errors"
	"github.com/brickingsoft/rio/pkg/cbpf"
	"github.com/brickingsoft/rio/pkg/iouring/aio"
	"github.com/brickingsoft/rio/pkg/iouring/aio/sys"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

// ListenTCP acts like [Listen] for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenTCP listens on all available unicast and anycast IP addresses
// of the local system.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ListenTCP(network string, addr *net.TCPAddr) (*TCPListener, error) {
	config := ListenConfig{
		Control:         nil,
		KeepAlive:       0,
		KeepAliveConfig: net.KeepAliveConfig{Enable: true},
		MultipathTCP:    false,
		ReusePort:       true,
	}
	ctx := context.Background()
	return config.ListenTCP(ctx, network, addr)
}

// ListenTCP acts like [Listen] for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenTCP listens on all available unicast and anycast IP addresses
// of the local system.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func (lc *ListenConfig) ListenTCP(ctx context.Context, network string, addr *net.TCPAddr) (*TCPListener, error) {
	// check multishot accept
	if lc.MultishotAccept {
		lc.MultishotAccept = aio.CheckMultishotAcceptEnable()
	}
	// network
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: net.UnknownNetworkError(network)}
	}
	if addr == nil {
		addr = &net.TCPAddr{}
	}
	// vortex
	vortex := lc.Vortex
	if vortex == nil {
		var vortexErr error
		vortex, vortexErr = getVortex()
		if vortexErr != nil {
			return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: vortexErr}
		}
	}
	// fd
	proto := syscall.IPPROTO_TCP
	if lc.MultipathTCP {
		if mp, ok := sys.TryGetMultipathTCPProto(); ok {
			proto = mp
		}
	}
	fd, fdErr := aio.OpenNetFd(ctx, vortex, aio.ListenMode, network, syscall.SOCK_STREAM, proto, addr, nil, false)
	if fdErr != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: fdErr}
	}

	// control
	if lc.Control != nil {
		control := func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return lc.Control(network, address, raw)
		}
		raw := sys.NewRawConn(fd.RegularSocket())
		if err := control(ctx, fd.CtrlNetwork(), addr.String(), raw); err != nil {
			_ = fd.Close()
			return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
		}
	}
	// reuse addr
	if err := fd.SetReuseAddr(true); err != nil {
		_ = fd.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
	}
	// reuse port
	if lc.ReusePort {
		if err := fd.SetReusePort(addr.Port); err != nil {
			_ = fd.Close()
			return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
		}
		// cbpf (dep reuse port)
		filter := cbpf.NewFilter(uint32(runtime.NumCPU()))
		if err := filter.ApplyTo(fd.RegularSocket()); err != nil {
			_ = fd.Close()
			return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
		}
	}
	// defer accept
	if err := syscall.SetsockoptInt(fd.RegularSocket(), syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, 1); err != nil {
		_ = fd.Close()
		err = os.NewSyscallError("setsockopt", err)
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
	}

	// bind
	if err := fd.Bind(addr); err != nil {
		_ = fd.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
	}
	// listen
	backlog := sys.MaxListenerBacklog()
	if err := syscall.Listen(fd.RegularSocket(), backlog); err != nil {
		_ = fd.Close()
		err = os.NewSyscallError("listen", err)
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
	}
	// set socket addr
	if sn, getSockNameErr := syscall.Getsockname(fd.RegularSocket()); getSockNameErr == nil {
		if sockname := sys.SockaddrToAddr(network, sn); sockname != nil {
			fd.SetLocalAddr(sockname)
		} else {
			fd.SetLocalAddr(addr)
		}
	} else {
		fd.SetLocalAddr(addr)
	}

	// install fixed fd
	directMode := !lc.DisableDirectAlloc
	if vortex.RegisterFixedFdEnabled() {
		if regErr := fd.Register(); regErr != nil {
			if !errors.Is(regErr, aio.ErrFixedFileUnavailable) {
				_ = fd.Close()
				return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: regErr}
			}
			directMode = false
		}
	}
	if directMode {
		directMode = vortex.DirectAllocEnabled()
	}

	// send zc
	useSendZC := false
	if lc.SendZC {
		useSendZC = aio.CheckSendZCEnable()
	}

	// ln
	ln := &TCPListener{
		fd:                 fd,
		directMode:         directMode,
		vortex:             vortex,
		acceptFuture:       nil,
		multipathTCP:       lc.MultipathTCP,
		keepAlive:          lc.KeepAlive,
		keepAliveConfig:    lc.KeepAliveConfig,
		useSendZC:          useSendZC,
		useMultishotAccept: lc.MultishotAccept,
		deadline:           time.Time{},
	}
	// prepare multishot accept
	if ln.useMultishotAccept {
		if err := ln.prepareMultishotAccepting(); err != nil {
			_ = ln.Close()
			return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: err}
		}
	}

	return ln, nil
}

// TCPListener is a TCP network listener. Clients should typically
// use variables of type [net.Listener] instead of assuming TCP.
type TCPListener struct {
	fd                 *aio.NetFd
	directMode         bool
	vortex             *aio.Vortex
	acceptFuture       *aio.AcceptFuture
	multipathTCP       bool
	keepAlive          time.Duration
	keepAliveConfig    net.KeepAliveConfig
	useSendZC          bool
	useMultishotAccept bool
	deadline           time.Time
}

// Accept implements the Accept method in the [net.Listener] interface; it
// waits for the next call and returns a generic [net.Conn].
func (ln *TCPListener) Accept() (net.Conn, error) {
	return ln.AcceptTCP()
}

// AcceptTCP accepts the next incoming call and returns the new
// connection.
func (ln *TCPListener) AcceptTCP() (tc *TCPConn, err error) {
	if !ln.ok() {
		return nil, syscall.EINVAL
	}

	if ln.useMultishotAccept {
		tc, err = ln.acceptMultishot()
	} else {
		tc, err = ln.acceptOneshot()
	}
	return
}

func (ln *TCPListener) acceptOneshot() (tc *TCPConn, err error) {
	// accept
	addr := &syscall.RawSockaddrAny{}
	addrLen := syscall.SizeofSockaddrAny
	var (
		cfd *aio.NetFd
	)
	if ln.directMode {
		cfd, err = ln.fd.AcceptDirectAlloc(addr, addrLen, ln.deadline)
	} else {
		cfd, err = ln.fd.Accept(addr, addrLen, ln.deadline)
	}
	if err != nil {
		if aio.IsCanceled(err) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "accept", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: err}
		return
	}

	// no delay
	_ = cfd.SetNoDelay(true)
	// keepalive
	keepAliveConfig := ln.keepAliveConfig
	if !keepAliveConfig.Enable && ln.keepAlive >= 0 {
		keepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   ln.keepAlive,
		}
	}
	if keepAliveConfig.Enable {
		_ = cfd.SetKeepAliveConfig(keepAliveConfig)
	}
	// conn
	tc = &TCPConn{
		conn{
			fd:            cfd,
			readDeadline:  time.Time{},
			writeDeadline: time.Time{},
			useSendZC:     ln.useSendZC,
		},
		0,
	}
	return
}

func (ln *TCPListener) acceptMultishot() (tc *TCPConn, err error) {
	ctx := ln.fd.Context()
	cfd, _, acceptErr := ln.acceptFuture.Await(ctx)
	if acceptErr != nil {
		if aio.IsCanceled(acceptErr) {
			acceptErr = net.ErrClosed
		}
		err = &net.OpError{Op: "accept", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: acceptErr}
		return
	}
	// no delay
	_ = cfd.SetNoDelay(true)
	// keepalive
	keepAliveConfig := ln.keepAliveConfig
	if !keepAliveConfig.Enable && ln.keepAlive >= 0 {
		keepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   ln.keepAlive,
		}
	}
	if keepAliveConfig.Enable {
		_ = cfd.SetKeepAliveConfig(keepAliveConfig)
	}

	// tcp conn
	tc = &TCPConn{
		conn{
			fd:            cfd,
			readDeadline:  time.Time{},
			writeDeadline: time.Time{},
			useSendZC:     ln.useSendZC,
		},
		0,
	}
	return
}

func (ln *TCPListener) prepareMultishotAccepting() (err error) {
	addr := &syscall.RawSockaddrAny{}
	addrLen := syscall.SizeofSockaddrAny
	backlog := sys.MaxListenerBacklog()
	if backlog < 1024 {
		backlog = 1024
	}
	if ln.directMode {
		future := ln.fd.AcceptMultishotDirectAsync(addr, addrLen, backlog)
		ln.acceptFuture = &future
	} else {
		future := ln.fd.AcceptMultishotAsync(addr, addrLen, backlog)
		ln.acceptFuture = &future
	}
	return
}

// Close stops listening on the TCP address.
// Already Accepted connections are not closed.
func (ln *TCPListener) Close() error {
	if !ln.ok() {
		return syscall.EINVAL
	}
	if err := ln.fd.Close(); err != nil {
		return &net.OpError{Op: "close", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: err}
	}
	return nil
}

// Addr returns the listener's network address, a [*TCPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (ln *TCPListener) Addr() net.Addr {
	if !ln.ok() {
		return nil
	}
	return ln.fd.LocalAddr()
}

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
// Only valid when not multishot accept mode.
func (ln *TCPListener) SetDeadline(t time.Time) error {
	if !ln.ok() {
		return syscall.EINVAL
	}
	ln.deadline = t
	return nil
}

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
//
// The returned RawConn only supports calling Control. Read and
// Write return an error.
func (ln *TCPListener) SyscallConn() (syscall.RawConn, error) {
	if !ln.ok() {
		return nil, syscall.EINVAL
	}
	return sys.NewRawConn(ln.fd.RegularSocket()), nil
}

// File returns a copy of the underlying [os.File].
// It is the caller's responsibility to close f when finished.
// Closing l does not affect f, and closing f does not affect l.
//
// The returned os.File's file descriptor is different from the
// connection's. Attempting to change properties of the original
// using this duplicate may or may not have the desired effect.
func (ln *TCPListener) File() (f *os.File, err error) {
	if !ln.ok() {
		return nil, syscall.EINVAL
	}
	f, err = ln.file()
	if err != nil {
		return nil, &net.OpError{Op: "file", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.LocalAddr(), Err: err}
	}
	return
}

func (ln *TCPListener) file() (*os.File, error) {
	ns, call, err := ln.fd.Dup()
	if err != nil {
		if call != "" {
			err = os.NewSyscallError(call, err)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(ns), ln.fd.Name())
	return f, nil
}

func (ln *TCPListener) ok() bool { return ln != nil && ln.fd != nil }

type noReadFrom struct{}

func (noReadFrom) ReadFrom(io.Reader) (int64, error) {
	panic("can't happen")
}

type tcpConnWithoutReadFrom struct {
	noReadFrom
	*TCPConn
}

func genericReadFrom(c *TCPConn, r io.Reader) (n int64, err error) {
	return io.Copy(tcpConnWithoutReadFrom{TCPConn: c}, r)
}

type noWriteTo struct{}

func (noWriteTo) WriteTo(io.Writer) (int64, error) {
	panic("can't happen")
}

type tcpConnWithoutWriteTo struct {
	noWriteTo
	*TCPConn
}

func genericWriteTo(c *TCPConn, w io.Writer) (n int64, err error) {
	// Use wrapper to hide existing w.WriteTo from io.Copy.
	return io.Copy(w, tcpConnWithoutWriteTo{TCPConn: c})
}

// TCPConn is an implementation of the [net.Conn] interface for TCP network
// connections.
type TCPConn struct {
	conn
	readFromFilePolicy int32
}

const (
	ReadFromFileUseMMapPolicy = int32(iota)
	ReadFromFileUseMixPolicy
)

func (c *TCPConn) SetReadFromFilePolicy(policy int32) {
	switch policy {
	case ReadFromFileUseMMapPolicy, ReadFromFileUseMixPolicy:
		c.readFromFilePolicy = policy
		break
	default:
		break
	}
}

// ReadFrom implements the [io.ReaderFrom] ReadFrom method.
func (c *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if r == nil {
		return 0, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: syscall.EINVAL}
	}
	var remain int64 = 1<<63 - 1 // by default, copy until EOF
	lr, ok := r.(*io.LimitedReader)
	if ok {
		remain, r = lr.N, lr.R
		if remain <= 0 {
			return 0, nil
		}
	}

	sendMode := 0 // 0: copy, 1: splice, 2: mmap
	var srcFd int
	switch v := r.(type) {
	case *TCPConn:
		srcFd = v.fd.RegularSocket()
		sendMode = 1
		break
	case tcpConnWithoutWriteTo:
		srcFd = v.fd.RegularSocket()
		sendMode = 1
		break
	case *UnixConn:
		if v.fd.Net() != "unix" {
			break
		}
		srcFd = v.fd.RegularSocket()
		sendMode = 1
		break
	case *os.File:
		if c.readFromFilePolicy == ReadFromFileUseMixPolicy {
			if remain == 1<<63-1 {
				info, infoErr := v.Stat()
				if infoErr != nil {
					return 0, infoErr
				}
				remain = info.Size()
			}
			wb, _ := c.WriteBuffer()
			if remain <= int64(wb) {
				srcFd = int(v.Fd())
				sendMode = 1
			} else {
				sendMode = 2
			}
		} else {
			sendMode = 2
		}
		break
	default:
		break
	}

	switch sendMode {
	case 1: // splice
		if srcFd < 1 {
			return 0, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: errors.New("no file descriptor found in reader")}
		}
		written, spliceErr := c.fd.Splice(srcFd, remain)
		if lr != nil {
			lr.N -= written
		}
		if spliceErr != nil {
			if errors.Is(spliceErr, context.Canceled) {
				spliceErr = net.ErrClosed
			}
			return written, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: spliceErr}
		}
		return written, nil
	case 2: // sendfile(mmap+send)
		written, sendfileErr := c.fd.Sendfile(r, c.useSendZC)
		if lr != nil {
			lr.N -= written
		}
		if sendfileErr != nil {
			if errors.Is(sendfileErr, context.Canceled) {
				sendfileErr = net.ErrClosed
			}
			return written, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: sendfileErr}
		}
		return written, nil
	default: // copy
		written, readFromErr := genericReadFrom(c, r)
		if readFromErr != nil && readFromErr != io.EOF {
			return written, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: readFromErr}
		}
		return written, nil
	}
}

// WriteTo implements the io.WriterTo WriteTo method.
func (c *TCPConn) WriteTo(w io.Writer) (int64, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if w == nil {
		return 0, &net.OpError{Op: "writeto", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: syscall.EINVAL}
	}
	uc, ok := w.(*UnixConn)
	if ok && uc.fd.Net() == "unix" {
		fd := c.fd.RegularSocket()
		written, spliceErr := uc.fd.Splice(fd, 1<<63-1)
		if spliceErr != nil {
			if errors.Is(spliceErr, context.Canceled) {
				spliceErr = net.ErrClosed
			}
			return written, &net.OpError{Op: "writeto", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: spliceErr}
		}
		return written, nil
	}

	// copy
	written, writeToErr := genericWriteTo(c, w)
	if writeToErr != nil && writeToErr != io.EOF {
		writeToErr = &net.OpError{Op: "writeto", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: writeToErr}
	}
	return written, writeToErr
}

// CloseRead shuts down the reading side of the TCP connection.
// Most callers should just use Close.
func (c *TCPConn) CloseRead() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.CloseRead(); err != nil {
		return &net.OpError{Op: "close", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// CloseWrite shuts down the writing side of the TCP connection.
// Most callers should just use Close.
func (c *TCPConn) CloseWrite() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.CloseWrite(); err != nil {
		return &net.OpError{Op: "close", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// SetLinger sets the behavior of Close on a connection which still
// has data waiting to be sent or to be acknowledged.
//
// If sec < 0 (the default), the operating system finishes sending the
// data in the background.
//
// If sec == 0, the operating system discards any unsent or
// unacknowledged data.
//
// If sec > 0, the data is sent in the background as with sec < 0.
// On some operating systems including Linux, this may cause Close to block
// until all data has been sent or discarded.
// On some operating systems after sec seconds have elapsed any remaining
// unsent data may be discarded.
func (c *TCPConn) SetLinger(sec int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetLinger(sec); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// SetNoDelay controls whether the operating system should delay
// packet transmission in hopes of sending fewer packets (Nagle's
// algorithm).  The default is true (no delay), meaning that data is
// sent as soon as possible after a Write.
func (c *TCPConn) SetNoDelay(noDelay bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetNoDelay(noDelay); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// SetKeepAlive sets whether the operating system should send
// keep-alive messages on the connection.
func (c *TCPConn) SetKeepAlive(keepalive bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetKeepAlive(keepalive); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// SetKeepAlivePeriod sets the duration the connection needs to
// remain idle before TCP starts sending keepalive probes.
//
// Note that calling this method on Windows prior to Windows 10 version 1709
// will reset the KeepAliveInterval to the default system value, which is normally 1 second.
func (c *TCPConn) SetKeepAlivePeriod(period time.Duration) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetKeepAlivePeriod(period); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// SetKeepAliveConfig configures keep-alive messages sent by the operating system.
func (c *TCPConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetKeepAliveConfig(config); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.LocalAddr(), Addr: c.fd.RemoteAddr(), Err: err}
	}
	return nil
}

// MultipathTCP reports whether the ongoing connection is using MPTCP.
//
// If Multipath TCP is not supported by the host, by the other peer or
// intentionally / accidentally filtered out by a device in between, a
// fallback to TCP will be done. This method does its best to check if
// MPTCP is still being used or not.
//
// On Linux, more conditions are verified on kernels >= v5.16, improving
// the results.
func (c *TCPConn) MultipathTCP() (bool, error) {
	if !c.ok() {
		return false, syscall.EINVAL
	}
	ok := sys.IsUsingMultipathTCP(c.fd.RegularSocket())
	return ok, nil
}
