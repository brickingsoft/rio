//go:build linux

package rio

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
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
	// network
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: net.UnknownNetworkError(network)}
	}
	if addr == nil {
		addr = &net.TCPAddr{}
	}
	// proto
	proto := syscall.IPPROTO_TCP
	if lc.MultipathTCP {
		if mp, ok := sys.TryGetMultipathTCPProto(); ok {
			proto = mp
		}
	}
	// control
	var control aio.Control = nil
	if lc.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return lc.Control(network, address, raw)
		}
	}
	// listen
	fd, fdErr := aio.Listen(ctx, network, proto, addr, lc.ReusePort, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: fdErr}
	}

	// ln
	ln := &TCPListener{
		fd:              fd,
		keepAlive:       lc.KeepAlive,
		keepAliveConfig: lc.KeepAliveConfig,
		deadline:        time.Time{},
	}
	return ln, nil
}

// TCPListener is a TCP network listener. Clients should typically
// use variables of type [net.Listener] instead of assuming TCP.
type TCPListener struct {
	fd              *aio.Listener
	keepAlive       time.Duration
	keepAliveConfig net.KeepAliveConfig
	deadline        time.Time
}

// Accept implements the Accept method in the [net.Listener] interface; it
// waits for the next call and returns a generic [net.Conn].
func (ln *TCPListener) Accept() (net.Conn, error) {
	return ln.AcceptTCP()
}

// AcceptTCP accepts the next incoming call and returns the new
// connection.
func (ln *TCPListener) AcceptTCP() (c *TCPConn, err error) {
	if !ln.ok() {
		return nil, syscall.EINVAL
	}

	cfd, acceptErr := ln.fd.Accept()
	if acceptErr != nil {
		if aio.IsCanceled(acceptErr) {
			acceptErr = net.ErrClosed
		}
		err = &net.OpError{Op: "accept", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: acceptErr}
		return
	}
	// conn
	c = &TCPConn{
		conn{
			fd: cfd,
		},
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
		if aio.IsFdUnavailable(err) {
			err = net.ErrClosed
		}
		return &net.OpError{Op: "close", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: err}
	}
	return nil
}

// Addr returns the listener's network address, a [*net.TCPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (ln *TCPListener) Addr() net.Addr {
	if !ln.ok() {
		return nil
	}
	return ln.fd.LocalAddr()
}

// SetDeadline sets the deadline associated with the listener.
// set zero time value disables the deadline.
func (ln *TCPListener) SetDeadline(t time.Time) error {
	if !ln.ok() {
		return syscall.EINVAL
	}
	ln.fd.SetReadDeadline(t)
	return nil
}

// SetSocketOptInt implements the rio.Listener SetSocketOptInt method.
func (ln *TCPListener) SetSocketOptInt(level int, optName int, optValue int) (err error) {
	if !ln.ok() {
		return syscall.EINVAL
	}
	if err = ln.fd.SetSocketoptInt(level, optName, optValue); err != nil {
		err = &net.OpError{Op: "set", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// GetSocketOptInt implements the rio.Listener GetSocketOptInt method.
func (ln *TCPListener) GetSocketOptInt(level int, optName int) (optValue int, err error) {
	if !ln.ok() {
		return 0, syscall.EINVAL
	}
	if optValue, err = ln.fd.GetSocketoptInt(level, optName); err != nil {
		err = &net.OpError{Op: "get", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: err}
		return
	}
	return
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
	return ln.fd.SyscallConn()
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
		return nil, &net.OpError{Op: "file", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: err}
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
}

// ReadFrom implements the [io.ReaderFrom] ReadFrom method.
func (c *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if r == nil {
		return 0, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	var remain int64 = 1<<63 - 1 // by default, copy until EOF
	lr, ok := r.(*io.LimitedReader)
	if ok {
		remain, r = lr.N, lr.R
		if remain <= 0 {
			return 0, nil
		}
	}

	var src *aio.Fd
	sendMode := 0 // 0: copy, 1: splice, 2: mmap
	switch v := r.(type) {
	case *net.TCPConn:
		dup, dupErr := v.File()
		if dupErr != nil {
			break
		}
		src = aio.NewRegularFd(int(dup.Fd()))
		sendMode = 1
		break
	case *TCPConn:
		src = &v.fd.Fd
		sendMode = 1
		break
	case tcpConnWithoutWriteTo:
		src = &v.fd.Fd
		sendMode = 1
		break
	case *UnixConn:
		if v.fd.Net() != "unix" {
			break
		}
		src = &v.fd.Fd
		sendMode = 1
		break
	case *os.File:
		if remain == 1<<63-1 {
			info, infoErr := v.Stat()
			if infoErr != nil {
				return 0, infoErr
			}
			remain = info.Size()
		}
		wb, _ := c.WriteBuffer()
		if remain <= int64(wb) {
			src = aio.NewRegularFd(int(v.Fd()))
			sendMode = 1
		} else {
			sendMode = 2
		}
		break
	default:
		break
	}

	switch sendMode {
	case 1: // splice
		if src == nil {
			return 0, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: errors.New("no file descriptor found in reader")}
		}
		written, spliceErr := c.fd.Splice(src, remain)
		if lr != nil {
			lr.N -= written
		}
		if spliceErr != nil {
			if errors.Is(spliceErr, context.Canceled) {
				spliceErr = net.ErrClosed
			}
			return written, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: spliceErr}
		}
		return written, nil
	case 2: // (sendfile+mmap+send)
		written, sendfileErr := c.fd.Sendfile(r)
		if lr != nil {
			lr.N -= written
		}
		if sendfileErr != nil {
			if errors.Is(sendfileErr, context.Canceled) {
				sendfileErr = net.ErrClosed
			}
			return written, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: sendfileErr}
		}
		return written, nil
	default: // copy
		written, readFromErr := genericReadFrom(c, r)
		if readFromErr != nil && readFromErr != io.EOF {
			return written, &net.OpError{Op: "readfrom", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: readFromErr}
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
		return 0, &net.OpError{Op: "writeto", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	uc, ok := w.(*UnixConn)
	if ok && uc.fd.Net() == "unix" {
		fd := &c.fd.Fd
		written, spliceErr := uc.fd.Splice(fd, 1<<63-1)
		if spliceErr != nil {
			if errors.Is(spliceErr, context.Canceled) {
				spliceErr = net.ErrClosed
			}
			return written, &net.OpError{Op: "writeto", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: spliceErr}
		}
		return written, nil
	}

	// copy
	written, writeToErr := genericWriteTo(c, w)
	if writeToErr != nil && writeToErr != io.EOF {
		writeToErr = &net.OpError{Op: "writeto", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: writeToErr}
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
		return &net.OpError{Op: "close", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
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
		return &net.OpError{Op: "close", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
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
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
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
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
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
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
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
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return nil
}

// SetKeepAliveConfig configures keep-alive messages sent by the operating system.
func (c *TCPConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetKeepAliveConfig(config); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
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
	ok := sys.IsUsingMultipathTCP(c.fd.RegularFileDescriptor())
	return ok, nil
}
