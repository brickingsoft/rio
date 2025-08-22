//go:build linux

package rio

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"golang.org/x/sys/unix"
)

// ListenUnix acts like [Listen] for Unix networks.
//
// The network must be "unix" or "unixpacket".
func ListenUnix(network string, addr *net.UnixAddr) (*UnixListener, error) {
	config := ListenConfig{}
	ctx := context.Background()
	return config.ListenUnix(ctx, network, addr)
}

// ListenUnix acts like [Listen] for Unix networks.
//
// The network must be "unix" or "unixpacket".
func (lc *ListenConfig) ListenUnix(ctx context.Context, network string, addr *net.UnixAddr) (*UnixListener, error) {
	// network
	switch network {
	case "unix", "unixpacket":
		break
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: net.UnknownNetworkError(network)}
	}
	if addr == nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: errors.New("missing address")}
	}

	// control
	var control aio.Control = nil
	if lc.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return lc.Control(network, address, raw)
		}
	}
	// listen
	fd, fdErr := aio.Listen(ctx, network, 0, addr, false, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: fdErr}
	}

	// ln
	ln := &UnixListener{
		fd:         fd,
		path:       fd.LocalAddr().String(),
		unlink:     true,
		unlinkOnce: sync.Once{},
		deadline:   time.Time{},
	}
	return ln, nil
}

// ListenUnixgram acts like [ListenPacket] for Unix networks.
//
// The network must be "unixgram".
func ListenUnixgram(network string, addr *net.UnixAddr) (*UnixConn, error) {
	config := ListenConfig{}
	ctx := context.Background()
	return config.ListenUnixgram(ctx, network, addr)
}

// ListenUnixgram acts like [ListenPacket] for Unix networks.
//
// The network must be "unixgram".
func (lc *ListenConfig) ListenUnixgram(ctx context.Context, network string, addr *net.UnixAddr) (*UnixConn, error) {
	// network
	switch network {
	case "unixgram":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: net.UnknownNetworkError(network)}
	}
	if addr == nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: errors.New("missing address")}
	}
	// control
	var control aio.Control = nil
	if lc.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return lc.Control(network, address, raw)
		}
	}
	// listen
	fd, fdErr := aio.ListenPacket(ctx, network, 0, addr, nil, false, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: fdErr}
	}

	// conn
	c := &UnixConn{
		conn{
			fd: fd,
		},
	}
	return c, nil
}

// UnixListener is a Unix domain socket listener. Clients should
// typically use variables of type [net.Listener] instead of assuming Unix
// domain sockets.
type UnixListener struct {
	fd         *aio.Listener
	path       string
	unlink     bool
	unlinkOnce sync.Once
	deadline   time.Time
}

// Accept implements the Accept method in the [net.Listener] interface.
// Returned connections will be of type [*UnixConn].
func (ln *UnixListener) Accept() (net.Conn, error) {
	return ln.AcceptUnix()
}

// AcceptUnix accepts the next incoming call and returns the new
// connection.
func (ln *UnixListener) AcceptUnix() (c *UnixConn, err error) {
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
	// unix conn
	c = &UnixConn{
		conn{
			fd: cfd,
		},
	}
	return
}

// SetSocketOptInt implements the rio.Listener SetSocketOptInt method.
func (ln *UnixListener) SetSocketOptInt(level int, optName int, optValue int) (err error) {
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
func (ln *UnixListener) GetSocketOptInt(level int, optName int) (optValue int, err error) {
	if !ln.ok() {
		return 0, syscall.EINVAL
	}
	if optValue, err = ln.fd.GetSocketoptInt(level, optName); err != nil {
		err = &net.OpError{Op: "get", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// Close stops listening on the Unix address. Already accepted
// connections are not closed.
func (ln *UnixListener) Close() error {
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

// Addr returns the listener's network address, a [*net.UnixAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (ln *UnixListener) Addr() net.Addr {
	if !ln.ok() {
		return nil
	}
	return ln.fd.LocalAddr()
}

// SetDeadline sets the deadline associated with the listener.
// set zero time value disables the deadline.
func (ln *UnixListener) SetDeadline(t time.Time) error {
	if !ln.ok() {
		return syscall.EINVAL
	}
	ln.deadline = t
	return nil
}

// SetUnlinkOnClose sets whether the underlying socket file should be removed
// from the file system when the listener is closed.
//
// The default behavior is to unlink the socket file only when package net created it.
// That is, when the listener and the underlying socket file were created by a call to
// Listen or ListenUnix, then by default closing the listener will remove the socket file.
// but if the listener was created by a call to FileListener to use an already existing
// socket file, then by default closing the listener will not remove the socket file.
func (ln *UnixListener) SetUnlinkOnClose(unlink bool) {
	ln.unlink = unlink
}

// File returns a copy of the underlying [os.File].
// It is the caller's responsibility to close f when finished.
// Closing l does not affect f, and closing f does not affect l.
//
// The returned os.File's file descriptor is different from the
// connection's. Attempting to change properties of the original
// using this duplicate may or may not have the desired effect.
func (ln *UnixListener) File() (f *os.File, err error) {
	if !ln.ok() {
		return nil, syscall.EINVAL
	}
	f, err = ln.file()
	if err != nil {
		err = &net.OpError{Op: "file", Net: ln.fd.Net(), Source: nil, Addr: ln.fd.TryLocalAddr(), Err: err}
	}
	return
}

func (ln *UnixListener) ok() bool { return ln != nil && ln.fd != nil }

func (ln *UnixListener) file() (*os.File, error) {
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

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
//
// The returned RawConn only supports calling Control. Read and
// Write return an error.
func (ln *UnixListener) SyscallConn() (syscall.RawConn, error) {
	if !ln.ok() {
		return nil, syscall.EINVAL
	}
	return ln.fd.SyscallConn()
}

// UnixConn is an implementation of the [net.Conn] interface for connections
// to Unix domain sockets.
type UnixConn struct {
	conn
}

// ReadFrom implements the [net.PacketConn] ReadFrom method.
func (c *UnixConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.ReadFromUnix(b)
}

// ReadFromUnix acts like [UnixConn.ReadFrom] but returns a [net.UnixAddr].
func (c *UnixConn) ReadFromUnix(b []byte) (n int, addr *net.UnixAddr, err error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	if len(b) == 0 {
		return 0, nil, &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}

	var (
		uaddr net.Addr
	)
	n, uaddr, err = c.fd.ReceiveFrom(b)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}

	ok := false
	addr, ok = uaddr.(*net.UnixAddr)
	if !ok {
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: errors.New("wrong address type")}
		return
	}
	return
}

// ReadMsgUnix reads a message from c, copying the payload into b and
// the associated out-of-band data into oob. It returns the number of
// bytes copied into b, the number of bytes copied into oob, the flags
// that were set on the message and the source address of the message.
//
// Note that if len(b) == 0 and len(oob) > 0, this function will still
// read (and discard) 1 byte from the connection.
func (c *UnixConn) ReadMsgUnix(b []byte, oob []byte) (n, oobn, flags int, addr *net.UnixAddr, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, syscall.EINVAL
	}
	bLen := len(b)
	oobLen := len(oob)
	if bLen == 0 && oobLen == 0 {
		return 0, 0, 0, nil, &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}

	var (
		uaddr net.Addr
	)
	n, oobn, flags, uaddr, err = c.fd.ReceiveMsg(b, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	ok := false
	addr, ok = uaddr.(*net.UnixAddr)
	if !ok {
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: net.InvalidAddrError("wrong address type")}
		return
	}
	return
}

// WriteTo implements the [net.PacketConn] WriteTo method.
func (c *UnixConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if len(b) == 0 || addr == nil || reflect.ValueOf(addr).IsNil() {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	uAddr, isUnixAddr := addr.(*net.UnixAddr)
	if !isUnixAddr {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	if uAddr.Net != c.fd.Net() {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	return c.writeTo(b, uAddr)
}

// WriteToUnix acts like [UnixConn.WriteTo] but takes a [net.UnixAddr].
func (c *UnixConn) WriteToUnix(b []byte, addr *net.UnixAddr) (int, error) {
	return c.WriteTo(b, addr)
}

func (c *UnixConn) writeTo(b []byte, addr net.Addr) (n int, err error) {
	n, err = c.fd.SendTo(b, addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// WriteMsgUnix writes a message to addr via c, copying the payload
// from b and the associated out-of-band data from oob. It returns the
// number of payload and out-of-band bytes written.
//
// Note that if len(b) == 0 and len(oob) > 0, this function will still
// write 1 byte to the connection.
func (c *UnixConn) WriteMsgUnix(b []byte, oob []byte, addr *net.UnixAddr) (n int, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	if len(b) == 0 && len(oob) == 0 {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	if addr == nil {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	if addr.Net != c.fd.Net() {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}

	if len(b) == 0 && c.fd.SocketType() != syscall.SOCK_DGRAM {
		b = []byte{0}
	}

	n, oobn, err = c.fd.SendMsg(b, oob, addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// SetSocketOptInt implements the rio.PacketConn SetSocketOptInt method.
func (c *UnixConn) SetSocketOptInt(level int, optName int, optValue int) (err error) {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err = c.fd.SetSocketoptInt(level, optName, optValue); err != nil {
		err = &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// GetSocketOptInt implements the rio.PacketConn GetSocketOptInt method.
func (c *UnixConn) GetSocketOptInt(level int, optName int) (optValue int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if optValue, err = c.fd.GetSocketoptInt(level, optName); err != nil {
		err = &net.OpError{Op: "get", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}
