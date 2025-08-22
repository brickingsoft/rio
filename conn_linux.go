//go:build linux

package rio

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio"
)

type conn struct {
	fd *aio.Conn
}

// Fd implements the rio.Conn Fd method.
func (c *conn) Fd() (*aio.NetFd, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return &c.fd.NetFd, nil
}

// Read implements the net.Conn Read method.
func (c *conn) Read(b []byte) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}

	if len(b) == 0 {
		return 0, &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}

	n, err = c.fd.Receive(b)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// Write implements the net.Conn Write method.
func (c *conn) Write(b []byte) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if len(b) == 0 {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}

	n, err = c.fd.Send(b)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// Close implements the net.Conn Close method.
func (c *conn) Close() error {
	if !c.ok() {
		return syscall.EINVAL
	}

	if err := c.fd.Close(); err != nil {
		if aio.IsFdUnavailable(err) {
			err = net.ErrClosed
		}
		return &net.OpError{Op: "close", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return nil
}

// LocalAddr implements the net.Conn LocalAddr method.
func (c *conn) LocalAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.LocalAddr()
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (c *conn) RemoteAddr() net.Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.RemoteAddr()
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *conn) SetDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *conn) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if t.IsZero() {
		c.fd.SetReadDeadline(time.Time{})
		return nil
	}
	if t.Before(time.Now()) {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: errors.New("set deadline too early")}
	}
	c.fd.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (c *conn) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if t.IsZero() {
		c.fd.SetWriteDeadline(time.Time{})
		return nil
	}
	if t.Before(time.Now()) {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: errors.New("set deadline too early")}
	}
	c.fd.SetWriteDeadline(t)
	return nil
}

// ReadBuffer get SO_RCVBUF.
func (c *conn) ReadBuffer() (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}

	n, err := c.fd.ReadBuffer()
	if err != nil {
		return 0, &net.OpError{Op: "get", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return n, nil
}

// SetReadBuffer set SO_RCVBUF.
func (c *conn) SetReadBuffer(bytes int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetReadBuffer(bytes); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return nil
}

// WriteBuffer get SO_SNDBUF.
func (c *conn) WriteBuffer() (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}

	n, err := c.fd.WriteBuffer()
	if err != nil {
		return 0, &net.OpError{Op: "get", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return n, nil
}

// SetWriteBuffer set SO_SNDBUF.
func (c *conn) SetWriteBuffer(bytes int) error {
	if !c.ok() {
		return syscall.EINVAL
	}

	if err := c.fd.SetWriteBuffer(bytes); err != nil {
		return &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return nil
}

// SetSocketOptInt implements the rio.Conn SetSocketOptInt method.
func (c *conn) SetSocketOptInt(level int, optName int, optValue int) (err error) {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err = c.fd.SetSocketoptInt(level, optName, optValue); err != nil {
		err = &net.OpError{Op: "set", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// GetSocketOptInt implements the rio.Conn GetSocketOptInt method.
func (c *conn) GetSocketOptInt(level int, optName int) (optValue int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if optValue, err = c.fd.GetSocketoptInt(level, optName); err != nil {
		err = &net.OpError{Op: "get", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}

// File returns a copy of the underlying [os.File].
// It is the caller's responsibility to close f when finished.
// Closing c does not affect f, and closing f does not affect c.
//
// The returned os.File's file descriptor is different from the connection's.
// Attempting to change properties of the original using this duplicate
// may or may not have the desired effect.
func (c *conn) File() (f *os.File, err error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	f, err = c.file()
	if err != nil {
		err = &net.OpError{Op: "file", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
	}
	return
}

func (c *conn) file() (*os.File, error) {
	ns, call, err := c.fd.Dup()
	if err != nil {
		if call != "" {
			err = os.NewSyscallError(call, err)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(ns), c.fd.Name())
	return f, nil
}

func (c *conn) deadline(ctx context.Context, deadline time.Time) time.Time {
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if deadline.IsZero() {
			deadline = ctxDeadline
		} else if ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	return deadline
}

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
func (c *conn) SyscallConn() (syscall.RawConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return c.fd.SyscallConn()
}

func (c *conn) ok() bool { return c != nil && c.fd != nil }
