//go:build linux

package rio

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

// DialContext connects to the address on the named network using
// the provided context.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// When using TCP, and the host in the address parameter resolves to multiple
// network addresses, any dial timeout (from d.Timeout or ctx) is spread
// over each consecutive dial, such that each is given an appropriate
// fraction of the time to connect.
// For example, if a host has 4 IP addresses and the timeout is 1 minute,
// the connect to each single address will be given 15 seconds to complete
// before trying the next one.
//
// See func [Dial] for a description of the network and address
// parameters.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (c net.Conn, err error) {
	addrs, addrsErr := sys.ResolveAddresses(network, address)
	if addrsErr != nil {
		err = &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: addrsErr}
		return
	}
	la := d.LocalAddr
	addrs = sys.FilterAddresses(addrs, la)
	addrsLen := len(addrs)
	if addrsLen == 0 {
		err = &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: errors.New("no addresses")}
		return
	}
	if addrsLen == 1 {
		c, err = d.dial(ctx, network, la, addrs[0])
		return
	}
	c, err = d.dialParallel(ctx, network, la, addrs)
	return
}

// Dial connects to the address on the named network.
//
// See func Dial for a description of the network and address
// parameters.
//
// Dial uses [context.Background] internally; to specify the context, use
// [Dialer.DialContext].
func (d *Dialer) Dial(network string, address string) (c net.Conn, err error) {
	ctx := context.Background()
	return d.DialContext(ctx, network, address)
}

// DialTCP acts like [Dial] for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*TCPConn, error) {
	ctx := context.Background()
	dialer := DefaultDialer
	return dialer.DialTCP(ctx, network, laddr, raddr)
}

// DialTCP acts like [Dial] for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func (d *Dialer) DialTCP(ctx context.Context, network string, laddr, raddr *net.TCPAddr) (*TCPConn, error) {
	// network
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: net.UnknownNetworkError(network)}
	}
	if raddr == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: errors.New("missing address")}
	}
	// deadline
	now := time.Now()
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() && deadline.Before(now) {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: aio.ErrTimeout}
	}

	// control
	var control aio.Control = d.ControlContext
	if control == nil && d.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return d.Control(network, address, raw)
		}
	}
	// proto
	proto := syscall.IPPROTO_TCP
	if d.MultipathTCP {
		if mp, ok := sys.TryGetMultipathTCPProto(); ok {
			proto = mp
		}
	}
	// fd
	fd, fdErr := aio.Connect(ctx, deadline, network, proto, laddr, raddr, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: fdErr}
	}

	// keepalive
	keepAliveConfig := d.KeepAliveConfig
	if !keepAliveConfig.Enable && d.KeepAlive >= 0 {
		keepAliveConfig = net.KeepAliveConfig{
			Enable: true,
			Idle:   d.KeepAlive,
		}
	}
	if keepAliveConfig.Enable {
		_ = fd.SetKeepAliveConfig(keepAliveConfig)
	}
	// conn
	c := &TCPConn{
		conn{
			fd: fd,
		},
	}

	return c, nil
}

// DialUDP acts like [Dial] for UDP networks.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func DialUDP(network string, laddr, raddr *net.UDPAddr) (*UDPConn, error) {
	ctx := context.Background()
	return DefaultDialer.DialUDP(ctx, network, laddr, raddr)
}

// DialUDP acts like [Dial] for UDP networks.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func (d *Dialer) DialUDP(ctx context.Context, network string, laddr, raddr *net.UDPAddr) (*UDPConn, error) {
	// network
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: net.UnknownNetworkError(network)}
	}
	// deadline
	now := time.Now()
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() && deadline.Before(now) {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: aio.ErrTimeout}
	}

	// control
	var control aio.Control = d.ControlContext
	if control == nil && d.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return d.Control(network, address, raw)
		}
	}
	// fd
	fd, fdErr := aio.Connect(ctx, deadline, network, 0, laddr, raddr, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: fdErr}
	}

	// conn
	c := &UDPConn{
		conn{
			fd: fd,
		},
	}
	return c, nil
}

// DialUnix acts like [Dial] for Unix networks.
//
// The network must be a Unix network name; see func Dial for details.
//
// If laddr is non-nil, it is used as the local address for the
// connection.
func DialUnix(network string, laddr, raddr *net.UnixAddr) (*UnixConn, error) {
	ctx := context.Background()
	return DefaultDialer.DialUnix(ctx, network, laddr, raddr)
}

// DialUnix acts like [Dial] for Unix networks.
//
// The network must be a Unix network name; see func Dial for details.
//
// If laddr is non-nil, it is used as the local address for the
// connection.
func (d *Dialer) DialUnix(ctx context.Context, network string, laddr, raddr *net.UnixAddr) (*UnixConn, error) {
	// network
	sotype := 0
	switch network {
	case "unix":
		sotype = syscall.SOCK_STREAM
		break
	case "unixpacket":
		sotype = syscall.SOCK_PACKET
	case "unixgram":
		sotype = syscall.SOCK_DGRAM
		break
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: net.UnknownNetworkError(network)}
	}
	if laddr != nil && sys.IsWildcard(laddr) {
		laddr = nil
	}
	if raddr != nil && sys.IsWildcard(raddr) {
		raddr = nil
	}
	if raddr == nil && (sotype != syscall.SOCK_DGRAM || laddr == nil) {
		return nil, errors.New("missing address")
	}
	// deadline
	now := time.Now()
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() && deadline.Before(now) {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: aio.ErrTimeout}
	}

	// control
	var control aio.Control = d.ControlContext
	if control == nil && d.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return d.Control(network, address, raw)
		}
	}
	// fd
	fd, fdErr := aio.Connect(ctx, deadline, network, 0, laddr, raddr, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: raddr, Err: fdErr}
	}

	// conn
	c := &UnixConn{
		conn{
			fd: fd,
		},
	}

	return c, nil
}

// DialIP acts like [Dial] for IP networks.
//
// The network must be an IP network name; see func Dial for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func DialIP(network string, laddr, raddr *net.IPAddr) (*IPConn, error) {
	ctx := context.Background()
	return DefaultDialer.DialIP(ctx, network, laddr, raddr)
}

// DialIP acts like [Dial] for IP networks.
//
// The network must be an IP network name; see func Dial for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func (d *Dialer) DialIP(_ context.Context, network string, laddr, raddr *net.IPAddr) (*IPConn, error) {
	c, err := net.DialIP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	return &IPConn{c}, nil
}
