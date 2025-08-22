//go:build linux

package rio

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"syscall"

	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

// ListenUDP acts like [ListenPacket] for UDP networks.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenUDP listens on all available IP addresses of the local system
// except multicast IP addresses.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ListenUDP(network string, addr *net.UDPAddr) (*UDPConn, error) {
	config := ListenConfig{}
	ctx := context.Background()
	return config.ListenUDP(ctx, network, addr)
}

// ListenUDP acts like [ListenPacket] for UDP networks.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenUDP listens on all available IP addresses of the local system
// except multicast IP addresses.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func (lc *ListenConfig) ListenUDP(ctx context.Context, network string, addr *net.UDPAddr) (*UDPConn, error) {
	return lc.listenUDP(ctx, network, nil, addr)
}

// ListenMulticastUDP acts like [ListenPacket] for UDP networks but
// takes a group address on a specific network interface.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// ListenMulticastUDP listens on all available IP addresses of the
// local system including the group, multicast IP address.
// If ifi is nil, ListenMulticastUDP uses the system-assigned
// multicast interface, although this is not recommended because the
// assignment depends on platforms and sometimes it might require
// routing configuration.
// If the Port field of gaddr is 0, a port number is automatically
// chosen.
//
// ListenMulticastUDP is just for convenience of simple, small
// applications. There are [golang.org/x/net/ipv4] and
// [golang.org/x/net/ipv6] packages for general purpose uses.
//
// Note that ListenMulticastUDP will set the IP_MULTICAST_LOOP socket option
// to 0 under IPPROTO_IP, to disable loopback of multicast packets.
func ListenMulticastUDP(network string, ifi *net.Interface, addr *net.UDPAddr) (*UDPConn, error) {
	config := ListenConfig{}
	ctx := context.Background()
	return config.ListenMulticastUDP(ctx, network, ifi, addr)
}

// ListenMulticastUDP acts like [ListenPacket] for UDP networks but
// takes a group address on a specific network interface.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// ListenMulticastUDP listens on all available IP addresses of the
// local system including the group, multicast IP address.
// If ifi is nil, ListenMulticastUDP uses the system-assigned
// multicast interface, although this is not recommended because the
// assignment depends on platforms and sometimes it might require
// routing configuration.
// If the Port field of gaddr is 0, a port number is automatically
// chosen.
//
// ListenMulticastUDP is just for convenience of simple, small
// applications. There are [golang.org/x/net/ipv4] and
// [golang.org/x/net/ipv6] packages for general purpose uses.
//
// Note that ListenMulticastUDP will set the IP_MULTICAST_LOOP socket option
// to 0 under IPPROTO_IP, to disable loopback of multicast packets.
func (lc *ListenConfig) ListenMulticastUDP(ctx context.Context, network string, ifi *net.Interface, addr *net.UDPAddr) (*UDPConn, error) {
	return lc.listenUDP(ctx, network, ifi, addr)
}

func (lc *ListenConfig) listenUDP(ctx context.Context, network string, ifi *net.Interface, addr *net.UDPAddr) (*UDPConn, error) {
	// network
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: net.UnknownNetworkError(network)}
	}
	if addr == nil {
		addr = &net.UDPAddr{}
	}
	// control
	var control aio.Control = nil
	if lc.Control != nil {
		control = func(ctx context.Context, network string, address string, raw syscall.RawConn) error {
			return lc.Control(network, address, raw)
		}
	}
	// listen
	fd, fdErr := aio.ListenPacket(ctx, network, 0, addr, ifi, lc.ReusePort, control)
	if fdErr != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: fdErr}
	}

	// conn
	c := &UDPConn{
		conn{
			fd: fd,
		},
	}
	return c, nil
}

// UDPConn is the implementation of the [net.Conn] and [net.PacketConn] interfaces
// for UDP network connections.
type UDPConn struct {
	conn
}

// ReadFromUDP acts like [UDPConn.ReadFrom] but returns a net.UDPAddr.
func (c *UDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
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
	addr, ok = uaddr.(*net.UDPAddr)
	if !ok {
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: errors.New("wrong address type")}
		return
	}
	return
}

// ReadFrom implements the [net.PacketConn] ReadFrom method.
func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return c.ReadFromUDP(b)
}

// ReadFromUDPAddrPort acts like ReadFrom but returns a [netip.AddrPort].
//
// If c is bound to an unspecified address, the returned
// netip.AddrPort's address might be an IPv4-mapped IPv6 address.
// Use [netip.Addr.Unmap] to get the address without the IPv6 prefix.
func (c *UDPConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	var udpAddr *net.UDPAddr
	n, udpAddr, err = c.ReadFromUDP(b)
	if err != nil {
		return
	}
	addr = udpAddr.AddrPort()
	return
}

// ReadMsgUDP reads a message from c, copying the payload into b and
// the associated out-of-band data into oob. It returns the number of
// bytes copied into b, the number of bytes copied into oob, the flags
// that were set on the message and the source address of the message.
//
// The packages [golang.org/x/net/ipv4] and [golang.org/x/net/ipv6] can be
// used to manipulate IP-level socket options in oob.
func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
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
	n, oobn, flags, uaddr, err = c.fd.ReceiveMsg(b, oob, 0)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = net.ErrClosed
		}
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}

	ok := false
	addr, ok = uaddr.(*net.UDPAddr)
	if !ok {
		err = &net.OpError{Op: "read", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: net.InvalidAddrError("wrong address type")}
		return
	}
	return
}

// ReadMsgUDPAddrPort is like [UDPConn.ReadMsgUDP] but returns an [netip.AddrPort] instead of a [net.UDPAddr].
func (c *UDPConn) ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error) {
	var udpAddr *net.UDPAddr
	n, oobn, flags, udpAddr, err = c.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}
	addr = udpAddr.AddrPort()
	return
}

// WriteToUDP acts like [UDPConn.WriteTo] but takes a [UDPAddr].
func (c *UDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error) {
	n, err = c.WriteTo(b, addr)
	return
}

// WriteToUDPAddrPort acts like [UDPConn.WriteTo] but takes a [netip.AddrPort].
func (c *UDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if len(b) == 0 || !addr.IsValid() {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	sa, saErr := sys.AddrPortToSockaddr(addr)
	if saErr != nil {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: saErr}
	}
	uaddr := sys.SockaddrToAddr(c.fd.Net(), sa)

	n, err = c.writeTo(b, uaddr)
	return
}

// WriteTo implements the [net.PacketConn] WriteTo method.
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if len(b) == 0 || reflect.ValueOf(addr).IsNil() {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	uAddr, addrOk := addr.(*net.UDPAddr)
	if !addrOk {
		return 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	n, err = c.writeTo(b, uAddr)
	return
}

func (c *UDPConn) writeTo(b []byte, addr net.Addr) (n int, err error) {
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

// WriteMsgUDP writes a message to addr via c if c isn't connected, or
// to c's remote address if c is connected (in which case addr must be
// nil). The payload is copied from b and the associated out-of-band
// data is copied from oob. It returns the number of payload and
// out-of-band bytes written.
//
// The packages [golang.org/x/net/ipv4] and [golang.org/x/net/ipv6] can be
// used to manipulate IP-level socket options in oob.
func (c *UDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	if len(b) == 0 && len(oob) == 0 {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	if addr == nil {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	n, oobn, err = c.writeMsg(b, oob, addr)
	return
}

// WriteMsgUDPAddrPort is like [UDPConn.WriteMsgUDP] but takes a [netip.AddrPort] instead of a [net.UDPAddr].
func (c *UDPConn) WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	if len(b) == 0 && len(oob) == 0 {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	if !addr.IsValid() {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: syscall.EINVAL}
	}
	sa, saErr := sys.AddrPortToSockaddr(addr)
	if saErr != nil {
		return 0, 0, &net.OpError{Op: "write", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: saErr}
	}
	uaddr := sys.SockaddrToAddr(c.fd.Net(), sa)
	n, oobn, err = c.writeMsg(b, oob, uaddr)
	return
}

func (c *UDPConn) writeMsg(b, oob []byte, addr net.Addr) (n, oobn int, err error) {
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
func (c *UDPConn) SetSocketOptInt(level int, optName int, optValue int) (err error) {
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
func (c *UDPConn) GetSocketOptInt(level int, optName int) (optValue int, err error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	if optValue, err = c.fd.GetSocketoptInt(level, optName); err != nil {
		err = &net.OpError{Op: "get", Net: c.fd.Net(), Source: c.fd.TryRemoteAddr(), Addr: c.fd.TryLocalAddr(), Err: err}
		return
	}
	return
}
