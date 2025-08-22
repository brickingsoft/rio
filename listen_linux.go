//go:build linux

package rio

import (
	"context"
	"net"

	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

// Listen announces on the local network address.
//
// See func Listen for a description of the network and address
// parameters.
//
// The ctx argument is used while resolving the address on which to listen;
// it does not affect the returned Listener.
func (lc *ListenConfig) Listen(ctx context.Context, network string, address string) (ln net.Listener, err error) {
	addr, addrErr := sys.ParseAddr(network, address)
	if addrErr != nil {
		err = &net.OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: addrErr}
		return
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		ln, err = lc.ListenTCP(ctx, network, a)
		break
	case *net.UnixAddr:
		ln, err = lc.ListenUnix(ctx, network, a)
		break
	default:
		err = &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: &net.AddrError{Err: "unexpected address type", Addr: address}}
		break
	}
	return
}

// ListenPacket announces on the local network address.
//
// See func ListenPacket for a description of the network and address
// parameters.
//
// The ctx argument is used while resolving the address on which to listen;
// it does not affect the returned Listener.
func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (c net.PacketConn, err error) {
	addr, addrErr := sys.ParseAddr(network, address)
	if addrErr != nil {
		err = &net.OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: addrErr}
		return
	}

	switch a := addr.(type) {
	case *net.UDPAddr:
		c, err = lc.ListenUDP(ctx, network, a)
		break
	case *net.IPAddr:
		c, err = lc.ListenIP(ctx, network, a)
		break
	case *net.UnixAddr:
		c, err = lc.ListenUnixgram(ctx, network, a)
		break
	default:
		err = &net.OpError{Op: "listen", Net: network, Source: nil, Addr: addr, Err: &net.AddrError{Err: "unexpected address type", Addr: address}}
		break
	}
	return
}
