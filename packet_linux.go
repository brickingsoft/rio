//go:build linux

package rio

import (
	"context"
	"github.com/brickingsoft/rio/pkg/sys"
	"net"
)

func ListenPacket(network string, addr string) (c net.PacketConn, err error) {
	config := ListenConfig{}
	ctx := context.Background()
	c, err = config.ListenPacket(ctx, network, addr)
	return
}

func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (c net.PacketConn, err error) {
	addr, _, _, addrErr := sys.ResolveAddr(network, address)
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
