package aio

import (
	"github.com/brickingsoft/errors"
	"net"
	"syscall"
)

type ListenerOptions struct {
	MultipathTCP       bool
	MulticastInterface *net.Interface
	FastOpen           int
}

func Listen(network string, address string, opts ListenerOptions) (fd NetFd, err error) {
	addr, family, ipv6only, addrErr := ResolveAddr(network, address)
	if addrErr != nil {
		err = errors.New(
			"listen failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpListen),
			errors.WithWrap(addrErr),
		)
		return
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		proto := syscall.IPPROTO_TCP
		if opts.MultipathTCP {
			if multipathProto, ok := tryGetMultipathTCPProto(); ok {
				proto = multipathProto
			}
		}
		fd, err = newListenerFd(network, family, syscall.SOCK_STREAM, proto, ipv6only, addr, nil)
		if err == nil && opts.FastOpen > 0 {
			_ = SetFastOpen(fd, opts.FastOpen)
		}
		break
	case "udp", "udp4", "udp6":
		fd, err = newListenerFd(network, family, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP, ipv6only, addr, opts.MulticastInterface)
		break
	case "unix":
		fd, err = newListenerFd(network, family, syscall.SOCK_STREAM, 0, ipv6only, addr, nil)
		break
	case "unixgram":
		fd, err = newListenerFd(network, family, syscall.SOCK_DGRAM, 0, ipv6only, addr, nil)
		break
	case "unixpacket":
		fd, err = newListenerFd(network, family, syscall.SOCK_SEQPACKET, 0, ipv6only, addr, nil)
		break
	case "ip", "ip4", "ip6":
		proto := 0
		var parseProtoError error
		network, proto, parseProtoError = ParseIpProto(network)
		if parseProtoError != nil {
			err = parseProtoError
			return
		}
		fd, err = newListenerFd(network, family, syscall.SOCK_RAW, proto, ipv6only, addr, nil)
		break
	default:
		err = errors.New(
			"listen failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpListen),
			errors.WithWrap(errors.Define("network is not support")),
		)
		return
	}
	return
}
