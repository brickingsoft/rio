//go:build unix

package sockets

import (
	"net"
	"syscall"
)

func sockaddrToTCPAddr(sa syscall.Sockaddr) (addr *net.TCPAddr) {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &net.TCPAddr{
			IP:   append([]byte{}, sa.Addr[:]...),
			Port: sa.Port,
		}
	case *syscall.SockaddrInet6:
		var zone string
		if sa.ZoneId != 0 {
			if ifi, err := net.InterfaceByIndex(int(sa.ZoneId)); err == nil {
				zone = ifi.Name
			}
		}
		if zone == "" && sa.ZoneId != 0 {
		}
		addr = &net.TCPAddr{
			IP:   append([]byte{}, sa.Addr[:]...),
			Port: sa.Port,
			Zone: zone,
		}
	}
	return
}

func sockaddrToUnixAddr(sa syscall.Sockaddr) net.Addr {
	var a net.Addr
	switch sa := sa.(type) {
	case *syscall.SockaddrUnix:
		a = &net.UnixAddr{Net: "unix", Name: sa.Name}
	}
	return a
}

func addrToSockaddr(family int, a net.Addr) (sa syscall.Sockaddr) {
	switch addr := a.(type) {
	case *net.TCPAddr:
		switch family {
		case syscall.AF_INET:
			sa4 := &syscall.SockaddrInet4{
				Port: addr.Port,
				Addr: [4]byte{},
			}
			ip := addr.IP
			if len(ip) == 0 {
				ip = net.IPv4zero
			}
			copy(sa4.Addr[:], ip.To4())
			sa = sa4
			break
		case syscall.AF_INET6:
			sa4 := &syscall.SockaddrInet6{
				Port: addr.Port,
				Addr: [16]byte{},
			}
			ip := addr.IP
			if len(ip) == 0 {
				ip = net.IPv6zero
			}
			copy(sa4.Addr[:], ip.To16())
			sa = sa4
			break
		}
		break
	case *net.UDPAddr:
		switch family {
		case syscall.AF_INET:
			sa4 := &syscall.SockaddrInet4{
				Port: addr.Port,
				Addr: [4]byte{},
			}
			copy(sa4.Addr[:], addr.IP.To4())
			sa = sa4
			break
		case syscall.AF_INET6:
			sa4 := &syscall.SockaddrInet6{
				Port: addr.Port,
				Addr: [16]byte{},
			}
			copy(sa4.Addr[:], addr.IP.To16())
			sa = sa4
			break
		}
		break
	case *net.UnixAddr:
		sa = &syscall.SockaddrUnix{
			Name: addr.Name,
		}
		break
	}
	return
}
