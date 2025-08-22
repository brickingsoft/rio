//go:build linux

package sys

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

func AddrToSockaddr(a net.Addr) (sa syscall.Sockaddr, err error) {
	var ipBytes []byte
	var port int
	var zone string
	switch a.Network() {
	case "tcp":
		addr := a.(*net.TCPAddr)
		if len(addr.IP) == 0 {
			ipBytes = net.IPv6zero
			break
		}
		ipBytes = addr.IP
		port = addr.Port
		zone = addr.Zone
		break
	case "udp":
		addr := a.(*net.UDPAddr)
		if len(addr.IP) == 0 {
			ipBytes = net.IPv6zero
			break
		}
		ipBytes = addr.IP
		port = addr.Port
		zone = addr.Zone
		break
	case "unix", "unixgram", "unixpacket":
		addr := a.(*net.UnixAddr)
		sa = &syscall.SockaddrUnix{
			Name: addr.Name,
		}
		return
	case "ip":
		addr := a.(*net.IPAddr)
		if len(addr.IP) == 0 {
			ipBytes = net.IPv6zero
			break
		}
		ipBytes = addr.IP
		zone = addr.Zone
		break
	default:
		err = errors.New("invalid addr")
		return
	}
	ip, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		err = errors.New("invalid IP")
		return
	}
	if ip.Is6() {
		zoneId := uint32(0)
		if zone != "" {
			if ifi, ifiErr := net.InterfaceByName(zone); ifiErr == nil {
				zoneId = uint32(ifi.Index)
			}
		}
		sa6 := &syscall.SockaddrInet6{
			Port:   port,
			Addr:   ip.As16(),
			ZoneId: zoneId,
		}
		sa = sa6
	} else {
		sa4 := &syscall.SockaddrInet4{
			Port: port,
			Addr: ip.As4(),
		}
		sa = sa4
	}
	return
}

func SockaddrToAddr(network string, sa syscall.Sockaddr) (addr net.Addr) {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		switch network {
		case "tcp", "tcp4":
			addr = &net.TCPAddr{
				IP:   append([]byte{}, sa.Addr[:]...),
				Port: sa.Port,
			}
			break
		case "udp", "udp4":
			addr = &net.UDPAddr{
				IP:   append([]byte{}, sa.Addr[:]...),
				Port: sa.Port,
			}
			break
		case "ip", "ip4":
			addr = &net.IPAddr{
				IP:   append([]byte{}, sa.Addr[:]...),
				Zone: "",
			}
			break
		}
	case *syscall.SockaddrInet6:
		var zone string
		if sa.ZoneId != 0 {
			if ifi, err := net.InterfaceByIndex(int(sa.ZoneId)); err == nil {
				zone = ifi.Name
			}
		}
		switch network {
		case "tcp", "tcp6":
			addr = &net.TCPAddr{
				IP:   append([]byte{}, sa.Addr[:]...),
				Port: sa.Port,
				Zone: zone,
			}
			break
		case "udp", "udp6":
			addr = &net.UDPAddr{
				IP:   append([]byte{}, sa.Addr[:]...),
				Port: sa.Port,
				Zone: zone,
			}
			break
		case "ip", "ip6":
			addr = &net.IPAddr{
				IP:   append([]byte{}, sa.Addr[:]...),
				Zone: zone,
			}
			break
		}
	case *syscall.SockaddrUnix:
		addr = &net.UnixAddr{Net: network, Name: sa.Name}
		break
	}
	return
}

func RawSockaddrAnyToSockaddr(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_NETLINK:
		pp := (*syscall.RawSockaddrNetlink)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrNetlink)
		sa.Family = pp.Family
		sa.Pad = pp.Pad
		sa.Pid = pp.Pid
		sa.Groups = pp.Groups
		return sa, nil

	case syscall.AF_PACKET:
		pp := (*syscall.RawSockaddrLinklayer)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrLinklayer)
		sa.Protocol = pp.Protocol
		sa.Ifindex = int(pp.Ifindex)
		sa.Hatype = pp.Hatype
		sa.Pkttype = pp.Pkttype
		sa.Halen = pp.Halen
		sa.Addr = pp.Addr
		return sa, nil

	case syscall.AF_UNIX:
		pp := (*syscall.RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		bytes := (*[len(pp.Path)]byte)(unsafe.Pointer(&pp.Path[0]))[0:n]
		sa.Name = string(bytes)
		return sa, nil

	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.Addr = pp.Addr
		return sa, nil

	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		sa.Addr = pp.Addr
		return sa, nil
	}
	return nil, syscall.EAFNOSUPPORT
}

func SockaddrInet4ToRawSockaddrAny(sa *syscall.SockaddrInet4) (name *syscall.RawSockaddrAny, nameLen int32) {
	name = &syscall.RawSockaddrAny{}
	raw := (*syscall.RawSockaddrInet4)(unsafe.Pointer(name))
	raw.Family = syscall.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	raw.Addr = sa.Addr
	nameLen = int32(unsafe.Sizeof(*raw))
	return
}

func SockaddrInet6ToRawSockaddrAny(sa *syscall.SockaddrInet6) (name *syscall.RawSockaddrAny, nameLen int32) {
	name = &syscall.RawSockaddrAny{}
	raw := (*syscall.RawSockaddrInet6)(unsafe.Pointer(name))
	raw.Family = syscall.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	raw.Scope_id = sa.ZoneId
	raw.Addr = sa.Addr
	nameLen = int32(unsafe.Sizeof(*raw))
	return
}

func SockaddrUnixToRawSockaddrAny(sa *syscall.SockaddrUnix) (name *syscall.RawSockaddrAny, nameLen int32) {
	name = &syscall.RawSockaddrAny{}
	raw := (*syscall.RawSockaddrUnix)(unsafe.Pointer(name))
	raw.Family = syscall.AF_UNIX
	path := make([]byte, len(sa.Name))
	copy(path, sa.Name)
	n := 0
	for n < len(path) && path[n] != 0 {
		n++
	}
	pp := []int8(unsafe.Slice((*int8)(unsafe.Pointer(&path[0])), n))
	copy(raw.Path[:], pp)
	nameLen = int32(unsafe.Sizeof(*raw))
	return
}

func SockaddrToRawSockaddrAny(sa syscall.Sockaddr) (name *syscall.RawSockaddrAny, nameLen int32, err error) {
	switch s := sa.(type) {
	case *syscall.SockaddrInet4:
		name, nameLen = SockaddrInet4ToRawSockaddrAny(s)
		return
	case *syscall.SockaddrInet6:
		name, nameLen = SockaddrInet6ToRawSockaddrAny(s)
		return
	case *syscall.SockaddrUnix:
		name, nameLen = SockaddrUnixToRawSockaddrAny(s)
		return
	default:
		err = errors.New("invalid address type")
		return
	}
}

func InterfaceToIPv4Addr(ifi *net.Interface) (net.IP, error) {
	if ifi == nil {
		return net.IPv4zero, nil
	}
	ifat, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, ifa := range ifat {
		switch v := ifa.(type) {
		case *net.IPAddr:
			if v.IP.To4() != nil {
				return v.IP, nil
			}
		case *net.IPNet:
			if v.IP.To4() != nil {
				return v.IP, nil
			}
		}
	}
	return nil, errors.New("no such network interface")
}

func SetIPv4MreqToInterface(mreq *syscall.IPMreq, ifi *net.Interface) error {
	if ifi == nil {
		return nil
	}
	ifat, err := ifi.Addrs()
	if err != nil {
		return err
	}
	for _, ifa := range ifat {
		switch v := ifa.(type) {
		case *net.IPAddr:
			if a := v.IP.To4(); a != nil {
				copy(mreq.Interface[:], a)
				goto done
			}
		case *net.IPNet:
			if a := v.IP.To4(); a != nil {
				copy(mreq.Interface[:], a)
				goto done
			}
		}
	}
done:
	if bytes.Equal(mreq.Multiaddr[:], net.IPv4zero.To4()) {
		return errors.New("no such multicast network interface")
	}
	return nil
}

func IsWildcard(addr net.Addr) bool {
	if addr == nil {
		return true
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a.IP == nil {
			return true
		}
		return a.IP.IsUnspecified()
	case *net.UDPAddr:
		if a.IP == nil {
			return true
		}
		return a.IP.IsUnspecified()
	case *net.IPAddr:
		if a.IP == nil {
			return true
		}
		return a.IP.IsUnspecified()
	case *net.UnixAddr:
		return a.Name == ""
	default:
		return false
	}
}

func LoopbackIP(network string) net.IP {
	if network != "" && network[len(network)-1] == '6' {
		return net.IPv6loopback
	}
	return net.IP{127, 0, 0, 1}
}

func ToLocal(network string, addr net.Addr) net.Addr {
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return &net.TCPAddr{IP: LoopbackIP(network), Port: a.Port, Zone: a.Zone}
	case *net.UDPAddr:
		return &net.UDPAddr{IP: LoopbackIP(network), Port: a.Port, Zone: a.Zone}
	case *net.UnixAddr:
		return a
	case *net.IPAddr:
		return &net.IPAddr{IP: LoopbackIP(network), Zone: a.Zone}
	default:
		return nil
	}
}

func AddrPortToSockaddr(ap netip.AddrPort) (sa syscall.Sockaddr, err error) {
	addr := ap.Addr()
	if addr.Is4() {
		return addrPortToSockaddrInet4(ap)
	}
	return addrPortToSockaddrInet6(ap)
}

func addrPortToSockaddrInet4(ap netip.AddrPort) (*syscall.SockaddrInet4, error) {
	addr := ap.Addr()
	if !addr.Is4() {
		return &syscall.SockaddrInet4{}, &net.AddrError{Err: "non-IPv4 address", Addr: addr.String()}
	}
	sa := &syscall.SockaddrInet4{
		Addr: addr.As4(),
		Port: int(ap.Port()),
	}
	return sa, nil
}

func addrPortToSockaddrInet6(ap netip.AddrPort) (*syscall.SockaddrInet6, error) {
	addr := ap.Addr()
	if !addr.IsValid() {
		return &syscall.SockaddrInet6{}, &net.AddrError{Err: "non-IPv6 address", Addr: addr.String()}
	}

	zoneId := uint32(0)
	if ifi, ifiErr := net.InterfaceByName(addr.Zone()); ifiErr == nil {
		zoneId = uint32(ifi.Index)
	}

	sa := &syscall.SockaddrInet6{
		Addr:   addr.As16(),
		Port:   int(ap.Port()),
		ZoneId: zoneId,
	}
	return sa, nil
}
