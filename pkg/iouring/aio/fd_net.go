//go:build linux

package aio

import (
	"errors"
	"fmt"
	"github.com/brickingsoft/rio/pkg/iouring"
	"github.com/brickingsoft/rio/pkg/iouring/aio/sys"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"reflect"
	"syscall"
	"time"
)

type OpenNetFdMode string

const (
	ListenMode OpenNetFdMode = "listen"
	DialMode   OpenNetFdMode = "dial"
)

func OpenNetFd(
	vortex *Vortex,
	mode OpenNetFdMode,
	network string, sotype int, proto int,
	laddr net.Addr, raddr net.Addr,
	directAlloc bool,
) (fd *NetFd, err error) {
	if laddr != nil && reflect.ValueOf(laddr).IsNil() {
		laddr = nil
	}
	if raddr != nil && reflect.ValueOf(raddr).IsNil() {
		raddr = nil
	}
	if laddr == nil && raddr == nil {
		err = errors.New("missing address")
		return
	}
	// sock
	family, ipv6only := sys.FavoriteAddrFamily(network, laddr, raddr, string(mode))
	var (
		regular = -1
		direct  = -1
		sockErr error
	)
	if directAlloc {
		op := vortex.acquireOperation()
		op.WithDirect(true).PrepareSocket(family, sotype|syscall.SOCK_NONBLOCK, proto)
		direct, _, sockErr = vortex.submitAndWait(op)
		vortex.releaseOperation(op)
		if sockErr == nil && mode == ListenMode {
			regular, sockErr = vortex.FixedFdInstall(direct)
		}
	} else {
		regular, sockErr = syscall.Socket(family, sotype|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, proto)
	}
	if sockErr != nil {
		err = sockErr
		return
	}
	// fd
	fd = &NetFd{
		Fd: Fd{
			regular:       regular,
			direct:        direct,
			allocated:     directAlloc,
			isStream:      sotype == syscall.SOCK_STREAM,
			zeroReadIsEOF: sotype != syscall.SOCK_DGRAM && sotype != syscall.SOCK_RAW,
			async:         false,
			inAdvanceIO:   false,
			vortex:        vortex,
		},
		family: family,
		sotype: sotype,
		net:    network,
		laddr:  laddr,
		raddr:  raddr,
	}
	// ipv6
	if ipv6only {
		if err = fd.SetIpv6only(true); err != nil {
			_ = fd.Close()
			return
		}
	}
	// zero copy
	if err = fd.SetZeroCopy(true); err != nil {
		_ = fd.Close()
		return
	}
	return
}

type NetFd struct {
	Fd
	family int
	sotype int
	net    string
	laddr  net.Addr
	raddr  net.Addr
}

func (fd *NetFd) Name() string {
	name := fd.Fd.Name()
	var ls, rs string
	if fd.laddr != nil {
		ls = fd.laddr.String()
	}
	if fd.raddr != nil {
		rs = fd.raddr.String()
	}
	return fmt.Sprintf("%s[network:%s][laddr:%s][raddr:%s]", name, fd.net, ls, rs)
}

func (fd *NetFd) Family() int {
	return fd.family
}

func (fd *NetFd) SocketType() int {
	return fd.sotype
}

func (fd *NetFd) Net() string {
	return fd.net
}

func (fd *NetFd) LocalAddr() net.Addr {
	if fd.laddr == nil {
		if !fd.Installed() {
			if installErr := fd.Install(); installErr != nil {
				return nil
			}
		}
		sa, saErr := syscall.Getsockname(fd.regular)
		if saErr != nil {
			return nil
		}
		fd.laddr = sys.SockaddrToAddr(fd.net, sa)
	}
	return fd.laddr
}

func (fd *NetFd) SetLocalAddr(addr net.Addr) {
	fd.laddr = addr
}

func (fd *NetFd) RemoteAddr() net.Addr {
	if fd.raddr == nil {
		if !fd.Installed() {
			if installErr := fd.Install(); installErr != nil {
				return nil
			}
		}
		sa, saErr := syscall.Getpeername(fd.regular)
		if saErr != nil {
			return nil
		}
		fd.raddr = sys.SockaddrToAddr(fd.net, sa)
	}
	return fd.raddr
}

func (fd *NetFd) SetRemoteAddr(addr net.Addr) {
	fd.raddr = addr
}

func (fd *NetFd) ReadBuffer() (n int, err error) {
	if fd.Installed() {
		n, err = syscall.GetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if err != nil {
			err = os.NewSyscallError("getsockopt", err)
			return
		}
	} else {
		n, err = fd.GetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}
	return
}

func (fd *NetFd) SetReadBuffer(bytes int) error {
	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)
	}
	return nil
}

func (fd *NetFd) WriteBuffer() (n int, err error) {
	if fd.Installed() {
		n, err = syscall.GetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		if err != nil {
			err = os.NewSyscallError("getsockopt", err)
			return
		}
	} else {
		n, err = fd.GetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}
	return
}

func (fd *NetFd) SetWriteBuffer(bytes int) error {
	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)
	}
	return nil
}

func (fd *NetFd) SetZeroCopy(ok bool) (err error) {
	if fd.family == syscall.AF_INET || fd.family == syscall.AF_INET6 {
		if iouring.VersionEnable(4, 14, 0) {
			if fd.Installed() {
				if err = syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, unix.SO_ZEROCOPY, boolint(ok)); err != nil {
					return os.NewSyscallError("setsockopt", err)
				}
			} else {
				return fd.SetSocketoptInt(syscall.SOL_SOCKET, unix.SO_ZEROCOPY, boolint(ok))
			}
			return
		}
	}
	return
}

func (fd *NetFd) SetNoDelay(noDelay bool) error {
	if fd.sotype&syscall.SOCK_STREAM != 0 {
		if fd.Installed() {
			if err := syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, boolint(noDelay)); err != nil {
				return os.NewSyscallError("setsockopt", err)
			}
		} else {
			return fd.SetSocketoptInt(syscall.IPPROTO_TCP, syscall.TCP_NODELAY, boolint(noDelay))
		}
	}
	return nil
}

func (fd *NetFd) SetLinger(sec int) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}

	var l syscall.Linger
	if sec >= 0 {
		l.Onoff = 1
		l.Linger = int32(sec)
	} else {
		l.Onoff = 0
		l.Linger = 0
	}
	if err := syscall.SetsockoptLinger(fd.regular, syscall.SOL_SOCKET, syscall.SO_LINGER, &l); err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

const (
	// defaultTCPKeepAliveIdle is a default constant value for TCP_KEEPIDLE.
	// See go.dev/issue/31510 for details.
	defaultTCPKeepAliveIdle = 15 * time.Second

	// defaultTCPKeepAliveInterval is a default constant value for TCP_KEEPINTVL.
	// It is the same as defaultTCPKeepAliveIdle, see go.dev/issue/31510 for details.
	defaultTCPKeepAliveInterval = 15 * time.Second

	// defaultTCPKeepAliveCount is a default constant value for TCP_KEEPCNT.
	defaultTCPKeepAliveCount = 9
)

func roundDurationUp(d time.Duration, to time.Duration) time.Duration {
	return (d + to - 1) / to
}

func (fd *NetFd) SetKeepAlive(keepalive bool) error {
	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(keepalive)); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, boolint(keepalive))
	}
	return nil
}

func (fd *NetFd) SetKeepAlivePeriod(d time.Duration) error {
	if d == 0 {
		d = defaultTCPKeepAliveIdle
	} else if d < 0 {
		return nil
	}
	secs := int(roundDurationUp(d, time.Second))

	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, secs); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, secs)
	}
	return nil
}

func (fd *NetFd) SetKeepAliveInterval(d time.Duration) error {
	if d == 0 {
		d = defaultTCPKeepAliveInterval
	} else if d < 0 {
		return nil
	}
	secs := int(roundDurationUp(d, time.Second))

	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, secs); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, secs)
	}
	return nil
}

func (fd *NetFd) SetKeepAliveCount(n int) error {
	if n == 0 {
		n = defaultTCPKeepAliveCount
	} else if n < 0 {
		return nil
	}

	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, n); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, n)
	}
	return nil
}

func (fd *NetFd) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	if err := fd.SetKeepAlive(config.Enable); err != nil {
		return err
	}
	if err := fd.SetKeepAlivePeriod(config.Idle); err != nil {
		return err
	}
	if err := fd.SetKeepAliveInterval(config.Interval); err != nil {
		return err
	}
	if err := fd.SetKeepAliveCount(config.Count); err != nil {
		return err
	}
	return nil
}

func (fd *NetFd) CloseRead() error {
	if fd.direct > -1 {
		op := fd.vortex.acquireOperation()
		op.PrepareCloseRead(fd)
		_, _, err := fd.vortex.submitAndWait(op)
		fd.vortex.releaseOperation(op)
		return err
	}
	return syscall.Shutdown(fd.regular, syscall.SHUT_RD)
}

func (fd *NetFd) CloseWrite() error {
	if fd.direct > -1 {
		op := fd.vortex.acquireOperation()
		op.PrepareCloseWrite(fd)
		_, _, err := fd.vortex.submitAndWait(op)
		fd.vortex.releaseOperation(op)
		return err
	}
	return syscall.Shutdown(fd.regular, syscall.SHUT_WR)
}

func (fd *NetFd) SetIpv6only(ipv6only bool) error {
	if fd.family == syscall.AF_INET6 && fd.sotype&syscall.SOCK_RAW == 0 {
		if fd.Installed() {
			if err := syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolint(ipv6only)); err != nil {
				return os.NewSyscallError("setsockopt", err)
			}
		} else {
			return fd.SetSocketoptInt(syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, boolint(ipv6only))
		}
	}
	return nil
}

func (fd *NetFd) SetBroadcast(ok bool) error {
	if (fd.sotype == syscall.SOCK_DGRAM || fd.sotype&syscall.SOCK_RAW == 0) && fd.family != syscall.AF_UNIX && fd.family != syscall.AF_INET6 {
		if fd.Installed() {
			if err := syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_BROADCAST, boolint(ok)); err != nil {
				return os.NewSyscallError("setsockopt", err)
			}
		} else {
			return fd.SetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_BROADCAST, boolint(ok))
		}
	}
	return nil
}

func (fd *NetFd) SetReuseAddr(ok bool) error {
	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, boolint(ok)); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.SOL_SOCKET, syscall.SO_REUSEADDR, boolint(ok))
	}
	return nil
}

func (fd *NetFd) SetTcpDeferAccept(ok bool) error {
	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, boolint(ok)); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, boolint(ok))
	}
	return nil
}

func (fd *NetFd) SetReusePort(reusePort int) error {
	if fd.Installed() {
		if err := syscall.SetsockoptInt(fd.regular, syscall.SOL_SOCKET, unix.SO_REUSEPORT, reusePort); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	} else {
		return fd.SetSocketoptInt(syscall.SOL_SOCKET, unix.SO_REUSEPORT, reusePort)
	}
	return nil
}

func (fd *NetFd) SetIPv4MulticastInterface(ifi *net.Interface) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}
	ip, err := sys.InterfaceToIPv4Addr(ifi)
	if err != nil {
		return err
	}
	var a [4]byte
	copy(a[:], ip.To4())
	return syscall.SetsockoptInet4Addr(fd.regular, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, a)
}

func (fd *NetFd) SetIPv4MulticastLoopback(ok bool) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, boolint(ok)))
}

func (fd *NetFd) JoinIPv4Group(ifi *net.Interface, ip net.IP) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}
	mreq := &syscall.IPMreq{Multiaddr: [4]byte{ip[0], ip[1], ip[2], ip[3]}}
	if err := sys.SetIPv4MreqToInterface(mreq, ifi); err != nil {
		return err
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptIPMreq(fd.regular, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq))
}

func (fd *NetFd) SetIPv6MulticastInterface(ifi *net.Interface) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}
	var v int
	if ifi != nil {
		v = ifi.Index
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, v))
}

func (fd *NetFd) SetIPv6MulticastLoopback(ok bool) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd.regular, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, boolint(ok)))
}

func (fd *NetFd) JoinIPv6Group(ifi *net.Interface, ip net.IP) error {
	if !fd.Installed() {
		if installErr := fd.Install(); installErr != nil {
			return installErr
		}
	}
	mreq := &syscall.IPv6Mreq{}
	copy(mreq.Multiaddr[:], ip)
	if ifi != nil {
		mreq.Interface = uint32(ifi.Index)
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptIPv6Mreq(fd.regular, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq))
}

func (fd *NetFd) CtrlNetwork() string {
	switch fd.net {
	case "unix", "unixgram", "unixpacket":
		return fd.net
	}
	switch fd.net[len(fd.net)-1] {
	case '4', '6':
		return fd.net
	}
	if fd.family == syscall.AF_INET {
		return fd.net + "4"
	}
	return fd.net + "6"
}
