//go:build linux

package aio

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"unsafe"
)

type operatorCanceler struct {
	cylinder *IOURingCylinder
	op       *Operator
}

func (canceler *operatorCanceler) Cancel() {
	cylinder := canceler.cylinder
	op := canceler.op
	userdata := uint64(uintptr(unsafe.Pointer(op)))
	cancelOp := &Operator{
		userdata:   Userdata{},
		fd:         nil,
		callback:   nil,
		completion: nil,
		timeout:    0,
		timer:      nil,
	}
	cancelOp.completion = func(_ int, _ *Operator, _ error) {
		runtime.KeepAlive(cancelOp)
	}
	for i := 0; i < 10; i++ {
		err := cylinder.prepare(opAsyncCancel, -1, uintptr(userdata), 0, 0, 0, cancelOp)
		if err == nil {
			break
		}
		if IsBusyError(err) {
			continue
		}
	}
	runtime.KeepAlive(userdata)
	runtime.KeepAlive(cancelOp)
}

type Message struct {
	syscall.Msghdr
}

func (msg *Message) Addr() (addr net.Addr, err error) {
	if msg.Name == nil {
		err = errors.Join(errors.New("aio.Message: get addr failed"), errors.New("addr is nil"))
		return
	}
	sa, saErr := RawToSockaddr((*syscall.RawSockaddrAny)(unsafe.Pointer(msg.Name)))
	if saErr != nil {
		err = errors.Join(errors.New("aio.Message: get addr failed"), saErr)
		return
	}

	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &net.UDPAddr{
			IP:   append([]byte{}, a.Addr[:]...),
			Port: a.Port,
		}
		break
	case *syscall.SockaddrInet6:
		zone := ""
		if a.ZoneId != 0 {
			ifi, ifiErr := net.InterfaceByIndex(int(a.ZoneId))
			if ifiErr != nil {
				err = errors.Join(errors.New("aio.Message: get addr failed"), ifiErr)
			}
			zone = ifi.Name
		}
		addr = &net.UDPAddr{
			IP:   append([]byte{}, a.Addr[:]...),
			Port: a.Port,
			Zone: zone,
		}
		break
	case *syscall.SockaddrUnix:
		addr = &net.UnixAddr{Net: "unixgram", Name: a.Name}
		break
	default:
		err = errors.Join(errors.New("aio.Message: get addr failed"), errors.New("unknown address type"))
		return
	}
	return
}

func (msg *Message) Bytes(n int) (b []byte) {
	if n < 0 || n > int(msg.Iovlen) {
		return
	}
	if msg.Iovlen == 0 {
		return
	}
	buffers := unsafe.Slice(msg.Iov, msg.Iovlen)
	buffer := buffers[n]
	b = unsafe.Slice(buffer.Base, buffer.Len)
	return
}

func (msg *Message) ControlBytes() (b []byte) {
	if msg.Controllen == 0 {
		return
	}
	b = unsafe.Slice(msg.Control, msg.Controllen)
	return
}

func (msg *Message) ControlLen() int {
	return int(msg.Controllen)
}

func (msg *Message) Flags() int32 {
	return msg.Msghdr.Flags
}

func (msg *Message) BuildRawSockaddrAny() (*syscall.RawSockaddrAny, int32) {
	rsa := new(syscall.RawSockaddrAny)
	msg.Msghdr.Name = (*byte)(unsafe.Pointer(rsa))
	msg.Msghdr.Namelen = syscall.SizeofSockaddrAny
	return rsa, int32(msg.Msghdr.Namelen)
}

func (msg *Message) SetAddr(addr net.Addr) (sa syscall.Sockaddr, err error) {
	sa = AddrToSockaddr(addr)
	name, nameLen, rawErr := SockaddrToRaw(sa)
	if rawErr != nil {
		panic(errors.New("aio.Message: set addr failed cause invalid addr type"))
		return
	}
	msg.Name = (*byte)(unsafe.Pointer(name))
	msg.Namelen = uint32(nameLen)
	return
}

func (msg *Message) Append(b []byte) (buf syscall.Iovec) {
	buf = syscall.Iovec{
		Len:  uint64(len(b)),
		Base: nil,
	}
	if buf.Len > 0 {
		buf.Base = &b[0]
	}
	if msg.Iovlen == 0 {
		msg.Iov = &buf
	} else {
		buffers := unsafe.Slice(msg.Iov, msg.Iovlen)
		buffers = append(buffers, buf)
		msg.Iov = &buffers[0]
	}
	msg.Iovlen++
	return
}

func (msg *Message) SetControl(b []byte) {
	bLen := uint64(len(b))
	if bLen > 64 {
		b = b[:64]
		bLen = 64
	}
	msg.Controllen = bLen
	if msg.Controllen > 0 {
		msg.Control = &b[0]
	}
}

func (msg *Message) SetFlags(flags uint32) {
	msg.Msghdr.Flags = int32(flags)
}
