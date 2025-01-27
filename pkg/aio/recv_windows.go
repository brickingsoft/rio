//go:build windows

package aio

import (
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func Recv(fd NetFd, b []byte, cb OperationCallback) {
	// check buf
	bLen := len(b)
	if bLen == 0 {
		cb(Userdata{}, ErrEmptyBytes)
		return
	} else if bLen > MaxRW {
		b = b[:MaxRW]
	}
	// op
	op := fd.ReadOperator()
	// msg
	buf := syscall.WSABuf{
		Len: uint32(bLen),
		Buf: &b[0],
	}
	flags := uint32(0)

	// cb
	op.callback = cb
	// completion
	op.completion = completeRecv

	// timeout
	op.tryPrepareTimeout()

	// overlapped
	overlapped := &op.overlapped

	// recv
	err := syscall.WSARecv(
		syscall.Handle(fd.Fd()),
		&buf, 1,
		&op.n, &flags,
		overlapped,
		nil,
	)
	if err != nil && !errors.Is(syscall.ERROR_IO_PENDING, err) {
		// handle err
		cb(Userdata{}, os.NewSyscallError("wsa_recv", err))
		// reset op
		op.reset()
	}
	return
}

func completeRecv(result int, op *Operator, err error) {
	if err != nil {
		err = os.NewSyscallError("wsa_recv", err)
		op.callback(Userdata{}, err)
		return
	}
	if result == 0 && op.fd.ZeroReadIsEOF() {
		op.callback(Userdata{}, io.EOF)
		return
	}
	op.callback(Userdata{N: result}, nil)
	return
}

func RecvFrom(fd NetFd, b []byte, cb OperationCallback) {
	// check buf
	bLen := len(b)
	if bLen == 0 {
		cb(Userdata{}, ErrEmptyBytes)
		return
	}
	// op
	op := fd.ReadOperator()
	// msg
	buf := syscall.WSABuf{
		Len: uint32(bLen),
		Buf: &b[0],
	}
	rsa := syscall.RawSockaddrAny{}
	rsaLen := int32(unsafe.Sizeof(rsa))
	op.rsa = &rsa

	flags := uint32(0)
	// cb
	op.callback = cb
	// completion
	op.completion = completeRecvFrom

	// timeout
	op.tryPrepareTimeout()

	// overlapped
	overlapped := &op.overlapped

	// recv from
	err := syscall.WSARecvFrom(
		syscall.Handle(fd.Fd()),
		&buf, 1,
		&op.n, &flags,
		&rsa, &rsaLen,
		overlapped,
		nil,
	)
	if err != nil && !errors.Is(syscall.ERROR_IO_PENDING, err) {
		// handle err
		cb(Userdata{}, os.NewSyscallError("wsa_recvfrom", err))
		// reset op
		op.reset()
	}
	return
}

func completeRecvFrom(result int, op *Operator, err error) {
	if err != nil {
		err = os.NewSyscallError("wsa_recvfrom", err)
		op.callback(Userdata{}, err)
		return
	}
	addr, addrErr := RawToAddr(op.rsa)
	if addrErr != nil {
		op.callback(Userdata{}, addrErr)
		return
	}
	op.callback(Userdata{N: result, Addr: addr}, nil)
	return
}

func RecvMsg(fd NetFd, b []byte, oob []byte, cb OperationCallback) {
	// check buf
	bLen := len(b)
	if bLen == 0 {
		cb(Userdata{}, ErrEmptyBytes)
		return
	}
	oobLen := len(oob)
	if oobLen == 0 {
		cb(Userdata{}, ErrEmptyBytes)
		return
	}
	// op
	op := fd.ReadOperator()
	// msg
	rsa := syscall.RawSockaddrAny{}
	rsaLen := int32(unsafe.Sizeof(rsa))

	op.msg = &windows.WSAMsg{
		Name:    &rsa,
		Namelen: rsaLen,
		Buffers: &windows.WSABuf{
			Len: uint32(bLen),
			Buf: &b[0],
		},
		BufferCount: 1,
		Control: windows.WSABuf{
			Len: uint32(oobLen),
			Buf: &oob[0],
		},
		Flags: 0,
	}
	if fd.Family() == syscall.AF_UNIX {
		op.msg.Flags = readMsgFlags
	}

	// cb
	op.callback = cb
	// completion
	op.completion = completeRecvMsg

	// timeout
	op.tryPrepareTimeout()

	// overlapped
	overlapped := &op.overlapped
	wsaoverlapped := (*windows.Overlapped)(unsafe.Pointer(overlapped))

	// recv msg
	err := windows.WSARecvMsg(
		windows.Handle(fd.Fd()),
		op.msg,
		&op.n,
		wsaoverlapped,
		nil,
	)
	if err != nil && !errors.Is(windows.ERROR_IO_PENDING, err) {
		// handle err
		cb(Userdata{}, os.NewSyscallError("wsa_recvmsg", err))
		// reset op
		op.reset()
	}
	return
}

func completeRecvMsg(result int, op *Operator, err error) {
	if err != nil {
		err = os.NewSyscallError("wsa_recvmsg", err)
		op.callback(Userdata{}, err)
		return
	}
	addr, addrErr := RawToAddr(op.msg.Name)
	if addrErr != nil {
		op.callback(Userdata{}, addrErr)
		return
	}
	oobn := int(op.msg.Control.Len)
	flags := int(op.msg.Flags)
	op.callback(Userdata{N: result, OOBN: oobn, Addr: addr, MessageFlags: flags}, nil)
	return
}
