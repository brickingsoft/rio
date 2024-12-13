//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package aio

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

func Recv(fd NetFd, b []byte, cb OperationCallback) {
	bLen := len(b)
	if bLen == 0 {
		cb(0, Userdata{}, ErrEmptyBytes)
		return
	}
	if bLen > MaxRW {
		b = b[:MaxRW]
	}

	op := ReadOperator(fd)
	op.userdata.Msg.Append(b)
	op.callback = cb
	op.completion = func(result int, cop *Operator, err error) {
		completeRecv(result, cop, err)
		runtime.KeepAlive(op)
	}

	cylinder := nextKqueueCylinder()

	if timeout := op.timeout; timeout > 0 {
		timer := getOperatorTimer()
		op.timer = timer
		timer.Start(timeout, &operatorCanceler{
			cylinder: cylinder,
			op:       op,
		})
	}

	if err := cylinder.prepareRead(fd.Fd(), op); err != nil {
		cb(0, Userdata{}, err)
		// reset
		op.callback = nil
		op.completion = nil
		if timer := op.timer; timer != nil {
			timer.Done()
			putOperatorTimer(timer)
		}
	}

	return
}

func completeRecv(result int, op *Operator, err error) {
	cb := op.callback
	userdata := op.userdata
	if err != nil || result == 0 {
		cb(0, userdata, err)
		return
	}

	fd := op.fd.Fd()
	b := userdata.Msg.Bytes(0)
	for {
		// todo see internal/poll/fd_unix.go
		n, rErr := syscall.Read(fd, b)
		if rErr != nil {
			n = 0
			if errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.EAGAIN) {
				continue
			}
			cb(n, userdata, rErr)
			break
		}
		cb(n, userdata, eofError(op.fd, n, nil))
		break
	}
	runtime.KeepAlive(userdata)
	return
}

func RecvFrom(fd NetFd, b []byte, cb OperationCallback) {
	bLen := len(b)
	if bLen == 0 {
		cb(0, Userdata{}, ErrEmptyBytes)
		return
	}

	op := ReadOperator(fd)
	op.userdata.Msg.Append(b)
	op.callback = cb
	op.completion = func(result int, cop *Operator, err error) {
		completeRecvFrom(result, cop, err)
		runtime.KeepAlive(op)
	}

	cylinder := nextKqueueCylinder()

	if timeout := op.timeout; timeout > 0 {
		timer := getOperatorTimer()
		op.timer = timer
		timer.Start(timeout, &operatorCanceler{
			cylinder: cylinder,
			op:       op,
		})
	}

	if err := cylinder.prepareRead(fd.Fd(), op); err != nil {
		cb(0, Userdata{}, err)
		// reset
		op.callback = nil
		op.completion = nil
		if timer := op.timer; timer != nil {
			timer.Done()
			putOperatorTimer(timer)
		}
	}
	return
}

func completeRecvFrom(result int, op *Operator, err error) {
	cb := op.callback
	userdata := op.userdata
	if err != nil || result == 0 {
		cb(0, userdata, err)
		return
	}
	fd := op.fd.Fd()
	b := userdata.Msg.Bytes(0)
	for {
		// todo see internal/poll/fd_unix.go
		n, sa, rErr := syscall.Recvfrom(fd, b, 0)
		if rErr != nil {
			n = 0
			if errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.EAGAIN) {
				continue
			}
			cb(n, userdata, rErr)
			break
		}
		rsa, rsaLen, rsaErr := SockaddrToRaw(sa)
		if rsaErr != nil {
			cb(n, userdata, rsaErr)
			break
		}
		userdata.Msg.Name = (*byte)(unsafe.Pointer(rsa))
		userdata.Msg.Namelen = uint32(rsaLen)

		cb(n, userdata, nil)
		break
	}
	runtime.KeepAlive(userdata)
	return
}

func RecvMsg(fd NetFd, b []byte, oob []byte, cb OperationCallback) {

	return
}

func completeRecvMsg(result int, op *Operator, err error) {

	return
}
