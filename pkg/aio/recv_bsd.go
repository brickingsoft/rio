//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package aio

import (
	"github.com/brickingsoft/errors"
	"io"
	"runtime"
	"syscall"
)

func Recv(fd NetFd, b []byte, cb OperationCallback) {
	// op
	op := acquireOperator(fd)
	// msg
	op.b = b

	op.callback = cb
	op.completion = completeRecv

	cylinder := nextKqueueCylinder()
	op.setCylinder(cylinder)

	if err := cylinder.prepareRead(fd.Fd(), op); err != nil {
		err = errors.New(
			"receive failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpRecv),
			errors.WithWrap(err),
		)
		cb(Userdata{}, err)
		releaseOperator(op)
	}
	return
}

func completeRecv(result int, op *Operator, err error) {
	cb := op.callback
	fd := op.fd
	b := op.b

	releaseOperator(op)

	if err != nil {
		if errors.Is(err, ErrClosed) && result == 0 {
			cb(Userdata{}, io.EOF)
			return
		}
		err = errors.New(
			"receive failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpRecv),
			errors.WithWrap(err),
		)
		cb(Userdata{}, err)
		return
	}
	if result == 0 && fd.ZeroReadIsEOF() {
		cb(Userdata{}, io.EOF)
		return
	}

	if result > len(b) {
		b = b[:result]
	}
	for {
		n, rErr := syscall.Read(fd.Fd(), b)
		if rErr != nil {
			n = 0
			if errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.EAGAIN) {
				continue
			}
			err = errors.New(
				"receive failed",
				errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
				errors.WithMeta(errMetaOpKey, errMetaOpRecv),
				errors.WithWrap(rErr),
			)
			cb(Userdata{}, err)
			break
		}
		if n == 0 && fd.ZeroReadIsEOF() {
			cb(Userdata{}, io.EOF)
			break
		}
		cb(Userdata{N: n}, nil)
		break
	}
	runtime.KeepAlive(b)
	return
}

func RecvFrom(fd NetFd, b []byte, cb OperationCallback) {
	// op
	op := acquireOperator(fd)
	// msg
	op.b = b

	op.callback = cb
	op.completion = completeRecvFrom

	cylinder := nextKqueueCylinder()
	op.setCylinder(cylinder)

	if err := cylinder.prepareRead(fd.Fd(), op); err != nil {
		err = errors.New(
			"receive from failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpRecvFrom),
			errors.WithWrap(err),
		)
		cb(Userdata{}, err)
		releaseOperator(op)
	}
	return
}

func completeRecvFrom(result int, op *Operator, err error) {
	cb := op.callback
	fd := op.fd.(NetFd)
	b := op.b

	releaseOperator(op)

	if err != nil {
		err = errors.New(
			"receive from failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpRecvFrom),
			errors.WithWrap(err),
		)
		cb(Userdata{}, err)
		return
	}
	if result == 0 {
		cb(Userdata{}, nil)
		return
	}

	network := fd.Network()

	if result > len(b) {
		b = b[:result]
	}

	for {
		n, sa, rErr := syscall.Recvfrom(fd.Fd(), b, 0)
		if rErr != nil {
			if errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.EAGAIN) {
				continue
			}
			err = errors.New(
				"receive from failed",
				errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
				errors.WithMeta(errMetaOpKey, errMetaOpRecvFrom),
				errors.WithWrap(rErr),
			)
			cb(Userdata{}, err)
			break
		}
		addr := SockaddrToAddr(network, sa)
		cb(Userdata{N: n, Addr: addr}, nil)
		break
	}
	runtime.KeepAlive(b)
	return
}

func RecvMsg(fd NetFd, b []byte, oob []byte, cb OperationCallback) {
	// op
	op := acquireOperator(fd)
	// msg
	op.b = b
	op.oob = oob

	op.callback = cb
	op.completion = completeRecvMsg

	cylinder := nextKqueueCylinder()
	op.setCylinder(cylinder)

	if err := cylinder.prepareRead(fd.Fd(), op); err != nil {
		err = errors.New(
			"receive message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpRecvMsg),
			errors.WithWrap(err),
		)
		cb(Userdata{}, err)
		releaseOperator(op)
	}
	return
}

func completeRecvMsg(result int, op *Operator, err error) {
	cb := op.callback
	fd := op.fd.(NetFd)
	b := op.b
	oob := op.oob

	releaseOperator(op)
	if err != nil {
		err = errors.New(
			"receive message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithMeta(errMetaOpKey, errMetaOpRecvMsg),
			errors.WithWrap(err),
		)
		cb(Userdata{}, err)
		return
	}
	if result == 0 {
		cb(Userdata{}, nil)
		return
	}
	network := fd.Network()
	if result > len(b) {
		b = b[:result]
	}
	for {
		n, oobn, flags, sa, rErr := syscall.Recvmsg(fd.Fd(), b, oob, 0)
		if rErr != nil {
			if errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.EAGAIN) {
				continue
			}
			err = errors.New(
				"receive message failed",
				errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
				errors.WithMeta(errMetaOpKey, errMetaOpRecvMsg),
				errors.WithWrap(rErr),
			)
			cb(Userdata{}, err)
			break
		}
		addr := SockaddrToAddr(network, sa)
		cb(Userdata{N: n, OOBN: oobn, Addr: addr, MessageFlags: flags}, nil)
		break
	}
	runtime.KeepAlive(b)
	return
}
