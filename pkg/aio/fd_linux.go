//go:build linux

package aio

import (
	"errors"
	"runtime"
	"syscall"
)

func Close(fd Fd, cb OperationCallback) {
	op := fd.WriteOperator()

	op.callback = cb
	op.completion = func(result int, cop *Operator, err error) {
		completeClose(result, cop, err)
		runtime.KeepAlive(op)
	}

	err := prepare(opClose, fd.Fd(), 0, 0, 0, 0, op)
	runtime.KeepAlive(op)
	if err != nil {
		cb(Userdata{}, err)
		op.clean()
	}
}

func completeClose(_ int, op *Operator, err error) {
	if err != nil {
		err = errors.Join(errors.New("aio.Operator: close failed"), err)
		op.callback(Userdata{}, err)
		return
	}
	op.callback(Userdata{}, nil)
	return
}

func CloseImmediately(fd Fd) {
	_ = syscall.Close(fd.Fd())
}
