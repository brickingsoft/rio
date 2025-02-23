//go:build windows

package aio

import (
	"syscall"
)

func CancelRead(fd Fd) {
	if op := fd.ROP(); op != nil {
		if received := op.received.Load(); received {
			return
		}
		handle := syscall.Handle(fd.Fd())
		overlapped := &op.overlapped
		_ = syscall.CancelIoEx(handle, overlapped)
	}
}

func CancelWrite(fd Fd) {
	if op := fd.WOP(); op != nil {
		if received := op.received.Load(); received {
			return
		}
		handle := syscall.Handle(fd.Fd())
		overlapped := &op.overlapped
		_ = syscall.CancelIoEx(handle, overlapped)
	}
}
