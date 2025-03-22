//go:build linux

package aio

import (
	"github.com/brickingsoft/rio/pkg/iouring"
	"syscall"
	"unsafe"
)

func (op *Operation) PrepareClose(fd int) {
	op.code = iouring.OpClose
	op.fd = fd
}

func (op *Operation) PrepareCloseDirect(filedIndex int) {
	op.code = iouring.OpClose
	op.filedIndex = filedIndex
	op.directMode = true
}

func (op *Operation) PrepareCloseRead(nfd *NetFd) {
	fd, direct := nfd.FileDescriptor()
	if direct {
		op.sqeFlags |= iouring.SQEFixedFile
	}
	if nfd.Async() {
		op.sqeFlags |= iouring.SQEAsync
	}
	op.code = iouring.OpShutdown
	op.fd = fd
	op.pipe.fdIn = syscall.SHUT_RD
	return
}

func (op *Operation) PrepareCloseWrite(nfd *NetFd) {
	fd, direct := nfd.FileDescriptor()
	if direct {
		op.sqeFlags |= iouring.SQEFixedFile
	}
	if nfd.Async() {
		op.sqeFlags |= iouring.SQEAsync
	}
	op.code = iouring.OpShutdown
	op.fd = fd
	op.pipe.fdIn = syscall.SHUT_WR
	return
}

func (op *Operation) PrepareCancel(target *Operation) {
	op.code = iouring.OpAsyncCancel
	op.ptr = unsafe.Pointer(target)
}

func (op *Operation) PrepareCancelFd(fd int) {
	op.code = iouring.OpAsyncCancel
	op.fd = fd
}

func (op *Operation) PrepareCancelFixedFd(fileIndex int) {
	op.code = iouring.OpAsyncCancel
	op.filedIndex = fileIndex
	op.directMode = true
}

func (op *Operation) PrepareFixedFdInstall(fd int) {
	op.code = iouring.OPFixedFdInstall
	op.fd = fd
}
