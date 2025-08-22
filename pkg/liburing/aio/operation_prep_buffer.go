//go:build linux

package aio

import (
	"syscall"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) PrepareProvideBuffers(bgid int, buffers []syscall.Iovec) {
	op.code = liburing.IORING_OP_PROVIDE_BUFFERS
	op.fd = bgid
	op.addr = unsafe.Pointer(&buffers[0])
	op.addrLen = uint32(len(buffers))
	return
}

func (op *Operation) packingProvideBuffers(sqe *liburing.SubmissionQueueEntry) (err error) {
	bgid := op.fd
	addr := uintptr(op.addr)
	addrLen := op.addrLen
	nr := int(addrLen)
	sqe.PrepareProvideBuffers(addr, addrLen, nr, bgid, 0)
	if op.timeout != nil {
		sqe.SetFlags(liburing.IOSQE_IO_LINK)
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareRemoveBuffers(bgid int, nr int) {
	op.code = liburing.IORING_OP_REMOVE_BUFFERS
	op.fd = bgid
	op.addrLen = uint32(nr)
	return
}

func (op *Operation) packingRemoveBuffers(sqe *liburing.SubmissionQueueEntry) (err error) {
	bgid := op.fd
	nr := int(op.addrLen)
	sqe.PrepareRemoveBuffers(nr, bgid)
	if op.timeout != nil {
		sqe.SetFlags(liburing.IOSQE_IO_LINK)
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}
