//go:build linux

package aio

import (
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) PrepareRead(fd *Fd, b []byte) {
	op.code = liburing.IORING_OP_READ
	op.fd = fd.direct
	op.addr = unsafe.Pointer(&b[0])
	op.addrLen = uint32(len(b))
	return
}

func (op *Operation) packingRead(sqe *liburing.SubmissionQueueEntry) (err error) {
	b := uintptr(op.addr)
	bLen := op.addrLen
	sqe.PrepareRead(op.fd, b, bLen, 0)
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareWrite(fd *Fd, b []byte) {
	op.code = liburing.IORING_OP_WRITE
	op.fd = fd.direct
	op.addr = unsafe.Pointer(&b[0])
	op.addrLen = uint32(len(b))
	return
}

func (op *Operation) packingWrite(sqe *liburing.SubmissionQueueEntry) (err error) {
	b := uintptr(op.addr)
	bLen := op.addrLen
	sqe.PrepareWrite(op.fd, b, bLen, 0)
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}

type SpliceParams struct {
	FdIn       int
	FdInFixed  bool
	OffIn      int64
	FdOut      int
	FdOutFixed bool
	OffOut     int64
	NBytes     uint32
	Flags      uint32
}

func (op *Operation) PrepareSplice(params *SpliceParams) {
	op.code = liburing.IORING_OP_SPLICE
	if params.FdInFixed {
		params.Flags |= liburing.SPLICE_F_FD_IN_FIXED
	}
	op.addr = unsafe.Pointer(params)
}

func (op *Operation) packingSplice(sqe *liburing.SubmissionQueueEntry) (err error) {
	params := (*SpliceParams)(op.addr)
	sqe.PrepareSplice(params.FdIn, params.OffIn, params.FdOut, params.OffOut, params.NBytes, params.Flags)
	if params.FdOutFixed {
		sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}
