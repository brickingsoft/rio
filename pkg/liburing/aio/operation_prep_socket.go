//go:build linux

package aio

import (
	"syscall"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) PrepareSocket(family int, sotype int, proto int) {
	op.code = liburing.IORING_OP_SOCKET
	op.fd = family
	op.addr = unsafe.Pointer(uintptr(sotype))
	op.addrLen = uint32(proto)
	return
}

func (op *Operation) packingSocket(sqe *liburing.SubmissionQueueEntry) (err error) {
	family := op.fd
	sotype := int(uintptr(op.addr))
	proto := int(op.addrLen)
	sqe.PrepareSocketDirectAlloc(family, sotype|syscall.SOCK_NONBLOCK, proto, 0)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareSetSocketoptInt(nfd *NetFd, level int, optName int, optValue *int) {
	op.PrepareSetSocketopt(nfd, level, optName, unsafe.Pointer(optValue), 4)
	return
}

func (op *Operation) PrepareGetSocketoptInt(nfd *NetFd, level int, optName int, optValue *int) {
	optValueLen := int32(4)
	op.PrepareGetSocketopt(nfd, level, optName, unsafe.Pointer(optValue), &optValueLen)
	return
}

func (op *Operation) PrepareSetSocketopt(nfd *NetFd, level int, optName int, optValue unsafe.Pointer, optValueLen int32) {
	op.code = liburing.IORING_OP_URING_CMD
	op.cmd = liburing.SOCKET_URING_OP_SETSOCKOPT
	op.fd = nfd.direct
	op.addr = unsafe.Pointer(uintptr(level))
	op.addrLen = uint32(optName)
	op.addr2 = optValue
	op.addr2Len = uint32(optValueLen)
	return
}

func (op *Operation) packingSetSocketopt(sqe *liburing.SubmissionQueueEntry) (err error) {
	fd := op.fd
	level := int(uintptr(op.addr))
	optName := int(op.addrLen)
	optValue := op.addr2
	optValueLen := int32(op.addr2Len)
	sqe.PrepareSetsockopt(fd, level, optName, optValue, optValueLen)
	sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareGetSocketopt(nfd *NetFd, level int, optName int, optValue unsafe.Pointer, optValueLen *int32) {
	op.code = liburing.IORING_OP_URING_CMD
	op.cmd = liburing.SOCKET_URING_OP_GETSOCKOPT
	op.fd = nfd.direct
	op.addr = unsafe.Pointer(uintptr(level))
	op.addrLen = uint32(optName)
	op.addr2 = optValue
	op.addr2Len = uint32(uintptr(unsafe.Pointer(optValueLen)))
	return
}

func (op *Operation) packingGetSocketopt(sqe *liburing.SubmissionQueueEntry) (err error) {
	fd := op.fd
	level := int(uintptr(op.addr))
	optName := int(op.addrLen)
	optValue := op.addr2
	optValueLen := (*int32)(unsafe.Pointer(uintptr(op.addr2Len)))
	sqe.PrepareGetsockopt(fd, level, optName, optValue, optValueLen)
	sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	sqe.SetData(unsafe.Pointer(op))
	return err
}
