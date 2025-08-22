//go:build linux

package aio

import (
	"errors"
	"syscall"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) PrepareNop() {
	op.code = liburing.IORING_OP_NOP
	return
}

func (op *Operation) PrepareCloseRing(key uint64) {
	op.code = liburing.IORING_OP_NOP
	op.cmd = op_cmd_close_ring
	op.fd = int(key)
	return
}

func (op *Operation) PrepareRegisterBufferAndRing(bgid uint16) {
	op.kind = op_kind_register
	op.cmd = op_cmd_register_buffer_and_ring
	op.addrLen = uint32(bgid)
	return
}

func (op *Operation) PrepareUnregisterBufferAndRing(br *BufferAndRing) {
	op.kind = op_kind_register
	op.cmd = op_cmd_unregister_buffer_and_ring
	op.addr = unsafe.Pointer(br)
	return
}

func (op *Operation) packingNop(sqe *liburing.SubmissionQueueEntry) (err error) {
	switch op.cmd {
	case op_cmd_close_ring:
		sqe.PrepareNop()
		sqe.SetData64(uint64(op.fd))
		break
	default:
		sqe.PrepareNop()
		break
	}
	return
}

func (op *Operation) PrepareLinkTimeout(deadline time.Time) {
	timeout := time.Until(deadline)
	if timeout < 1 {
		timeout = 1 * time.Millisecond
	}
	ts := syscall.NsecToTimespec(timeout.Nanoseconds())
	op.code = liburing.IORING_OP_LINK_TIMEOUT
	op.addr = unsafe.Pointer(&ts)
}

func (op *Operation) packingLinkTimeout(sqe *liburing.SubmissionQueueEntry) (err error) {
	if op.addr == nil {
		return NewInvalidOpErr(errors.New("invalid link_timeout"))
	}
	ts := (*syscall.Timespec)(op.addr)
	sqe.PrepareLinkTimeout(ts, 0)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareMSGRing(ringFd int, n uint32, cqeFlags uint32) {
	op.code = liburing.IORING_OP_MSG_RING
	op.cmd = op_cmd_msg_ring
	op.fd = ringFd
	op.addrLen = n
	op.addr2Len = cqeFlags
	return
}

func (op *Operation) PrepareMSGRingFd(ringFd int, sourceFd int, attachment *Operation) {
	op.code = liburing.IORING_OP_MSG_RING
	op.cmd = op_cmd_msg_ring_fd
	op.fd = ringFd
	op.addr = unsafe.Pointer(uintptr(sourceFd))
	if attachment != nil {
		op.addr2 = unsafe.Pointer(attachment)
	}
	return
}

func (op *Operation) packingMSGRing(sqe *liburing.SubmissionQueueEntry) (err error) {
	switch op.cmd {
	case op_cmd_msg_ring:
		fd := op.fd
		length := op.addrLen
		cqeFlags := op.addr2Len
		sqe.PrepareMsgRingCQEFlags(fd, length, nil, 0, cqeFlags)
		break
	case op_cmd_msg_ring_fd:
		fd := op.fd
		sourceFd := int(uintptr(op.addr))
		userdata := op.addr2
		sqe.PrepareMsgRingFdAlloc(fd, sourceFd, userdata, 0)
		break
	default:
		err = NewInvalidOpErr(errors.New("invalid cmd"))
		return
	}
	if op.timeout != nil {
		sqe.SetFlags(liburing.IOSQE_IO_LINK)
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepPollAdd(fd int, fixed bool, mask uint32) {
	op.code = liburing.IORING_OP_POLL_ADD
	op.fd = fd
	if fixed {
		op.addrLen = 1
	}
	op.addr2Len = mask
}

func (op *Operation) packingPollAdd(sqe *liburing.SubmissionQueueEntry) (err error) {
	sqe.PreparePollAdd(op.fd, op.addr2Len)
	if op.addrLen == 1 {
		sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}
