//go:build linux

package aio

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) PrepareClose(fd int) {
	op.cmd = op_cmd_close_regular
	op.code = liburing.IORING_OP_CLOSE
	op.fd = fd
}

func (op *Operation) PrepareCloseDirect(filedIndex int) {
	op.cmd = op_cmd_close_direct
	op.code = liburing.IORING_OP_CLOSE
	op.fd = filedIndex
}

func (op *Operation) packingClose(sqe *liburing.SubmissionQueueEntry) (err error) {
	switch op.cmd {
	case op_cmd_close_regular:
		sqe.PrepareClose(op.fd)
		break
	case op_cmd_close_direct:
		sqe.PrepareCloseDirect(uint32(op.fd))
		break
	default:
		err = errors.New("undefined close fd op cmd")
		return
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareCloseRead(conn *Conn) {
	op.code = liburing.IORING_OP_SHUTDOWN
	op.fd = conn.direct
	op.cmd = syscall.SHUT_RD
	return
}

func (op *Operation) PrepareCloseWrite(conn *Conn) {
	op.code = liburing.IORING_OP_SHUTDOWN
	op.fd = conn.direct
	op.cmd = syscall.SHUT_WR
	return
}

func (op *Operation) packingShutdown(sqe *liburing.SubmissionQueueEntry) (err error) {
	cmd := op.cmd
	sqe.PrepareShutdown(op.fd, cmd)
	sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareCancel(target *Operation) {
	op.code = liburing.IORING_OP_ASYNC_CANCEL
	op.cmd = op_cmd_cancel_op
	op.addr = unsafe.Pointer(target)
}

func (op *Operation) PrepareCancelFd(fd int) {
	op.code = liburing.IORING_OP_ASYNC_CANCEL
	op.cmd = op_cmd_cancel_regular
	op.fd = fd
}

func (op *Operation) PrepareCancelFixedFd(fileIndex int) {
	op.code = liburing.IORING_OP_ASYNC_CANCEL
	op.fd = fileIndex
	op.cmd = op_cmd_cancel_direct
}

func (op *Operation) packingCancel(sqe *liburing.SubmissionQueueEntry) (err error) {
	switch op.cmd {
	case op_cmd_cancel_regular:
		sqe.PrepareCancelFd(op.fd, 0)
		break
	case op_cmd_cancel_direct:
		sqe.PrepareCancelFdFixed(uint32(op.fd), 0)
		break
	case op_cmd_cancel_op:
		sqe.PrepareCancel(uintptr(op.addr), 0)
		break
	default:
		err = errors.New("undefined cancel fd op cmd")
		return
	}
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareFixedFdInstall(fd int) {
	op.code = liburing.IORING_OP_FIXED_FD_INSTALL
	op.fd = fd
}

func (op *Operation) packingFixedFdInstall(sqe *liburing.SubmissionQueueEntry) (err error) {
	sqe.PrepareFixedFdInstall(op.fd, 0)
	sqe.SetData(unsafe.Pointer(op))
	return err
}
