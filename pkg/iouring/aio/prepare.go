package aio

import (
	"github.com/brickingsoft/rio/pkg/iouring"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func (vortex *Vortex) PrepareOperation(op *Operation) Future {
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareConnect(fd int, addr *syscall.RawSockaddrAny, addrLen int, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareConnect(fd, addr, addrLen)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareAccept(fd int, addr *syscall.RawSockaddrAny, addrLen int, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareAccept(fd, addr, addrLen)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareReceive(fd int, b []byte, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareReceive(fd, b)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareSend(fd int, b []byte, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareSend(fd, b)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareSendZC(fd int, b []byte, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareSendZC(fd, b)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareReceiveMsg(fd int, b []byte, oob []byte, addr *syscall.RawSockaddrAny, addrLen int, flags int32, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareReceiveMsg(fd, b, oob, addr, addrLen, flags)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareSendMsg(fd int, b []byte, oob []byte, addr *syscall.RawSockaddrAny, addrLen int, flags int32, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareSendMsg(fd, b, oob, addr, addrLen, flags)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareSendMsgZC(fd int, b []byte, oob []byte, addr *syscall.RawSockaddrAny, addrLen int, flags int32, deadline time.Time) Future {
	op := vortex.acquireOperation()
	op.WithDeadline(deadline).PrepareSendMsgZC(fd, b, oob, addr, addrLen, flags)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareSplice(fdIn int, offIn int64, fdOut int, offOut int64, nbytes uint32, flags uint32) Future {
	op := vortex.acquireOperation()
	op.PrepareSplice(fdIn, offIn, fdOut, offOut, nbytes, flags)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) PrepareTee(fdIn int, fdOut int, nbytes uint32, flags uint32) Future {
	op := vortex.acquireOperation()
	op.PrepareTee(fdIn, fdOut, nbytes, flags)
	return vortex.prepareOperation(op)
}

func (vortex *Vortex) prepareOperation(op *Operation) Future {
	vortex.ops.Enqueue(op)
	return Future{
		vortex: vortex,
		op:     op,
	}
}

func (vortex *Vortex) prepareSQE(op *Operation) error {
	sqe := vortex.ring.GetSQE()
	if sqe == nil {
		return os.NewSyscallError("ring_getsqe", syscall.EBUSY)
	}
	switch op.kind {
	case iouring.OpNop:
		sqe.PrepareNop()
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpConnect:
		addrPtr := (*syscall.RawSockaddrAny)(unsafe.Pointer(op.msg.Name))
		addrLenPtr := uint64(op.msg.Namelen)
		sqe.PrepareConnect(op.fd, addrPtr, addrLenPtr)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpAccept:
		addrPtr := (*syscall.RawSockaddrAny)(unsafe.Pointer(op.msg.Name))
		addrLenPtr := uint64(uintptr(unsafe.Pointer(&op.msg.Namelen)))
		sqe.PrepareAccept(op.fd, addrPtr, addrLenPtr, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpRecv:
		b := uintptr(unsafe.Pointer(&op.b[0]))
		bLen := uint32(len(op.b))
		sqe.PrepareRecv(op.fd, b, bLen, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpSend:
		b := uintptr(unsafe.Pointer(&op.b[0]))
		bLen := uint32(len(op.b))
		sqe.PrepareSend(op.fd, b, bLen, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpSendZC:
		sqe.PrepareSendZC(op.fd, op.b, 0, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpRecvmsg:
		sqe.PrepareRecvMsg(op.fd, &op.msg, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpSendmsg:
		sqe.PrepareSendMsg(op.fd, &op.msg, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpSendMsgZC:
		sqe.PrepareSendmsgZC(op.fd, &op.msg, 0)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpSplice:
		sqe.PrepareSplice(op.pipe.fdIn, op.pipe.offIn, op.pipe.fdOut, op.pipe.offOut, op.pipe.nbytes, op.pipe.spliceFlags)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpTee:
		sqe.PrepareTee(op.pipe.fdIn, op.pipe.fdOut, op.pipe.nbytes, op.pipe.spliceFlags)
		sqe.SetData(unsafe.Pointer(op))
		break
	case iouring.OpAsyncCancel:
		sqe.PrepareCancel(uintptr(op.ptr), 0)
		break
	default:
		sqe.PrepareNop()
		return UnsupportedOp
	}
	runtime.KeepAlive(sqe)
	return nil
}
