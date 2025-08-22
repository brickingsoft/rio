//go:build linux

package aio

import (
	"errors"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) packingSQE(sqe *liburing.SubmissionQueueEntry) (err error) {
	switch op.code {
	case liburing.IORING_OP_NOP:
		err = op.packingNop(sqe)
		break
	case liburing.IORING_OP_MSG_RING:
		err = op.packingMSGRing(sqe)
		break
	case liburing.IORING_OP_URING_CMD:
		err = op.packingURingCMD(sqe)
		break
	case liburing.IORING_OP_ASYNC_CANCEL:
		err = op.packingCancel(sqe)
		break
	case liburing.IORING_OP_CLOSE:
		err = op.packingClose(sqe)
		break
	case liburing.IORING_OP_FIXED_FD_INSTALL:
		err = op.packingFixedFdInstall(sqe)
		break
	case liburing.IORING_OP_SHUTDOWN:
		err = op.packingShutdown(sqe)
		break
	case liburing.IORING_OP_LINK_TIMEOUT:
		err = op.packingLinkTimeout(sqe)
		break
	case liburing.IORING_OP_READ:
		err = op.packingRead(sqe)
		break
	case liburing.IORING_OP_WRITE:
		err = op.packingWrite(sqe)
		break
	case liburing.IORING_OP_SOCKET:
		err = op.packingSocket(sqe)
		break
	case liburing.IORING_OP_CONNECT:
		err = op.packingConnect(sqe)
		break
	case liburing.IORING_OP_LISTEN:
		err = op.packingListen(sqe)
		break
	case liburing.IORING_OP_BIND:
		err = op.packingBind(sqe)
		break
	case liburing.IORING_OP_ACCEPT:
		err = op.packingAccept(sqe)
		break
	case liburing.IORING_OP_RECV:
		err = op.packingReceive(sqe)
		break
	case liburing.IORING_OP_SEND:
		err = op.packingSend(sqe)
		break
	case liburing.IORING_OP_SEND_ZC:
		err = op.packingSendZC(sqe)
		break
	case liburing.IORING_OP_RECVMSG:
		err = op.packingReceiveMsg(sqe)
		break
	case liburing.IORING_OP_SENDMSG:
		err = op.packingSendMsg(sqe)
		break
	case liburing.IORING_OP_SENDMSG_ZC:
		err = op.packingSendMsgZC(sqe)
		break
	case liburing.IORING_OP_SPLICE:
		err = op.packingSplice(sqe)
		break
	case liburing.IORING_OP_PROVIDE_BUFFERS:
		err = op.packingProvideBuffers(sqe)
		break
	case liburing.IORING_OP_REMOVE_BUFFERS:
		err = op.packingRemoveBuffers(sqe)
		break
	case liburing.IORING_OP_POLL_ADD:
		err = op.packingPollAdd(sqe)
		break
	default:
		return NewInvalidOpErr(errors.New("unsupported"))
	}
	if err == nil && op.personality > 0 {
		sqe.SetPersonality(op.personality)
	}
	return
}
