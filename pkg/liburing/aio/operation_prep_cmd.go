//go:build linux

package aio

import (
	"errors"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) packingURingCMD(sqe *liburing.SubmissionQueueEntry) (err error) {
	switch op.cmd {
	case liburing.SOCKET_URING_OP_SETSOCKOPT:
		err = op.packingSetSocketopt(sqe)
		break
	case liburing.SOCKET_URING_OP_GETSOCKOPT:
		err = op.packingGetSocketopt(sqe)
		break
	default:
		err = NewInvalidOpErr(errors.New("unsupported iouring command"))
		return
	}
	return
}
