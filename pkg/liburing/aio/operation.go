//go:build linux

package aio

import (
	"sync"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

var (
	operations = sync.Pool{}
)

func AcquireOperation() *Operation {
	v := operations.Get()
	if v == nil {
		v = &Operation{
			code: liburing.IORING_OP_LAST,
			kind: op_kind_oneshot,
		}
	}
	return v.(*Operation)
}

func AcquireOperationWithDeadline(deadline time.Time) *Operation {
	if deadline.IsZero() {
		return AcquireOperation()
	}
	timeout := AcquireOperation()
	timeout.PrepareLinkTimeout(deadline)
	op := AcquireOperation()
	op.timeout = timeout
	return op
}

func ReleaseOperation(op *Operation) {
	if timeout := op.timeout; timeout != nil {
		op.timeout = nil
		op.channel.timeout = nil
		if channel := timeout.channel; channel != nil {
			timeout.channel = nil
			releaseChannel(channel)
		}
		timeout.reset()
		operations.Put(timeout)
	}

	if channel := op.channel; channel != nil {
		op.channel = nil
		releaseChannel(channel)
	}

	op.reset()
	operations.Put(op)
}

const (
	op_kind_oneshot uint32 = iota
	op_kind_multishot
	op_kind_register
)

const (
	op_cmd_close_ring int = iota + 1
	op_cmd_close_regular
	op_cmd_close_direct
	op_cmd_cancel_op
	op_cmd_cancel_regular
	op_cmd_cancel_direct
	op_cmd_msg_ring
	op_cmd_msg_ring_fd
	op_cmd_register_buffer_and_ring
	op_cmd_unregister_buffer_and_ring
	op_cmd_send_bundle
)

type Operation struct {
	code        uint8          // 1
	_pad        [1]uint8       // 1
	personality uint16         // 2
	kind        uint32         // 4
	cmd         int            // 8
	timeout     *Operation     // 8
	channel     *Channel       // 8
	fd          int            // 8
	addr        unsafe.Pointer // 8
	addr2       unsafe.Pointer // 8
	addrLen     uint32         // 4
	addr2Len    uint32         // 4
}

func (op *Operation) reset() {
	op.code = liburing.IORING_OP_LAST
	op.cmd = 0
	op.personality = 0
	op.kind = 0
	op.timeout = nil
	op.channel = nil
	op.fd = -1
	op.addr = nil
	op.addrLen = 0
	op.addr2 = nil
	op.addr2Len = 0
	return
}
