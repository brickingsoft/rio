//go:build linux

package aio

import (
	"net"

	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

func (c *Conn) Send(b []byte) (n int, err error) {
	if c.IsStream() && len(b) > maxRW {
		b = b[:maxRW]
	}
	var (
		op     = AcquireOperationWithDeadline(c.writeDeadline)
		future Future
	)
	if poller.sendZCEnabled {
		op.PrepareSendZC(c, b)
		future = poller.Submit(op)
		n, _, _, err = future.AwaitZeroCopy()
	} else {
		op.PrepareSend(c, b)
		n, _, err = poller.SubmitAndWait(op)
	}
	ReleaseOperation(op)
	if err != nil {
		return
	}
	return
}

func (c *Conn) SendTo(b []byte, addr net.Addr) (n int, err error) {
	sa, saErr := sys.AddrToSockaddr(addr)
	if saErr != nil {
		err = saErr
		return
	}
	rsa, rsaLen, rsaErr := sys.SockaddrToRawSockaddrAny(sa)
	if rsaErr != nil {
		err = rsaErr
		return
	}
	var (
		op     = AcquireOperationWithDeadline(c.writeDeadline)
		msg    = acquireMsg(b, nil, rsa, int(rsaLen), 0)
		future Future
	)
	if poller.sendZCEnabled {
		op.PrepareSendMsgZC(c, msg)
		future = poller.Submit(op)
		n, _, _, err = future.AwaitZeroCopy()
	} else {
		op.PrepareSendMsg(c, msg)
		n, _, err = poller.SubmitAndWait(op)
	}
	ReleaseOperation(op)
	releaseMsg(msg)
	return
}

func (c *Conn) SendMsg(b []byte, oob []byte, addr net.Addr) (n int, oobn int, err error) {
	sa, saErr := sys.AddrToSockaddr(addr)
	if saErr != nil {
		err = saErr
		return
	}
	rsa, rsaLen, rsaErr := sys.SockaddrToRawSockaddrAny(sa)
	if rsaErr != nil {
		err = rsaErr
		return
	}
	var (
		op     = AcquireOperationWithDeadline(c.writeDeadline)
		msg    = acquireMsg(b, oob, rsa, int(rsaLen), 0)
		future Future
	)

	if poller.sendZCEnabled {
		op.PrepareSendMsgZC(c, msg)
		future = poller.Submit(op)
		n, _, _, err = future.AwaitZeroCopy()
	} else {
		op.PrepareSendMsg(c, msg)
		n, _, err = poller.SubmitAndWait(op)
	}

	if err == nil {
		oobn = int(msg.Controllen)
	}
	ReleaseOperation(op)
	releaseMsg(msg)
	return
}
