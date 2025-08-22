//go:build linux

package aio

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

func (c *Conn) Receive(b []byte) (n int, err error) {
	if c.IsStream() && len(b) > maxRW {
		b = b[:maxRW]
	}
	if poller.multishotEnabled {
		if c.multishotReceiver == nil {
			c.multishotReceiver, err = newMultishotReceiver(c)
			if err != nil {
				err = nil
				n, err = c.receiveOneshot(b)
				return
			}
		}
		n, err = c.multishotReceiver.Recv(b, c.readDeadline)
		if err != nil && errors.Is(err, io.EOF) {
			if !c.zeroReadIsEOF {
				err = nil
			}
		}
	} else {
		n, err = c.receiveOneshot(b)
	}
	return
}

func (c *Conn) receiveOneshot(b []byte) (n int, err error) {
	op := AcquireOperationWithDeadline(c.readDeadline)
	op.PrepareReceive(c, b)
	n, _, err = poller.SubmitAndWait(op)
	ReleaseOperation(op)
	if n == 0 && err == nil && c.zeroReadIsEOF {
		err = io.EOF
	}
	return
}

func (c *Conn) ReceiveFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) == 0 {
		return
	}
	if poller.multishotEnabled {
		if c.multishotMsgReceiver == nil {
			c.multishotMsgReceiver, err = newMultishotMsgReceiver(c)
			if err != nil {
				err = nil
				n, addr, err = c.receiveFromOneshot(b)
				return
			}
		}
		n, _, _, addr, err = c.multishotMsgReceiver.ReceiveMsg(&c.NetFd, b, nil, c.readDeadline)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
	} else {
		n, addr, err = c.receiveFromOneshot(b)
	}
	return
}

func (c *Conn) receiveFromOneshot(b []byte) (n int, addr net.Addr, err error) {
	rsa := &syscall.RawSockaddrAny{}
	rsaLen := syscall.SizeofSockaddrAny

	msg := acquireMsg(b, nil, rsa, rsaLen, 0)

	op := AcquireOperationWithDeadline(c.readDeadline)
	op.PrepareReceiveMsg(c, msg)
	n, _, err = poller.SubmitAndWait(op)
	ReleaseOperation(op)

	releaseMsg(msg)
	if err != nil {
		return
	}
	sa, saErr := sys.RawSockaddrAnyToSockaddr(rsa)
	if saErr != nil {
		err = saErr
		return
	}
	addr = sys.SockaddrToAddr(c.Net(), sa)
	return
}

func (c *Conn) ReceiveMsg(b []byte, oob []byte, flags int) (n int, oobn int, flag int, addr net.Addr, err error) {
	if poller.multishotEnabled && len(oob) == 0 && flags == 0 {
		if c.multishotMsgReceiver == nil {
			c.multishotMsgReceiver, err = newMultishotMsgReceiver(c)
			if err != nil {
				err = nil
				n, oobn, flag, addr, err = c.receiveMsgOneshot(b, oob, flags)
				return
			}
		}

		n, oobn, flag, addr, err = c.multishotMsgReceiver.ReceiveMsg(&c.NetFd, b, oob, c.readDeadline)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
	} else {
		n, oobn, flag, addr, err = c.receiveMsgOneshot(b, oob, flags)
	}
	return
}

func (c *Conn) receiveMsgOneshot(b []byte, oob []byte, flags int) (n int, oobn int, flag int, addr net.Addr, err error) {
	rsa := &syscall.RawSockaddrAny{}
	rsaLen := syscall.SizeofSockaddrAny

	msg := acquireMsg(b, oob, rsa, rsaLen, int32(flags))

	op := AcquireOperationWithDeadline(c.readDeadline)
	op.PrepareReceiveMsg(c, msg)
	n, _, err = poller.SubmitAndWait(op)
	if err == nil {
		oobn = int(msg.Controllen)
		flag = int(msg.Flags)
	}
	ReleaseOperation(op)

	releaseMsg(msg)

	if err != nil {
		return
	}
	sa, saErr := sys.RawSockaddrAnyToSockaddr(rsa)
	if saErr != nil {
		err = saErr
		return
	}
	addr = sys.SockaddrToAddr(c.Net(), sa)
	return
}
