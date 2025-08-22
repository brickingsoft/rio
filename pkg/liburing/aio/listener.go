//go:build linux

package aio

import (
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

func newMultishotAcceptor(ln *Listener) (acceptor *MultishotAcceptor) {
	acceptor = &MultishotAcceptor{
		serving:         true,
		acceptAddr:      &syscall.RawSockaddrAny{},
		acceptAddrLen:   syscall.SizeofSockaddrAny,
		operation:       &Operation{},
		future:          nil,
		err:             nil,
		locker:          new(sync.Mutex),
		operationLocker: new(sync.Mutex),
	}
	acceptor.operation.PrepareAcceptMultishot(ln, acceptor.acceptAddr, &acceptor.acceptAddrLen)
	acceptor.future = poller.Submit(acceptor.operation)
	return
}

type MultishotAcceptor struct {
	serving         bool
	acceptAddr      *syscall.RawSockaddrAny
	acceptAddrLen   int
	operation       *Operation
	future          Future
	err             error
	locker          *sync.Mutex
	operationLocker *sync.Mutex
}

func (acceptor *MultishotAcceptor) Handle(n int, flags uint32, err error) (bool, int, uint32, unsafe.Pointer, error) {
	return true, n, flags, nil, err
}

func (acceptor *MultishotAcceptor) Accept(deadline time.Time) (fd int, err error) {
	acceptor.locker.Lock()
	if acceptor.err != nil {
		err = acceptor.err

		acceptor.locker.Unlock()
		return
	}

	var (
		flags uint32
	)
	fd, flags, _, err = acceptor.future.AwaitDeadline(deadline)
	if err != nil {
		acceptor.serving = false
		acceptor.err = err
		if IsTimeout(err) {
			if acceptor.cancel() {
				for {
					_, _, _, waitErr := acceptor.future.Await()
					if IsCanceled(waitErr) {
						break
					}
				}
			}
		}
		acceptor.locker.Unlock()
		return
	}

	if flags&liburing.IORING_CQE_F_MORE == 0 {
		acceptor.locker.Lock()
		acceptor.serving = false
		acceptor.err = ErrCanceled
		err = acceptor.err

		acceptor.locker.Unlock()
		return
	}

	acceptor.locker.Unlock()
	return
}

func (acceptor *MultishotAcceptor) cancel() bool {
	acceptor.operationLocker.Lock()
	defer acceptor.operationLocker.Unlock()
	if op := acceptor.operation; op != nil {
		return poller.Cancel(acceptor.operation) == nil
	}
	return false
}

func (acceptor *MultishotAcceptor) Close() (err error) {
	if acceptor.locker.TryLock() {
		if acceptor.serving {
			acceptor.serving = false
			if acceptor.cancel() {
				for {
					_, _, _, waitErr := acceptor.future.Await()
					if IsCanceled(waitErr) {
						break
					}
				}
			}
		}
		acceptor.err = ErrCanceled
		acceptor.locker.Unlock()
		return
	}
	acceptor.cancel()
	return
}

type Listener struct {
	NetFd
	multishotAcceptOnce sync.Once
	multishotAcceptor   *MultishotAcceptor
}

func (fd *Listener) Accept() (*Conn, error) {
	if poller.multishotEnabled {
		fd.multishotAcceptOnce.Do(func() {
			fd.multishotAcceptor = newMultishotAcceptor(fd)
		})
		var (
			accepted int
			err      error
		)
		accepted, err = fd.multishotAcceptor.Accept(fd.readDeadline)
		if err != nil {
			return nil, err
		}
		// new conn
		conn := fd.newAcceptedConnFd(accepted)
		return conn, nil
	}

	return fd.acceptOneshot()
}

func (fd *Listener) acceptOneshot() (conn *Conn, err error) {
	acceptAddr := &syscall.RawSockaddrAny{}
	acceptAddrLen := syscall.SizeofSockaddrAny
	acceptAddrLenPtr := &acceptAddrLen

	op := AcquireOperationWithDeadline(fd.readDeadline)
	op.PrepareAccept(fd, acceptAddr, acceptAddrLenPtr)
	accepted, _, acceptErr := poller.SubmitAndWait(op)
	ReleaseOperation(op)

	if acceptErr != nil {
		err = acceptErr
		return
	}

	// new conn
	conn = fd.newAcceptedConnFd(accepted)
	sa, saErr := sys.RawSockaddrAnyToSockaddr(acceptAddr)
	if saErr == nil {
		addr := sys.SockaddrToAddr(conn.net, sa)
		conn.SetRemoteAddr(addr)
	}
	return
}

func (fd *Listener) Close() error {
	if fd.multishotAcceptor != nil {
		if err := fd.multishotAcceptor.Close(); err != nil {
			err = nil
		}
	}
	return fd.NetFd.Close()
}

func (fd *Listener) newAcceptedConnFd(accepted int) (conn *Conn) {
	conn = &Conn{
		NetFd: NetFd{
			Fd: Fd{
				locker:        sync.Mutex{},
				regular:       -1,
				direct:        accepted,
				isStream:      fd.isStream,
				zeroReadIsEOF: fd.zeroReadIsEOF,
				readDeadline:  time.Time{},
				writeDeadline: time.Time{},
			},
			kind:   AcceptedNetFd,
			family: fd.family,
			sotype: fd.sotype,
			net:    fd.net,
			laddr:  nil,
			raddr:  nil,
		},
	}
	poller.Pin()
	return
}
