//go:build dragonfly || freebsd || netbsd || openbsd

package aio

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

func Accept(fd NetFd, cb OperationCallback) {
	op := readOperator(fd)
	op.userdata.Fd = fd
	op.callback = cb
	op.completion = func(result int, cop *Operator, err error) {
		completeAccept(result, cop, err)
		runtime.KeepAlive(op)
	}

	if timeout := op.timeout; timeout > 0 {
		timer := getOperatorTimer()
		op.timer = timer
		timer.Start(timeout, &operatorCanceler{
			op: op,
		})
	}

	cylinder := nextKqueueCylinder()
	if err := cylinder.prepareRead(fd.Fd(), op); err != nil {
		cb(-1, Userdata{}, err)
		// reset
		op.callback = nil
		op.completion = nil
		if timer := op.timer; timer != nil {
			timer.Done()
			putOperatorTimer(timer)
		}
	}
}

func completeAccept(result int, op *Operator, err error) {
	cb := op.callback
	userdata := op.userdata
	if err != nil || result == 0 {
		cb(-1, Userdata{}, err)
		return
	}
	ln := userdata.Fd.(NetFd)
	timer := op.timer
	sock := 0
	var sa syscall.Sockaddr
	for {
		if timer != nil && timer.DeadlineExceeded() {
			cb(-1, Userdata{}, ErrOperationDeadlineExceeded)
			return
		}
		sock, sa, err = syscall.Accept4(ln.Fd(), syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNABORTED) {
				continue
			}
			cb(-1, Userdata{}, os.NewSyscallError("accept4", err))
			return
		}
		break
	}

	// get local addr
	lsa, lsaErr := syscall.Getsockname(sock)
	if lsaErr != nil {
		_ = syscall.Close(sock)
		cb(-1, Userdata{}, os.NewSyscallError("getsockname", lsaErr))
		return
	}
	la := SockaddrToAddr(ln.Network(), lsa)
	// get remote addr
	ra := SockaddrToAddr(ln.Network(), sa)

	// conn
	conn := &netFd{
		handle:     sock,
		network:    ln.Network(),
		family:     ln.Family(),
		socketType: ln.SocketType(),
		protocol:   ln.Protocol(),
		ipv6only:   ln.IPv6Only(),
		localAddr:  la,
		remoteAddr: ra,
		rop:        Operator{},
		wop:        Operator{},
	}
	conn.rop.fd = conn
	conn.wop.fd = conn

	cb(sock, Userdata{Fd: conn}, nil)
	runtime.KeepAlive(ln)
	return
}
