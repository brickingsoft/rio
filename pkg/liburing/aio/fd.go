//go:build linux

package aio

import (
	"errors"
	"fmt"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
	"syscall"
	"time"
)

const maxRW = 1 << 30

type Fd struct {
	regular       int
	direct        int
	isStream      bool
	zeroReadIsEOF bool
	readDeadline  time.Time
	writeDeadline time.Time
	multishot     bool
	eventLoop     *EventLoop
}

func (fd *Fd) FileDescriptor() int {
	return fd.direct
}

func (fd *Fd) RegularFileDescriptor() int {
	return fd.regular
}

func (fd *Fd) IsStream() bool {
	return fd.isStream
}

func (fd *Fd) ZeroReadIsEOF() bool {
	return fd.zeroReadIsEOF
}

func (fd *Fd) Name() string {
	return fmt.Sprintf("[fd: %d, %d]", fd.direct, fd.regular)
}

func (fd *Fd) SetReadDeadline(t time.Time) {
	fd.readDeadline = t
}

func (fd *Fd) SetWriteDeadline(t time.Time) {
	fd.writeDeadline = t
}

func (fd *Fd) Installed() bool {
	return fd.regular != -1
}

func (fd *Fd) Install() (err error) {
	if fd.regular != -1 {
		return
	}
	if fd.direct == -1 {
		err = errors.New("fd is not directed")
		return
	}
	var regular int
	op := AcquireOperation()
	op.PrepareFixedFdInstall(fd.direct)
	regular, _, err = fd.eventLoop.SubmitAndWait(op)
	ReleaseOperation(op)
	if err == nil {
		fd.regular = regular
	}
	return
}

func (fd *Fd) SyscallConn() (syscall.RawConn, error) {
	if !fd.Installed() {
		if err := fd.Install(); err != nil {
			return nil, err
		}
	}
	return sys.NewRawConn(fd.regular), nil
}

func (fd *Fd) Dup() (int, string, error) {
	if !fd.Installed() {
		if err := fd.Install(); err != nil {
			return 0, "", err
		}
	}
	return sys.DupCloseOnExec(fd.regular)
}
