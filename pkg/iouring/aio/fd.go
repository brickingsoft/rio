//go:build linux

package aio

import (
	"errors"
	"fmt"
	"github.com/brickingsoft/rio/pkg/iouring/aio/sys"
	"os"
	"sync"
	"syscall"
)

const maxRW = 1 << 30

type Fd struct {
	regular       int
	direct        int
	allocated     bool
	isStream      bool
	zeroReadIsEOF bool
	async         bool
	nonBlocking   bool
	inAdvanceIO   bool
	locker        sync.Mutex
	vortex        *Vortex
}

func (fd *Fd) FileDescriptor() (n int, direct bool) {
	if fd.Registered() {
		n = fd.direct
		direct = true
		return
	}
	return fd.regular, false
}

func (fd *Fd) Name() string {
	return fmt.Sprintf("[fd:%d][direct:%d][allocated:%t][async:%t][nonblocking:%t]", fd.regular, fd.direct, fd.allocated, fd.async, fd.nonBlocking)
}

func (fd *Fd) IsStream() bool {
	return fd.isStream
}

func (fd *Fd) ZeroReadIsEOF() bool {
	return fd.zeroReadIsEOF
}

func (fd *Fd) Async() bool {
	return fd.async
}

func (fd *Fd) SetAsync(async bool) {
	fd.async = async
}

func (fd *Fd) EnableInAdvance() {
	fd.inAdvanceIO = true
}

func (fd *Fd) canInAdvance() bool {
	return fd.inAdvanceIO && fd.regular != -1 && fd.nonBlocking
}

func (fd *Fd) Vortex() *Vortex {
	return fd.vortex
}

func (fd *Fd) RegularFd() int {
	return fd.regular
}

func (fd *Fd) DirectFd() int {
	return fd.direct
}

func (fd *Fd) SetNonblocking(nonblocking bool) error {
	if fd.regular == -1 {
		return errors.New("fd has not installed")
	}
	if err := syscall.SetNonblock(fd.regular, nonblocking); err != nil {
		return os.NewSyscallError("setnonblock", err)
	}
	return nil
}

func (fd *Fd) Nonblocking() bool {
	return fd.nonBlocking
}

func (fd *Fd) SetCloseOnExec() {
	if fd.regular != -1 {
		syscall.CloseOnExec(fd.regular)
	}
}

func (fd *Fd) Dup() (int, string, error) {
	return sys.DupCloseOnExec(fd.regular)
}

func (fd *Fd) Registered() bool {
	return fd.direct != -1
}

func (fd *Fd) Register() error {
	if fd.direct > -1 {
		return nil
	}
	direct, regErr := fd.vortex.RegisterFixedFd(fd.regular)
	if regErr != nil {
		return regErr
	}
	fd.direct = direct
	fd.allocated = false
	return nil
}

func (fd *Fd) Installed() bool {
	return fd.regular != -1
}

func (fd *Fd) Install() (err error) {
	fd.locker.Lock()
	defer fd.locker.Unlock()
	if fd.regular != -1 {
		return nil
	}
	if fd.direct == -1 {
		err = errors.New("fd is not directed")
		return
	}
	regular, installErr := fd.vortex.FixedFdInstall(fd.direct)
	if installErr != nil {
		err = installErr
		return
	}
	fd.regular = regular
	return
}

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}
