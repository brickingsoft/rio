//go:build darwin || dragonfly || freebsd || openbsd

package aio

import (
	"syscall"
	"time"
	"unsafe"
)

func (cylinder *KqueueCylinder) prepareRW(fd int, filter int16, flags uint16, op *Operator) (err error) {
	if cylinder.stopped.Load() {
		err = ErrUnexpectedCompletion
		return
	}
	entry := syscall.Kevent_t{
		Ident:  uint64(fd),
		Filter: filter,
		Flags:  flags,
		Udata:  (*byte)(unsafe.Pointer(op)),
	}
	if ok := cylinder.submit(&entry); !ok {
		time.Sleep(cylinder.eventsWaitTimeout)
		ok = cylinder.submit(&entry)
		if !ok {
			err = ErrBusy
		}
		return
	}
	return
}

func (cylinder *KqueueCylinder) deconstructEvent(event syscall.Kevent_t) (fd int, op *Operator) {
	fd = int(event.Ident)
	if event.Udata == nil {
		return
	}
	op = (*Operator)(unsafe.Pointer(event.Udata))
	return
}

func (cylinder *KqueueCylinder) createPipeEvent(b []byte) syscall.Kevent_t {
	for {
		n, _ := syscall.Write(cylinder.pipe[1], b)
		if n == 0 {
			continue
		}
		break
	}
	return syscall.Kevent_t{
		Ident:  uint64(cylinder.pipe[0]),
		Filter: syscall.EVFILT_READ,
		Flags:  syscall.EV_ADD | syscall.EV_ONESHOT | syscall.EV_CLEAR,
	}
}
