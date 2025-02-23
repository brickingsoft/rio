//go:build netbsd

package aio

import (
	"github.com/brickingsoft/errors"
	"syscall"
	"time"
	"unsafe"
)

func (cylinder *KqueueCylinder) prepareRW(fd int, filter int16, flags uint16, op *Operator) (err error) {
	if cylinder.stopped.Load() {
		err = errors.From(ErrUnexpectedCompletion)
		return
	}
	var userdata int64 = 0
	if op != nil {
		userdata = int64(uintptr(unsafe.Pointer(op)))
	}
	entry := syscall.Kevent_t{
		Ident:  uint64(fd),
		Filter: uint32(filter),
		Flags:  uint32(flags),
		Udata:  userdata,
	}
	if ok := cylinder.submit(&entry); !ok {
		time.Sleep(cylinder.eventsWaitTimeout)
		ok = cylinder.submit(&entry)
		if !ok {
			err = errors.From(ErrBusy)
		}
		return
	}
	return
}

func (cylinder *KqueueCylinder) deconstructEvent(event syscall.Kevent_t) (fd int, data int64, eof bool, op *Operator) {
	fd = int(event.Ident)
	data = event.Data
	eof = event.Flags&syscall.EV_EOF != 0
	if event.Udata == 0 {
		return
	}
	op = (*Operator)(unsafe.Pointer(uintptr(event.Udata)))
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
		Flags:  syscall.EV_ADD | syscall.EV_ONESHOT,
	}
}
