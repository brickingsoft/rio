//go:build darwin || dragonfly || freebsd

package aio

import (
	"errors"
	"golang.org/x/sys/unix"
	"runtime"
	"time"
	"unsafe"
)

func (cylinder *KqueueCylinder) prepare(filter int16, flags uint16, op *Operator) (err error) {
	if cylinder.stopped.Load() {
		err = ErrUnexpectedCompletion
		return
	}
	ident := uint64(0)
	if op != nil {
		ident = uint64(op.fd.Fd())
	}
	entry := unix.Kevent_t{
		Ident:  ident,
		Filter: filter,
		Flags:  flags,
		Fflags: 0,
		Data:   0,
		Udata:  (*byte)(unsafe.Pointer(op)),
	}
	if ok := cylinder.submit(&entry); !ok {
		err = ErrBusy
		return
	}
	return
}

func (cylinder *KqueueCylinder) Loop(beg func(), end func()) {
	beg()
	defer end()

	// todo setup timeout
	timeout := time.Millisecond

	kqfd := cylinder.fd
	changes := make([]unix.Kevent_t, cylinder.sq.capacity)
	events := make([]unix.Kevent_t, cylinder.sq.capacity)
	for {
		if cylinder.stopped.Load() {
			break
		}
		// deadline
		deadline := time.Now().Add(timeout)
		timespec, timespecErr := unix.TimeToTimespec(time.Now().Add(timeout))
		if timespecErr != nil {
			timespec = unix.NsecToTimespec(deadline.UnixNano())
		}
		// changes
		peeked := cylinder.sq.PeekBatch(changes)
		// submit and wait
		n, err := unix.Kevent(kqfd, changes[:peeked], events, &timespec)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			// todo handle err
			break
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			event := events[i]
			if event.Ident == 0 && event.Udata == nil {
				// stop
				cylinder.stopped.Store(true)
				break
			}
			cylinder.completing.Add(1)
			op := (*Operator)(unsafe.Pointer(event.Udata))
			if completion := op.completion; completion != nil {
				if event.Filter&unix.EVFILT_READ != 0 {
					// todo handle recv|recv_from|recv_msg in callback
					completion(0, op, nil)
				} else if event.Filter&unix.EVFILT_WRITE != 0 {
					// todo handle recv|recv_from|recv_msg in callback
					completion(0, op, nil)
				} else if event.Filter&unix.EVFILT_USER != 0 {
					// todo hande wakeup
				} else {
					completion(0, op, errors.New("aio.KqueueCylinder: unsupported filter"))
				}
				runtime.KeepAlive(op)
				op.callback = nil
				op.completion = nil
			}
			cylinder.completing.Add(-1)
		}
	}
	if kqfd > 0 {
		_ = unix.Close(kqfd)
	}
}