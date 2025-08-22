//go:build linux

package aio

import (
	"errors"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

type Promise interface {
	Complete(n int, flags uint32, err error)
}

type PromiseAdaptor interface {
	Handle(n int, flags uint32, err error) (bool, int, uint32, unsafe.Pointer, error)
}

type CompletionEvent struct {
	N          int
	Flags      uint32
	Err        error
	Attachment unsafe.Pointer
}

type Future interface {
	Await() (n int, flags uint32, attachment unsafe.Pointer, err error)
	AwaitDeadline(deadline time.Time) (n int, flags uint32, attachment unsafe.Pointer, err error)
	AwaitBatch(hungry bool, deadline time.Time) (events []CompletionEvent)
	AwaitZeroCopy() (n int, flags uint32, attachment unsafe.Pointer, err error)
}

var (
	channels = [2]sync.Pool{}
	timers   sync.Pool
)

func acquireTimer(timeout time.Duration) *time.Timer {
	v := timers.Get()
	if v == nil {
		timer := time.NewTimer(timeout)
		return timer
	}
	timer := v.(*time.Timer)
	timer.Reset(timeout)
	return timer
}

func releaseTimer(timer *time.Timer) {
	timer.Stop()
	timers.Put(timer)
}

const (
	oneshotChannelSize   = 2
	multishotChannelSize = 1024
)

func acquireChannel(multishot bool) *Channel {
	if multishot {
		v := channels[1].Get()
		if v == nil {
			v = &Channel{
				ch:      make(chan CompletionEvent, multishotChannelSize),
				adaptor: nil,
				timeout: nil,
			}
		}
		return v.(*Channel)
	}
	v := channels[0].Get()
	if v == nil {
		v = &Channel{
			ch:      make(chan CompletionEvent, oneshotChannelSize),
			adaptor: nil,
			timeout: nil,
		}
	}
	return v.(*Channel)
}

func releaseChannel(c *Channel) {
	c.adaptor = nil
	c.timeout = nil
	switch cap(c.ch) {
	case oneshotChannelSize:
		channels[0].Put(c)
		break
	case multishotChannelSize:
		channels[1].Put(c)
		break
	default:
		break
	}
}

type Channel struct {
	ch      chan CompletionEvent
	adaptor PromiseAdaptor
	timeout *Channel
}

func (c *Channel) Complete(n int, flags uint32, err error) {
	if c.adaptor == nil {
		c.ch <- CompletionEvent{n, flags, err, nil}
		return
	}
	var (
		pass       bool
		attachment unsafe.Pointer
	)
	if pass, n, flags, attachment, err = c.adaptor.Handle(n, flags, err); pass {
		c.ch <- CompletionEvent{n, flags, err, attachment}
	}
	return
}

func (c *Channel) CompleteWithAttachment(n int, flags uint32, attachment unsafe.Pointer, err error) {
	c.ch <- CompletionEvent{n, flags, err, attachment}
}

func (c *Channel) Await() (n int, flags uint32, attachment unsafe.Pointer, err error) {
	r, ok := <-c.ch
	if !ok {
		err = ErrCanceled
		return
	}
	n, flags, attachment, err = r.N, r.Flags, r.Attachment, r.Err
	if c.timeout != nil {
		if _, _, _, timeoutErr := c.timeout.Await(); errors.Is(timeoutErr, syscall.ETIME) {
			err = ErrTimeout
		}
	}
	return
}

func (c *Channel) AwaitDeadline(deadline time.Time) (n int, flags uint32, attachment unsafe.Pointer, err error) {
	if c.timeout != nil {
		panic(errors.New("channel cannot await deadline when timeout is set"))
	}
	if deadline.IsZero() {
		return c.Await()
	}
	timeout := time.Until(deadline)
	if timeout < 1 {
		err = ErrTimeout
		return
	}
	timer := acquireTimer(timeout)
	select {
	case r := <-c.ch:
		n, flags, attachment, err = r.N, r.Flags, r.Attachment, r.Err
		break
	case <-timer.C:
		err = ErrTimeout
		break
	}
	releaseTimer(timer)
	return
}

func (c *Channel) AwaitZeroCopy() (n int, flags uint32, attachment unsafe.Pointer, err error) {
	r, ok := <-c.ch
	if !ok {
		err = ErrCanceled
		return
	}
	n, flags, attachment, err = r.N, r.Flags, r.Attachment, r.Err
	if err != nil {
		return
	}
	if flags&liburing.IORING_CQE_F_MORE != 0 {
		r, ok = <-c.ch
		if !ok {
			err = ErrCanceled
			return
		}
		if r.Flags&liburing.IORING_CQE_F_NOTIF != 0 {
			return
		}
		err = errors.New("await zero-copy of data failed cause no IORING_CQE_F_NOTIF")
		return
	}
	return
}

func (c *Channel) AwaitBatch(hungry bool, deadline time.Time) (events []CompletionEvent) {
	ready := len(c.ch)
	if ready == 0 {
		if !hungry {
			return
		}
		n, flags, attachment, err := c.AwaitDeadline(deadline)
		event := CompletionEvent{
			N:          n,
			Flags:      flags,
			Err:        err,
			Attachment: attachment,
		}
		events = append(events, event)
		if err != nil {
			return
		}
		ready = len(c.ch)
		if ready == 0 {
			return
		}
	}
	for i := 0; i < ready; i++ {
		n, flags, attachment, err := c.Await()
		event := CompletionEvent{
			N:          n,
			Flags:      flags,
			Err:        err,
			Attachment: attachment,
		}
		events = append(events, event)
		if err != nil {
			return
		}
	}
	return
}
