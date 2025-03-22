//go:build linux

package aio

import (
	"context"
	"errors"
	"github.com/brickingsoft/rio/pkg/iouring"
	"sync"
	"syscall"
	"time"
)

func Open(ctx context.Context, options ...Option) (v *Vortex, err error) {
	// check kernel version
	version := iouring.GetVersion()
	if version.Invalidate() {
		err = errors.New("get kernel version failed")
		return
	}
	if !version.GTE(6, 0, 0) {
		err = errors.New("kernel version must greater than or equal to 6.0")
		return
	}
	// options
	opt := Options{
		PrepSQEAffCPU: -1,
		WaitCQEMode:   WaitCQEPushMode,
	}
	for _, option := range options {
		option(&opt)
	}
	// ring
	ring, ringErr := OpenIOURing(ctx, opt)
	if ringErr != nil {
		err = ringErr
		return
	}
	// vortex
	v = &Vortex{
		IOURing: ring,
		operations: sync.Pool{
			New: func() interface{} {
				return &Operation{
					code:     iouring.OpLast,
					borrowed: true,
					resultCh: make(chan Result, 1),
				}
			},
		},
		timers: sync.Pool{
			New: func() interface{} {
				return time.NewTimer(0)
			},
		},
	}
	return
}

type Vortex struct {
	IOURing
	operations sync.Pool
	timers     sync.Pool
}

func (vortex *Vortex) FixedFdInstall(ctx context.Context, directFd int) (regularFd int, err error) {
	op := vortex.acquireOperation()
	op.PrepareFixedFdInstall(directFd)
	regularFd, _, err = vortex.submitAndWait(ctx, op)
	vortex.releaseOperation(op)
	return
}

func (vortex *Vortex) CancelOperation(ctx context.Context, op *Operation) (n int, cqeFlags uint32, err error) {
	if vortex.tryCancelOperation(ctx, op) { // cancel succeed
		r, ok := <-op.resultCh
		if !ok {
			op.Close()
			err = ErrCanceled
			return
		}
		n, cqeFlags, err = r.N, r.Flags, r.Err
		if errors.Is(err, syscall.ECANCELED) {
			err = ErrTimeout
		}
		return
	}
	// cancel failed
	// means target op is not in ring, maybe completed or lost
	timer := vortex.acquireTimer(50 * time.Microsecond)
	defer vortex.releaseTimer(timer)

	select {
	case <-timer.C: // maybe lost
		op.Close()
		err = ErrCanceled
		break
	case r, ok := <-op.resultCh: // completed
		if !ok {
			err = ErrCanceled
			break
		}
		n, cqeFlags, err = r.N, r.Flags, r.Err
		if errors.Is(err, syscall.ECANCELED) {
			err = ErrTimeout
		}
		break
	}
	return
}

func (vortex *Vortex) tryCancelOperation(ctx context.Context, target *Operation) (ok bool) {
	if target.canCancel() {
		op := vortex.acquireOperation()
		op.PrepareCancel(target)
		_, _, err := vortex.submitAndWait(ctx, op)
		ok = err == nil
		vortex.releaseOperation(op)
	}
	return
}

func (vortex *Vortex) acquireOperation() *Operation {
	op := vortex.operations.Get().(*Operation)
	return op
}

func (vortex *Vortex) releaseOperation(op *Operation) {
	if op.canRelease() {
		op.reset()
		vortex.operations.Put(op)
	}
}

func (vortex *Vortex) acquireTimer(timeout time.Duration) *time.Timer {
	timer := vortex.timers.Get().(*time.Timer)
	timer.Reset(timeout)
	return timer
}

func (vortex *Vortex) releaseTimer(timer *time.Timer) {
	timer.Stop()
	vortex.timers.Put(timer)
	return
}

func (vortex *Vortex) submitAndWait(ctx context.Context, op *Operation) (n int, cqeFlags uint32, err error) {
RETRY:
	vortex.Submit(op)
	n, cqeFlags, err = vortex.awaitOperation(ctx, op)
	if err != nil {
		if errors.Is(err, ErrSQBusy) { // means cannot get sqe
			goto RETRY
		}
		return
	}
	return
}

func (vortex *Vortex) awaitOperation(ctx context.Context, op *Operation) (n int, cqeFlags uint32, err error) {
	select {
	case r, ok := <-op.resultCh:
		if !ok {
			op.Close()
			err = ErrCanceled
			break
		}
		n, cqeFlags, err = r.N, r.Flags, r.Err
		if err != nil && errors.Is(err, syscall.ECANCELED) {
			err = ErrCanceled
		}
		if op.linkTimeout != nil { // wait link timeout
			r, ok = <-op.linkTimeout.resultCh
			if ok {
				if err != nil && errors.Is(r.Err, syscall.ETIME) {
					err = ErrTimeout
				}
			}
		}
		break
	case <-ctx.Done():
		err = ctx.Err()
		if errors.Is(err, context.DeadlineExceeded) { // deadline so can cancel
			n, cqeFlags, err = vortex.CancelOperation(ctx, op)
		} else { // ctx canceled so try cancel and close op
			vortex.tryCancelOperation(ctx, op)
			op.Close()
			err = ErrCanceled
		}
		break
	}
	return
}
