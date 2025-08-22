//go:build linux

package liburing

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (ring *Ring) Submit() (uint, error) {
	return ring.submitAndWait(0)
}

func (ring *Ring) submitAndWaitMinTimeout(waitNr uint32, ts *syscall.Timespec, minTimeoutUsec uint32, sigmask *unix.Sigset_t) (*CompletionQueueEvent, error) {
	var submit uint32
	var err error
	var cqe *CompletionQueueEvent

	if ts != nil {
		if ring.features&IORING_FEAT_EXT_ARG != 0 {
			arg := GetEventsArg{
				sigMask:     uint64(uintptr(unsafe.Pointer(sigmask))),
				sigMaskSz:   nSig / szDivider,
				minWaitUsec: minTimeoutUsec,
				ts:          uint64(uintptr(unsafe.Pointer(ts))),
			}
			data := getData{
				submit:   ring.flushSQ(),
				waitNr:   waitNr,
				getFlags: IORING_ENTER_EXT_ARG,
				sz:       int(unsafe.Sizeof(arg)),
				hasTS:    ts != nil,
				arg:      unsafe.Pointer(&arg),
			}

			cqe, err = ring.getCQE(data)
			return cqe, err
		}
		submit, err = ring.submitTimeout(waitNr, ts)
		if err != nil {
			return cqe, err
		}
	} else {
		submit = ring.flushSQ()
	}

	data := getData{
		submit:   submit,
		waitNr:   waitNr,
		getFlags: 0,
		sz:       nSig / szDivider,
		arg:      unsafe.Pointer(sigmask),
	}
	cqe, err = ring.getCQE(data)
	return cqe, err
}

func (ring *Ring) SubmitAndWaitMinTimeout(waitNr uint32, ts *syscall.Timespec, minTimeout time.Duration, sigmask *unix.Sigset_t) (*CompletionQueueEvent, error) {
	minTimeoutUsec := uint32(minTimeout.Microseconds())
	if minTimeoutUsec > 0 && ring.features&IORING_FEAT_MIN_TIMEOUT == 0 {
		minTimeoutUsec = 0
	}
	return ring.submitAndWaitMinTimeout(waitNr, ts, minTimeoutUsec, sigmask)
}

func (ring *Ring) SubmitAndWaitTimeout(waitNr uint32, ts *syscall.Timespec, sigmask *unix.Sigset_t) (*CompletionQueueEvent, error) {
	return ring.submitAndWaitMinTimeout(waitNr, ts, 0, sigmask)
}

func (ring *Ring) SubmitAndWait(waitNr uint32) (uint, error) {
	return ring.submitAndWait(waitNr)
}

func (ring *Ring) SubmitAndGetEvents() (uint, error) {
	return ring.submit(ring.flushSQ(), 0, true)
}

var (
	_updateTimeout         = time.Now()
	_updateTimeoutUserdata = uint64(uintptr(unsafe.Pointer(&_updateTimeout)))
)

func (ring *Ring) submitTimeout(waitNr uint32, ts *syscall.Timespec) (uint32, error) {
	var sqe *SubmissionQueueEntry
	var err error
	sqe = ring.GetSQE()
	if sqe == nil {
		_, err = ring.Submit()
		if err != nil {
			return 0, err
		}
		sqe = ring.GetSQE()
		if sqe == nil {
			return 0, syscall.EAGAIN
		}
	}
	sqe.PrepareTimeout(ts, waitNr, 0)
	sqe.UserData = _updateTimeoutUserdata

	return ring.flushSQ(), nil
}

func (ring *Ring) submit(submitted uint32, waitNr uint32, getEvents bool) (uint, error) {
	cqNeedsEnter := getEvents || waitNr != 0 || ring.cqRingNeedsEnter()

	var flags uint32
	var ret uint
	var err error

	flags = 0
	if ring.sqRingNeedsEnter(submitted, &flags) || cqNeedsEnter {
		if cqNeedsEnter {
			flags |= IORING_ENTER_GETEVENTS
		}
		if ring.kind&regRing != 0 {
			flags |= IORING_ENTER_REGISTERED_RING
		}

		ret, err = ring.Enter(submitted, waitNr, flags, nil)
		if err != nil {
			return 0, err
		}
	} else {
		ret = uint(submitted)
	}

	return ret, nil
}

func (ring *Ring) submitAndWait(waitNr uint32) (uint, error) {
	return ring.submit(ring.flushSQ(), waitNr, false)
}

func (ring *Ring) sqRingWait() (uint, error) {
	flags := IORING_ENTER_SQ_WAIT

	if ring.kind&doubleRegRing != 0 {
		flags |= IORING_ENTER_REGISTERED_RING
	}
	return ring.Enter(0, 0, flags, nil)
}
