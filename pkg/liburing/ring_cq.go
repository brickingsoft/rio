//go:build linux

package liburing

import (
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type GetEventsArg struct {
	sigMask     uint64
	sigMaskSz   uint32
	minWaitUsec uint32
	ts          uint64
}

func (ring *Ring) CQAdvance(numberOfCQEs uint32) {
	atomic.StoreUint32(ring.cqRing.head, *ring.cqRing.head+numberOfCQEs)
}

func (ring *Ring) CQESeen(event *CompletionQueueEvent) {
	if event != nil {
		ring.CQAdvance(1)
	}
}

func (ring *Ring) WaitCQENr(waitNr uint32) (*CompletionQueueEvent, error) {
	data := getData{
		submit:   0,
		waitNr:   waitNr,
		getFlags: 0,
		sz:       nSig / szDivider,
		arg:      nil,
	}
	cqe, err := ring.getCQE(data)
	return cqe, err
}

func (ring *Ring) WaitCQE() (*CompletionQueueEvent, error) {
	cqe, _, err := ring.peekCQE()
	if err == nil && cqe != nil {
		return cqe, nil
	}
	return ring.WaitCQENr(1)
}

func (ring *Ring) waitCQEsNew(waitNr uint32, ts *syscall.Timespec, minTimeout time.Duration, sigmask *unix.Sigset_t) (*CompletionQueueEvent, error) {
	arg := &GetEventsArg{
		sigMask:     uint64(uintptr(unsafe.Pointer(sigmask))),
		sigMaskSz:   nSig / szDivider,
		minWaitUsec: 0,
		ts:          uint64(uintptr(unsafe.Pointer(ts))),
	}
	if minTimeout > 0 && ring.features&IORING_FEAT_MIN_TIMEOUT != 0 {
		arg.minWaitUsec = uint32(minTimeout.Microseconds())
	}

	data := getData{
		waitNr:   waitNr,
		getFlags: IORING_ENTER_EXT_ARG,
		sz:       int(unsafe.Sizeof(GetEventsArg{})),
		hasTS:    true,
		arg:      unsafe.Pointer(arg),
	}
	cqe, err := ring.getCQE(data)
	return cqe, err
}

func (ring *Ring) WaitCQEs(waitNr uint32, ts *syscall.Timespec, sigmask *unix.Sigset_t) (*CompletionQueueEvent, error) {
	return ring.WaitCQEsMinTimeout(waitNr, ts, 0, sigmask)
}

func (ring *Ring) WaitCQEsMinTimeout(waitNr uint32, ts *syscall.Timespec, minTimeout time.Duration, sigmask *unix.Sigset_t) (*CompletionQueueEvent, error) {
	var toSubmit uint32
	if ts != nil {
		if ring.features&IORING_FEAT_EXT_ARG != 0 {
			return ring.waitCQEsNew(waitNr, ts, minTimeout, sigmask)
		}
		var err error
		toSubmit, err = ring.submitTimeout(waitNr, ts)
		if err != nil {
			return nil, err
		}
	}
	data := getData{
		submit:   toSubmit,
		waitNr:   waitNr,
		getFlags: 0,
		sz:       nSig / szDivider,
		arg:      unsafe.Pointer(sigmask),
	}
	cqe, err := ring.getCQE(data)
	return cqe, err
}

func (ring *Ring) WaitCQETimeout(ts *syscall.Timespec) (*CompletionQueueEvent, error) {
	return ring.WaitCQEs(1, ts, nil)
}

func (ring *Ring) ForEachCQE(callback func(cqe *CompletionQueueEvent)) {
	var cqe *CompletionQueueEvent
	for head := atomic.LoadUint32(ring.cqRing.head); ; head++ {
		if head != atomic.LoadUint32(ring.cqRing.tail) {
			cqeIndex := ring.cqeIndex(head, *ring.cqRing.ringMask)
			cqe = (*CompletionQueueEvent)(
				unsafe.Add(unsafe.Pointer(ring.cqRing.cqes), cqeIndex*unsafe.Sizeof(CompletionQueueEvent{})),
			)
			callback(cqe)
		} else {
			break
		}
	}
}

func (ring *Ring) PeekCQE() (*CompletionQueueEvent, error) {
	cqe, _, err := ring.peekCQE()
	if err == nil && cqe != nil {
		return cqe, nil
	}
	return ring.WaitCQENr(0)
}

func (ring *Ring) PeekBatchCQE(cqes []*CompletionQueueEvent) uint32 {
	var ready uint32
	var overflowChecked bool
	var shift int

	if ring.flags&IORING_SETUP_CQE32 != 0 {
		shift = 1
	}
	count := uint32(len(cqes))

AGAIN:
	ready = ring.CQReady()
	if ready != 0 {
		if count > ready {
			count = ready
		}
		head := *ring.cqRing.head
		mask := *ring.cqRing.ringMask
		last := head + count
		for i := 0; head != last; head, i = head+1, i+1 {
			cqes[i] = (*CompletionQueueEvent)(
				unsafe.Add(
					unsafe.Pointer(ring.cqRing.cqes),
					uintptr((head&mask)<<shift)*unsafe.Sizeof(CompletionQueueEvent{}),
				),
			)
		}
		return count
	}

	if overflowChecked {
		return 0
	}

	if ring.cqRingNeedsFlush() {
		_, _ = ring.GetEvents()
		overflowChecked = true
		goto AGAIN
	}
	return 0
}

func (ring *Ring) GetEvents() (uint, error) {
	flags := IORING_ENTER_GETEVENTS
	if ring.kind&regRing != 0 {
		flags |= IORING_ENTER_REGISTERED_RING
	}
	return ring.Enter(0, 0, flags, nil)
}

func (ring *Ring) CQEntries() uint32 {
	return *ring.cqRing.ringEntries
}

func (ring *Ring) CQReady() uint32 {
	return atomic.LoadUint32(ring.cqRing.tail) - *ring.cqRing.head
}

func (ring *Ring) CQHasOverflow() bool {
	return atomic.LoadUint32(ring.sqRing.flags)&IORING_SQ_CQ_OVERFLOW != 0
}

func (ring *Ring) CQEventFdEnabled() bool {
	if *ring.cqRing.flags == 0 {
		return true
	}
	return !(*ring.cqRing.flags&IORING_CQ_EVENTFD_DISABLED != 0)
}

func (ring *Ring) CQEventFdToggle(enabled bool) error {
	var flags uint32
	if enabled == ring.CQEventFdEnabled() {
		return nil
	}
	if *ring.cqRing.flags == 0 {
		return syscall.EOPNOTSUPP
	}
	flags = *ring.cqRing.flags
	if enabled {
		flags &= ^IORING_CQ_EVENTFD_DISABLED
	} else {
		flags |= IORING_CQ_EVENTFD_DISABLED
	}
	atomic.StoreUint32(ring.cqRing.flags, flags)
	return nil
}

func (ring *Ring) cqeShift() uint32 {
	if ring.flags&IORING_SETUP_CQE32 != 0 {
		return 1
	}
	return 0
}

func (ring *Ring) cqeIndex(ptr, mask uint32) uintptr {
	return uintptr((ptr & mask) << ring.cqeShift())
}

func (ring *Ring) peekCQE() (*CompletionQueueEvent, uint32, error) {
	var cqe *CompletionQueueEvent
	var err error
	var available uint32
	var shift uint32
	mask := *ring.cqRing.ringMask

	if ring.flags&IORING_SETUP_CQE32 != 0 {
		shift = 1
	}

	for {
		tail := atomic.LoadUint32(ring.cqRing.tail)
		head := *ring.cqRing.head
		cqe = nil
		available = tail - head
		if available == 0 {
			break
		}
		cqe = (*CompletionQueueEvent)(
			unsafe.Add(unsafe.Pointer(ring.cqRing.cqes), uintptr((head&mask)<<shift)*unsafe.Sizeof(CompletionQueueEvent{})),
		)
		if ring.features&IORING_FEAT_EXT_ARG == 0 && cqe.UserData == _updateTimeoutUserdata {
			if cqe.Res < 0 {
				err = syscall.Errno(uintptr(-cqe.Res))
			}
			ring.CQAdvance(1)
			if err == nil {
				continue
			}
			cqe = nil
		}

		break
	}
	return cqe, available, err
}

func (ring *Ring) cqRingNeedsFlush() bool {
	return atomic.LoadUint32(ring.sqRing.flags)&(IORING_SQ_CQ_OVERFLOW|IORING_SQ_TASKRUN) != 0
}

func (ring *Ring) cqRingNeedsEnter() bool {
	return (ring.flags&IORING_SETUP_IOPOLL) != 0 || ring.cqRingNeedsFlush()
}

type getData struct {
	submit   uint32
	waitNr   uint32
	getFlags uint32
	sz       int
	hasTS    bool
	arg      unsafe.Pointer
}

func (ring *Ring) getCQE(data getData) (*CompletionQueueEvent, error) {
	var cqe *CompletionQueueEvent
	var looped bool
	var err error

	for {
		var needEnter bool
		var flags uint32
		var nrAvailable uint32
		var ret uint
		var localErr error

		cqe, nrAvailable, localErr = ring.peekCQE()
		if localErr != nil {
			err = localErr
			break
		}
		if cqe == nil && data.waitNr == 0 && data.submit == 0 {
			if looped || !ring.cqRingNeedsEnter() {
				err = unix.EAGAIN
				break
			}
			needEnter = true
		}
		if data.waitNr > nrAvailable || needEnter {
			flags = IORING_ENTER_GETEVENTS | data.getFlags
			needEnter = true
		}
		if ring.sqRingNeedsEnter(data.submit, &flags) {
			needEnter = true
		}
		if !needEnter {
			break
		}
		if looped && data.hasTS {
			arg := (*GetEventsArg)(data.arg)
			if cqe == nil && arg.ts != 0 {
				err = unix.ETIME
			}
			break
		}
		if ring.kind&regRing != 0 {
			flags |= IORING_ENTER_REGISTERED_RING
		}
		ret, localErr = ring.Enter2(data.submit, data.waitNr, flags, data.arg, data.sz)
		if localErr != nil {
			err = localErr
			break
		}
		data.submit -= uint32(ret)
		if cqe != nil {
			break
		}
		if !looped {
			looped = true
			err = localErr
		}
	}
	return cqe, err
}
