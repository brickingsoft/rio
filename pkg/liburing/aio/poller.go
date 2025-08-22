//go:build linux

package aio

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

var (
	pollerLocker sync.Mutex
	pollerInit   atomic.Bool
	poller       *Poller
	pollerErr    error
)

func Pin() error {
	if pollerInit.Load() {
		if pollerErr == nil {
			poller.Pin()
			return nil
		}
		return pollerErr
	}
	pollerLocker.Lock()
	if pollerInit.Load() {
		poller.Pin()
		pollerLocker.Unlock()
		return pollerErr
	}
	if !liburing.VersionEnable(6, 13, 0) {
		// support
		// * io_uring_setup_buf_ring 5.19
		// * io_uring_register_ring_fd 5.18
		// * io_uring_prep_msg_ring  6.0
		// * io_uring_prep_recv_multishot  6.0
		// * io_uring_prep_cmd 6.7
		// * io_uring_prep_fixed_fd_install 6.8
		// * io_uring_prep_listen 6.12
		// * io_uring_prep_bind 6.12
		// * io_uring_unregister_files 6.13 (not blocked)
		pollerErr = errors.New("kernel version must >= 6.13")
		pollerLocker.Unlock()
		return pollerErr
	}
	// options
	opt := Options{}
	for _, option := range presetOptions {
		option(&opt)
	}
	// new poller
	poller, pollerErr = newPoller(opt)
	if pollerErr != nil {
		pollerLocker.Unlock()
		return pollerErr
	}
	pollerInit.Store(true)
	pollerLocker.Unlock()
	// pin
	poller.Pin()
	return nil
}

func Unpin() {
	if pollerInit.Load() {
		if count := poller.Unpin(); count == 0 {
			pollerLocker.Lock()
			poller.Shutdown()
			pollerInit.Store(false)
			pollerLocker.Unlock()
		}
	}
}

func newPoller(options Options) (poller *Poller, err error) {

	defaultFlags := liburing.IORING_SETUP_SINGLE_ISSUER | liburing.IORING_SETUP_COOP_TASKRUN |
		liburing.IORING_SETUP_DEFER_TASKRUN | liburing.IORING_SETUP_REGISTERED_FD_ONLY

	if options.Flags == 0 { // set default flags
		options.Flags = defaultFlags
	}

	if options.Flags&liburing.IORING_SETUP_SQPOLL != 0 { // check IORING_SETUP_SQPOLL
		if cpus := uint32(runtime.NumCPU()); cpus > 1 { // IORING_SETUP_SQPOLL must be used in more than 1 cpu
			if options.SQThreadIdle == 0 {
				options.SQThreadIdle = uint32((2 * time.Second).Milliseconds())
			}
			if options.Flags&liburing.IORING_SETUP_SQ_AFF != 0 {
				if options.SQThreadCPU > cpus {
					options.SQThreadCPU = options.SQThreadCPU % cpus
				}
			}
		} else { // reset flags and count
			options.Flags = defaultFlags
		}
	}

	vch := make(chan *Poller, 1)
	ech := make(chan error, 1)

	go func(options Options, vch chan<- *Poller, ech chan<- error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// buffer and ring
		bufferAndRingConfig := options.BufferAndRingConfig
		bufferAndRingConfigErr := bufferAndRingConfig.Validate()
		if bufferAndRingConfigErr != nil {
			ech <- bufferAndRingConfigErr
			return
		}
		bgids := make([]uint16, math.MaxUint16)
		for i := 0; i < len(bgids); i++ {
			bgids[i] = uint16(i)
		}

		// options
		opts := make([]liburing.Option, 0, 1)
		opts = append(opts, liburing.WithEntries(options.Entries))
		opts = append(opts, liburing.WithFlags(options.Flags))
		if options.Flags&liburing.IORING_SETUP_SQPOLL != 0 {
			opts = append(opts, liburing.WithSQThreadIdle(options.SQThreadIdle))
			if options.Flags&liburing.IORING_SETUP_SQ_AFF != 0 {
				opts = append(opts, liburing.WithSQThreadCPU(options.SQThreadCPU))
			}
		}
		// aff cpu
		if options.Flags&liburing.IORING_SETUP_SINGLE_ISSUER != 0 {
			_ = sys.AffCPU(0)
		}
		// new ring
		ring, ringErr := liburing.New(opts...)
		if ringErr != nil {
			ech <- ringErr
			return
		}

		// wakeup
		var (
			wakeup    *Wakeup
			wakeupErr error
		)
		if ring.Flags()&liburing.IORING_SETUP_SINGLE_ISSUER != 0 {
			wakeup, wakeupErr = newWakeup()
			if wakeupErr != nil {
				_ = ring.Close()
				ech <- wakeupErr
				return
			}
		}

		// register personality
		personality, _ := ring.RegisterPersonality()
		// register napi
		var napi *liburing.NAPI
		if options.NAPIBusyPollTimeout > 0 {
			us := uint32(options.NAPIBusyPollTimeout.Microseconds())
			if us == 0 {
				us = 50
			}
			napi = &liburing.NAPI{
				BusyPollTo:     us,
				PreferBusyPoll: 1,
				Resv:           0,
			}
			_, napiErr := ring.RegisterNAPI(napi)
			if napiErr != nil {
				_ = ring.Close()
				if wakeup != nil {
					_ = wakeup.Close()
				}
				ech <- napiErr
				return
			}
		}

		// register files
		if _, regErr := ring.RegisterFilesSparse(uint32(math.MaxUint16)); regErr != nil {
			_ = ring.Close()
			if wakeup != nil {
				_ = wakeup.Close()
			}
			ech <- regErr
			return
		}

		poller = &Poller{
			ring:                ring,
			wakeup:              wakeup,
			wg:                  new(sync.WaitGroup),
			key:                 uint64(uintptr(unsafe.Pointer(ring))),
			personality:         uint16(personality),
			running:             atomic.Bool{},
			idle:                atomic.Bool{},
			waitTimeoutCurve:    options.WaitCQETimeoutCurve,
			submitter:           nil,
			ready:               make(chan *Operation, ring.SQEntries()),
			orphan:              nil,
			bufferAndRingConfig: bufferAndRingConfig,
			bufferAndRingLocker: new(sync.Mutex),
			bufferAndRingIdles:  make([]*BufferAndRing, 0, 8),
			bufferAndRingIds:    bgids,
			sendZCEnabled:       options.SendZCEnabled,
			multishotEnabled:    !options.MultishotDisabled,
			reference:           atomic.Int64{},
		}
		poller.running.Store(true)
		// return poller
		vch <- poller

		poller.wg.Add(1)

		// handle buffer and ring idles
		ctx, cancel := context.WithCancel(context.Background())
		bufferAndRingDone := poller.handleIdleBufferAndRing(ctx)

		// process
		poller.process()

		// shutdown >>>
		// unregister buffer and ring group
		cancel()
		<-bufferAndRingDone
		for _, idle := range poller.bufferAndRingIdles {
			poller.unregisterBufferAndRing(idle)
		}
		// unregister napi
		if napi != nil {
			_, _ = ring.UnregisterNAPI(napi)
		}
		// unregister personality
		_, _ = ring.UnregisterPersonality()
		// unregister files
		_, _ = ring.UnregisterFiles()
		// close ring
		_ = ring.Close()
		// close ready
		for i := 0; i < len(poller.ready); i++ {
			op := <-poller.ready
			op.channel.Complete(0, 0, ErrCanceled)
		}
		close(poller.ready)
		// close wakeup
		if wakeup != nil {
			_ = wakeup.Close()
		}
		// shutdown <<<

		poller.wg.Done()
	}(options, vch, ech)

	select {
	case poller = <-vch:
		break
	case err = <-ech:
		break
	}
	close(vch)
	close(ech)
	return
}

type Poller struct {
	ring                *liburing.Ring
	wakeup              *Wakeup
	wg                  *sync.WaitGroup
	key                 uint64
	personality         uint16
	running             atomic.Bool
	idle                atomic.Bool
	waitTimeoutCurve    Curve
	submitter           func(op *Operation)
	ready               chan *Operation
	orphan              *Operation
	bufferAndRingConfig BufferAndRingConfig
	bufferAndRingLocker sync.Locker
	bufferAndRingIdles  []*BufferAndRing
	bufferAndRingIds    []uint16
	sendZCEnabled       bool
	multishotEnabled    bool
	reference           atomic.Int64
}

func (poller *Poller) Pin() int64 {
	return poller.reference.Add(1)
}

func (poller *Poller) Unpin() int64 {
	return poller.reference.Add(-1)
}

func (poller *Poller) Submit(op *Operation) (future Future) {
	channel := poller.setupChannel(op)
	future = channel
	if poller.running.Load() {
		poller.submitter(op)
	} else {
		channel.Complete(0, 0, ErrCanceled)
	}
	return
}

func (poller *Poller) SubmitAndWait(op *Operation) (n int, flags uint32, err error) {
	n, flags, _, err = poller.Submit(op).Await()
	return
}

func (poller *Poller) Cancel(target *Operation) (err error) {
	op := AcquireOperation()
	op.PrepareCancel(target)
	_, _, err = poller.SubmitAndWait(op)
	ReleaseOperation(op)
	return
}

func (poller *Poller) AcquireBufferAndRing() (br *BufferAndRing, err error) {
	// try get idled one
	poller.bufferAndRingLocker.Lock()
	if len(poller.bufferAndRingIdles) > 0 {
		br = poller.bufferAndRingIdles[0]
		poller.bufferAndRingIdles = poller.bufferAndRingIdles[1:]
		poller.bufferAndRingLocker.Unlock()
		return
	}
	// try get bgid
	if len(poller.bufferAndRingIds) == 0 {
		err = errors.New("register buffer and ring failed cause no bgid available")
		poller.bufferAndRingLocker.Unlock()
		return
	}
	bgid := poller.bufferAndRingIds[0]
	poller.bufferAndRingIds = poller.bufferAndRingIds[1:]
	poller.bufferAndRingLocker.Unlock()

	// register one
	var ptr unsafe.Pointer
	op := AcquireOperation()
	op.PrepareRegisterBufferAndRing(bgid)
	_, _, ptr, err = poller.Submit(op).Await()
	if err == nil {
		br = (*BufferAndRing)(ptr)
	}
	ReleaseOperation(op)
	return
}

func (poller *Poller) ReleaseBufferAndRing(br *BufferAndRing) {
	if br == nil {
		return
	}
	poller.bufferAndRingLocker.Lock()
	poller.bufferAndRingIdles = append(poller.bufferAndRingIdles, br)
	poller.bufferAndRingLocker.Unlock()
}

func (poller *Poller) registerBufferAndRing(bgid uint16) (br *BufferAndRing, err error) {
	entries := uint32(poller.bufferAndRingConfig.Count)
	value, setupErr := poller.ring.SetupBufRing(entries, bgid, 0)
	if setupErr != nil {
		err = setupErr
		return
	}

	mask := uint16(liburing.BufferRingMask(entries))
	buffer := make([]byte, poller.bufferAndRingConfig.Count*poller.bufferAndRingConfig.Size)
	bufferUnitLength := uint32(poller.bufferAndRingConfig.Size)
	for i := uint32(0); i < entries; i++ {
		beg := bufferUnitLength * i
		end := beg + bufferUnitLength
		slice := buffer[beg:end]
		value.BufRingAdd(unsafe.Pointer(&slice[0]), bufferUnitLength, uint16(i), mask, uint16(i))
	}
	value.BufRingAdvance(uint16(entries))

	br = &BufferAndRing{
		bgid:        bgid,
		mask:        mask,
		count:       uint16(entries),
		size:        uint32(poller.bufferAndRingConfig.Size),
		lastUseTime: time.Time{},
		value:       value,
		buffer:      buffer,
	}
	return
}

func (poller *Poller) unregisterBufferAndRing(br *BufferAndRing) {
	if br == nil {
		return
	}
	entries := uint32(poller.bufferAndRingConfig.Count)
	_ = poller.ring.FreeBufRing(br.value, entries, br.bgid)
	bgid := br.bgid
	poller.bufferAndRingLocker.Lock()
	poller.bufferAndRingIds = append(poller.bufferAndRingIds, bgid)
	poller.bufferAndRingLocker.Unlock()

	br.value = nil
	br.buffer = nil
	return
}

func (poller *Poller) handleIdleBufferAndRing(ctx context.Context) (done chan struct{}) {
	done = make(chan struct{})
	go func(ctx context.Context, poller *Poller, done chan struct{}) {
		var scratch []*BufferAndRing
		maxIdleDuration := poller.bufferAndRingConfig.IdleTimeout
		stopped := false
		timer := time.NewTimer(maxIdleDuration)
		for {
			select {
			case <-ctx.Done():
				stopped = true
				break
			case <-timer.C:
				poller.bufferAndRingLocker.Lock()
				n := len(poller.bufferAndRingIdles)
				if n == 0 {
					poller.bufferAndRingLocker.Unlock()
					break
				}
				criticalTime := time.Now().Add(-maxIdleDuration)
				l, r, mid := 0, n-1, 0
				for l <= r {
					mid = (l + r) / 2
					if criticalTime.After(poller.bufferAndRingIdles[mid].lastUseTime) {
						l = mid + 1
					} else {
						r = mid - 1
					}
				}
				i := r
				if i == -1 {
					poller.bufferAndRingLocker.Unlock()
					break
				}

				scratch = append((scratch)[:0], poller.bufferAndRingIdles[:i+1]...)
				m := copy(poller.bufferAndRingIdles, poller.bufferAndRingIdles[i+1:])
				for i = m; i < n; i++ {
					poller.bufferAndRingIdles[i] = nil
				}
				poller.bufferAndRingIdles = poller.bufferAndRingIdles[:m]
				poller.bufferAndRingLocker.Unlock()

				for j := range scratch {
					op := AcquireOperation()
					op.PrepareUnregisterBufferAndRing(scratch[j])
					_, _, _, _ = poller.Submit(op).Await()
					ReleaseOperation(op)
					poller.unregisterBufferAndRing(scratch[j])
					scratch[j] = nil
				}
				timer.Reset(maxIdleDuration)
				break
			}
			if stopped {
				break
			}
		}
		timer.Stop()
		close(done)
	}(ctx, poller, done)
	return
}

func (poller *Poller) Shutdown() {
	if poller.running.CompareAndSwap(true, false) {
		// submit close op
		op := &Operation{}
		op.PrepareCloseRing(poller.key)
		poller.submitter(op)
		// wait
		poller.wg.Wait()
	}
	return
}

func (poller *Poller) process() {
	if poller.ring.Flags()&liburing.IORING_SETUP_SINGLE_ISSUER == 0 {
		poller.submitter = poller.submit2
		poller.process2()
	} else {
		poller.submitter = poller.submit1
		poller.process1()
	}
}

func (poller *Poller) setupChannel(op *Operation) *Channel {
	if op.channel != nil {
		return op.channel
	}
	channel := acquireChannel(op.kind == op_kind_multishot)
	if op.timeout != nil {
		op.timeout.channel = acquireChannel(false)
		channel.timeout = op.timeout.channel
	}
	op.channel = channel
	return channel
}

func (poller *Poller) submit1(op *Operation) {
	poller.ready <- op
	if poller.idle.CompareAndSwap(true, false) {
		if ok := poller.wakeup.Wakeup(poller.ring.Fd()); !ok {
			op.channel.Complete(0, 0, ErrCanceled)
			return
		}
	}
	return
}

func (poller *Poller) process1() {
	curve := poller.waitTimeoutCurve
	if len(curve) == 0 {
		curve = SCurve
	}
	if curve.HasNoTimeout() {
		curve = SCurve
	}
	var (
		stopped      bool
		ready        = poller.ready
		readyN       uint32
		registerN    uint32
		completed    uint32
		waitNr       uint32
		waitTimeout  *syscall.Timespec
		ring         = poller.ring
		transmission = NewCurveTransmission(curve)
		cqes         = make([]*liburing.CompletionQueueEvent, ring.CQEntries())
	)

	// register ring
	_, _ = ring.RegisterRingFd()

	waitNr, waitTimeout = transmission.Match(1)
	for {
		// prepare
		if poller.orphan != nil {
			if !poller.prepareSQE(poller.orphan) {
				goto SUBMIT
			}
			poller.orphan = nil
		}
		if readyN = uint32(len(ready)); readyN > 0 {
			for i := uint32(0); i < readyN; i++ {
				op := <-ready
				if op.kind == op_kind_register {
					registerN++
				}
				if !poller.prepareSQE(op) {
					poller.orphan = op
					break
				}
			}
		}
		readyN -= registerN
		registerN = 0
		// submit and wait
	SUBMIT:
		if readyN == 0 && completed == 0 { // idle
			if poller.idle.CompareAndSwap(false, true) {
				waitNr, waitTimeout = 1, nil
			} else {
				waitNr, waitTimeout = transmission.Match(1)
			}
		} else {
			// adjust wait timeout
			waitNr, waitTimeout = transmission.Match(readyN + completed)
		}
		_, _ = ring.SubmitAndWaitTimeout(waitNr, waitTimeout, nil)
		// reset idle
		poller.idle.CompareAndSwap(true, false)
		// handle complete
		if completed, stopped = poller.completeCQE(&cqes); stopped {
			break
		}
	}
	return
}

func (poller *Poller) submit2(op *Operation) {
	poller.ready <- op
	return
}

func (poller *Poller) process2() {
	wg := new(sync.WaitGroup)
	done := make(chan struct{})
	wg.Add(1)
	go func(poller *Poller, wg *sync.WaitGroup, done chan struct{}) {
		var (
			ring    = poller.ring
			ready   = poller.ready
			readyN  uint32
			orphan  *Operation
			stopped bool
		)
		for {
			// orphan
			if orphan != nil {
				if !poller.prepareSQE(orphan) {
					_, _ = ring.Submit()
					continue
				}
				orphan = nil
				_, _ = ring.Submit()
			}
			// ready
			if readyN = uint32(len(ready)); readyN > 0 {
				for i := uint32(0); i < readyN; i++ {
					op := <-ready
					if !poller.prepareSQE(op) {
						orphan = op
						break
					}
				}
				_, _ = ring.Submit()
				continue
			}
			// wait
			select {
			case op := <-ready:
				if !poller.prepareSQE(op) {
					orphan = op
				}
				_, _ = ring.Submit()
				break
			case <-done:
				stopped = true
				break
			}
			if stopped {
				break
			}
		}
		wg.Done()
	}(poller, wg, done)

	var (
		ring         = poller.ring
		stopped      bool
		completed    uint32
		waitNr       uint32            = 1
		waitTimeout  *syscall.Timespec = nil
		transmission                   = NewCurveTransmission(poller.waitTimeoutCurve)
		cqes                           = make([]*liburing.CompletionQueueEvent, poller.ring.CQEntries())
	)

	for {
		_, _ = ring.WaitCQEs(waitNr, waitTimeout, nil)
		if completed, stopped = poller.completeCQE(&cqes); stopped {
			break
		}
		if completed == 0 {
			waitNr = 1
			waitTimeout = nil
			continue
		}
		if completed < waitNr {
			waitNr, waitTimeout = transmission.Down()
			continue
		}
		waitNr, waitTimeout = transmission.Up()
	}
	close(done)
	wg.Wait()
}

func (poller *Poller) handleRegister(op *Operation) bool {
	if op.kind == op_kind_register {
		switch op.cmd {
		case op_cmd_register_buffer_and_ring:
			bgid := uint16(op.addrLen)
			br, brErr := poller.registerBufferAndRing(bgid)
			op.channel.CompleteWithAttachment(1, 0, unsafe.Pointer(br), brErr)
			break
		case op_cmd_unregister_buffer_and_ring:
			br := (*BufferAndRing)(op.addr)
			poller.unregisterBufferAndRing(br)
			op.channel.Complete(1, 0, nil)
			break
		default:
			op.channel.Complete(0, 0, errors.New("invalid register cmd"))
			break
		}
		return true
	}
	return false
}

func (poller *Poller) prepareSQE(op *Operation) bool {
	if poller.handleRegister(op) {
		return true
	}
	// get sqe
	sqe := poller.ring.GetSQE()
	if sqe == nil {
		return false
	}
	op.personality = poller.personality
	// prepare timeout timeout
	if op.timeout != nil {
		timeoutSQE := poller.ring.GetSQE()
		if timeoutSQE == nil { // no sqe left, prepare nop and set op to head or ready
			sqe.PrepareNop()
			return false
		}
		// packing
		if err := op.packingSQE(sqe); err != nil {
			op.channel.Complete(0, 0, err)
			sqe.PrepareNop()
			return true
		}
		op.timeout.personality = poller.personality
		// packing timeout
		if err := op.timeout.packingSQE(timeoutSQE); err != nil {
			op.channel.Complete(0, 0, err)
			sqe.PrepareNop()
			return true
		}
		return true
	}
	// packing
	if err := op.packingSQE(sqe); err != nil {
		op.channel.Complete(0, 0, err)
		sqe.PrepareNop()
		return true
	}
	return true
}

func (poller *Poller) completeCQE(cqesp *[]*liburing.CompletionQueueEvent) (completed uint32, stopped bool) {
	ring := poller.ring
	cqes := *cqesp
	if peeked := ring.PeekBatchCQE(cqes); peeked > 0 {
		for i := uint32(0); i < peeked; i++ {
			cqe := cqes[i]
			cqes[i] = nil

			if cqe.UserData == 0 { // no op
				ring.CQAdvance(1)
				continue
			}

			if cqe.UserData == poller.key { // userdata is key means closed
				ring.CQAdvance(1)
				poller.running.CompareAndSwap(true, false)
				stopped = true
				continue
			}

			// get op from cqe
			copp := unsafe.Pointer(uintptr(cqe.UserData))
			cop := (*Operation)(copp)
			if cop.channel != nil {
				var (
					opN     = int(cqe.Res)
					opFlags = cqe.Flags
					opErr   error
				)
				if opN < 0 {
					if -opN == int(syscall.ECANCELED) {
						opErr = ErrCanceled
					} else {
						opErr = os.NewSyscallError(cop.Name(), syscall.Errno(-opN))
					}
					opN = 0
				}
				cop.channel.Complete(opN, opFlags, opErr)
			}
			ring.CQAdvance(1)
			cop = nil
			copp = nil
			cqe.UserData = 0
		}
		completed += peeked
	}
	return
}
