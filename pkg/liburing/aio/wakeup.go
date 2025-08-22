//go:build linux

package aio

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func newWakeup() (v *Wakeup, err error) {
	vch := make(chan *Wakeup, 1)
	ech := make(chan error, 1)
	go func(vch chan *Wakeup, ech chan error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ring, ringErr := liburing.New(
			liburing.WithEntries(4),
			liburing.WithFlags(liburing.IORING_SETUP_COOP_TASKRUN|liburing.IORING_SETUP_SINGLE_ISSUER),
		)
		if ringErr != nil {
			ech <- ringErr
			return
		}
		if _, regErr := ring.RegisterRingFd(); regErr != nil {
			_ = ring.Close()
			ech <- regErr
			return
		}

		personality, _ := ring.RegisterPersonality()

		w := &Wakeup{
			ring:        ring,
			wg:          new(sync.WaitGroup),
			personality: uint16(personality),
			ready:       make(chan int, ring.SQEntries()),
			running:     atomic.Bool{},
		}
		// send wakeup
		vch <- w

		w.process()
	}(vch, ech)

	select {
	case v = <-vch:
		break
	case err = <-ech:
		break
	}
	close(vch)
	close(ech)
	return
}

type Wakeup struct {
	ring        *liburing.Ring
	wg          *sync.WaitGroup
	personality uint16
	ready       chan int
	running     atomic.Bool
}

func (r *Wakeup) Wakeup(ringFd int) (ok bool) {
	if ok = r.running.Load(); ok {
		r.ready <- ringFd
		return
	}
	return
}

func (r *Wakeup) Close() (err error) {
	if r.running.CompareAndSwap(true, false) {
		// send -1
		r.ready <- -1
		// wait
		r.wg.Wait()
		// close ready
		close(r.ready)
	}
	return
}

func (r *Wakeup) process() {
	r.wg.Add(1)
	r.running.Store(true)
	ring := r.ring
	for {
		fd, ok := <-r.ready
		if !ok {
			break
		}
		if fd == -1 {
			break
		}
		sqe := ring.GetSQE()
		if sqe == nil {
			_, _ = ring.Submit()
			sqe = ring.GetSQE()
		}
		sqe.PrepareMsgRing(fd, 0, nil, 0)
		_, err := ring.SubmitAndWait(1)
		if err != nil {
			continue
		}
		ring.CQAdvance(1)
	}
	// close ring
	_ = r.ring.Close()
	// done
	r.wg.Done()
}
