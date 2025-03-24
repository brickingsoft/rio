//go:build linux

package aio

import (
	"errors"
	"github.com/brickingsoft/rio/pkg/iouring"
	"github.com/brickingsoft/rio/pkg/process"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	ErrIOURingSQBusy = errors.New("submission queue is busy")
)

type SQEProducer interface {
	Produce(op *Operation) bool
	Close() error
}

func newSQEChanProducer(ring *iouring.Ring, affinityCPU int, batchSize int, batchTimeWindow time.Duration, batchIdleTime time.Duration) SQEProducer {

	p := &SQEChanProducer{
		running:         atomic.Bool{},
		ring:            ring,
		ch:              make(chan *Operation, ring.SQEntries()),
		affinityCPU:     affinityCPU,
		batchSize:       batchSize,
		batchTimeWindow: batchTimeWindow,
		batchIdleTime:   batchIdleTime,
		wg:              new(sync.WaitGroup),
	}

	p.running.Store(true)

	if ring.Flags()&iouring.SetupSQPoll != 0 {
		go p.handleImmediately()
	} else {
		go p.handleBatch()
	}

	p.wg.Add(1)
	return p
}

type SQEChanProducer struct {
	running         atomic.Bool
	ring            *iouring.Ring
	ch              chan *Operation
	affinityCPU     int
	batchSize       int
	batchTimeWindow time.Duration
	batchIdleTime   time.Duration
	wg              *sync.WaitGroup
}

func (producer *SQEChanProducer) Produce(op *Operation) bool {
	if producer.running.Load() {
		producer.ch <- op
		return true
	}
	return false
}

func (producer *SQEChanProducer) Close() (err error) {
	producer.running.Store(false)
	time.Sleep(50 * time.Millisecond)
	close(producer.ch)
	producer.wg.Wait()
	return
}

func (producer *SQEChanProducer) handleImmediately() {
	defer producer.wg.Done()

	if producer.affinityCPU > -1 {
		runtime.LockOSThread()
		_ = process.SetCPUAffinity(producer.affinityCPU)
		defer runtime.UnlockOSThread()
	}
	ring := producer.ring
	operations := producer.ch

	for {
		op, ok := <-operations
		if !ok {
			break
		}
		if op == nil {
			continue
		}
		if op.canPrepare() {
			sqe := ring.GetSQE()
			if sqe == nil {
				op.failed(ErrIOURingSQBusy) // when prep err occur, means no sqe left
				break
			}
			var timeoutSQE *iouring.SubmissionQueueEntry
			if op.timeout != nil {
				timeoutSQE = ring.GetSQE()
				if timeoutSQE == nil { // timeout but no sqe, then prep_nop and submit
					op.failed(ErrIOURingSQBusy)
					sqe.PrepareNop()
					_, _ = ring.Submit()
					break
				}
			}
			if err := op.packingSQE(sqe); err != nil { // make err but prep_nop, so need to submit
				op.failed(err)
				sqe.PrepareNop()
			} else {
				if timeoutSQE != nil { // prep_link_timeout
					timeoutOp := op.attached
					if timeoutErr := timeoutOp.packingSQE(timeoutSQE); timeoutErr != nil {
						// should be ok
						panic(errors.New("packing timeout SQE failed: " + timeoutErr.Error()))
					}
				}
			}
			_, _ = ring.Submit()
		}
	}
}

func (producer *SQEChanProducer) handleBatch() {
	defer producer.wg.Done()

	if producer.affinityCPU > -1 {
		runtime.LockOSThread()
		_ = process.SetCPUAffinity(producer.affinityCPU)
		defer runtime.UnlockOSThread()
	}
	ring := producer.ring
	operations := producer.ch

	idleTime := producer.batchIdleTime
	if idleTime < 1 {
		idleTime = defaultSQEProduceBatchIdleTime
	}
	batchTimeWindow := producer.batchTimeWindow
	if batchTimeWindow < 1 {
		batchTimeWindow = defaultSQEProduceBatchTimeWindow
	}

	batchTimer := time.NewTimer(batchTimeWindow)
	defer batchTimer.Stop()

	batchSize := producer.batchSize
	if batchSize < 1 {
		batchSize = 64
	}
	batchOps := make([]*Operation, batchSize)
	batchSQEs := make([]*iouring.SubmissionQueueEntry, batchSize*2)

	var (
		batchIdx     = 0
		stopped      = false
		idle         = false
		needToSubmit = false
	)

	for {
		if stopped {
			break
		}
		select {
		case <-batchTimer.C:
			needToSubmit = true
			break
		case op, ok := <-operations:
			if !ok {
				stopped = true
				break
			}
			if op == nil {
				break
			}
			if idle {
				idle = false
				batchTimer.Reset(batchTimeWindow)
			}
			batchOps[batchIdx] = op
			batchIdx++
			if batchIdx == batchSize {
				needToSubmit = true
				break
			}
			break
		}
		if batchIdx == 0 { // when no request, use idle time
			idle = true
			batchTimer.Reset(idleTime)
			continue
		}
		if needToSubmit { // go to prepare
			sqeIndex := 0
			for i := 0; i < batchIdx; i++ {
				op := batchOps[i]
				if op == nil {
					continue
				}
				if op.canPrepare() {
					sqe := ring.GetSQE()
					if sqe == nil {
						op.failed(ErrIOURingSQBusy) // when prep err occur, means no sqe left
						continue
					}
					var timeoutSQE *iouring.SubmissionQueueEntry
					if op.timeout != nil {
						timeoutSQE = ring.GetSQE()
						if timeoutSQE == nil { // timeout but no sqe, then prep_nop and submit
							op.failed(ErrIOURingSQBusy)
							sqe.PrepareNop()
							batchSQEs[sqeIndex] = sqe
							sqeIndex++
							continue
						}
					}
					batchSQEs[sqeIndex] = sqe
					sqeIndex++
					if err := op.packingSQE(sqe); err != nil { // make err but prep_nop, so need to submit
						op.failed(err)
						sqe.PrepareNop()
					} else {
						if timeoutSQE != nil { // prep_link_timeout
							timeoutOp := op.attached
							if timeoutErr := timeoutOp.packingSQE(timeoutSQE); timeoutErr != nil {
								// should be ok
								panic(errors.New("packing timeout SQE failed: " + timeoutErr.Error()))
							}
							batchSQEs[sqeIndex] = timeoutSQE
							sqeIndex++
						}
					}
					continue
				}
			}

		SUBMIT:
			if _, submitErr := ring.Submit(); submitErr != nil {
				if errors.Is(submitErr, syscall.EAGAIN) || errors.Is(submitErr, syscall.EINTR) {
					goto SUBMIT
				}
				for i := 0; i < batchIdx; i++ {
					op := batchOps[i]
					op.failed(os.NewSyscallError("ring_submit", submitErr))
				}
				continue
			}
			// clean
			for i := 0; i < batchIdx; i++ {
				batchOps[i] = nil
			}
			for i := 0; i < sqeIndex; i++ {
				batchSQEs[sqeIndex] = nil
			}
			// reset
			batchIdx = 0
			batchTimer.Reset(batchTimeWindow)
		}
	}
}
