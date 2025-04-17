package aio

import (
	"syscall"
	"time"
)

type Transmission interface {
	Match(n uint32) (waitNr uint32, waitTimeout *syscall.Timespec)
	Up() (uint32, *syscall.Timespec)
	Down() (uint32, *syscall.Timespec)
}

type Curve []struct {
	N       uint32
	Timeout time.Duration
}

func NewCurveTransmission(curve Curve) Transmission {
	if len(curve) == 0 {
		curve = Curve{
			{8, 10 * time.Microsecond},
		}
	}
	times := make([]WaitNTime, 0, 1)
	for _, t := range curve {
		n := t.N
		if n < 1 || t.Timeout < 1 {
			continue
		}
		timeout := syscall.NsecToTimespec(t.Timeout.Nanoseconds())
		times = append(times, WaitNTime{
			n:    n,
			time: timeout,
		})
	}
	return &CurveTransmission{
		curve: times,
		size:  len(curve),
		idx:   0,
	}
}

type WaitNTime struct {
	n    uint32
	time syscall.Timespec
}

type CurveTransmission struct {
	curve []WaitNTime
	size  int
	idx   int
}

func (tran *CurveTransmission) Match(n uint32) (uint32, *syscall.Timespec) {
	left := WaitNTime{}
	for i := 0; i < tran.size; i++ {
		right := tran.curve[i]
		if left.n <= n && n < right.n {
			return right.n, &right.time
		}
		left = right
	}
	tail := tran.curve[tran.size-1]
	return tail.n, &tail.time
}

func (tran *CurveTransmission) Up() (uint32, *syscall.Timespec) {
	if tran.idx == tran.size-1 {
		tail := tran.curve[tran.idx]
		return tail.n, &tail.time
	}
	tran.idx++
	node := tran.curve[tran.idx]
	return node.n, &node.time
}

func (tran *CurveTransmission) Down() (uint32, *syscall.Timespec) {
	if tran.idx < 1 {
		head := tran.curve[0]
		return head.n, &head.time
	}
	tran.idx--
	node := tran.curve[tran.idx]
	return node.n, &node.time
}
