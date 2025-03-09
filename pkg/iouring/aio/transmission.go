package aio

import (
	"sort"
	"syscall"
	"time"
)

type Transmission interface {
	Up() (uint32, syscall.Timespec)
	Down() (uint32, syscall.Timespec)
}

type Curve []struct {
	N       uint32
	Timeout time.Duration
}

const (
	defaultWaitTimeout = 1 * time.Microsecond
)

var (
	defaultCurve = Curve{
		{4, 500 * time.Nanosecond},
		{8, 1 * time.Microsecond},
		{16, 500 * time.Microsecond},
		{32, 1 * time.Millisecond},
		{64, 2 * time.Millisecond},
	}
)

func NewCurveTransmission(curve Curve) Transmission {
	if len(curve) == 0 {
		curve = defaultCurve
	}
	times := make([]WaitNTime, len(curve))
	for i, t := range curve {
		n := t.N
		if n == 0 {
			n = 1
		}
		timeout := t.Timeout
		if timeout < 1 {
			timeout = defaultWaitTimeout
		}
		times[i] = WaitNTime{
			n:    n,
			time: syscall.NsecToTimespec(timeout.Nanoseconds()),
		}
	}
	sort.Slice(times, func(i, j int) bool {
		return times[i].n < times[j].n
	})
	return &CurveTransmission{
		curve: times,
		size:  len(curve),
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

func (tran *CurveTransmission) Up() (uint32, syscall.Timespec) {
	if tran.idx == tran.size-1 {
		return tran.curve[tran.idx].n, tran.curve[tran.idx].time
	}
	tran.idx++
	return tran.curve[tran.idx].n, tran.curve[tran.idx].time
}

func (tran *CurveTransmission) Down() (uint32, syscall.Timespec) {
	if tran.idx == 0 {
		return tran.curve[0].n, tran.curve[0].time
	}
	tran.idx--
	return tran.curve[tran.idx].n, tran.curve[tran.idx].time
}
