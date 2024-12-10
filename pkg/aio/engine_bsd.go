//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package aio

import (
	"errors"
	"golang.org/x/sys/unix"
	"runtime"
	"sync/atomic"
	"unsafe"
)

func (engine *Engine) Start() {

}

func (engine *Engine) Stop() {

}

type KqueueCylinder struct {
	fd         int
	sq         *SubmissionQueue
	completing atomic.Int64
	stopped    atomic.Bool
}

func (cylinder *KqueueCylinder) Fd() int {
	return cylinder.fd
}

func (cylinder *KqueueCylinder) Stop() {
	if cylinder.stopped.Load() {
		return
	}
	cylinder.stopped.Store(true)
	// todo submit a no-op entry
	//TODO implement me
	panic("implement me")
}

func (cylinder *KqueueCylinder) Actives() int64 {
	return cylinder.sq.Len() + cylinder.completing.Load()
}

func (cylinder *KqueueCylinder) submit(entry *unix.Kevent_t) (ok bool) {
	if cylinder.stopped.Load() {
		return
	}
	ok = cylinder.sq.Enqueue(unsafe.Pointer(entry))
	runtime.KeepAlive(entry)
	return
}

type submissionQueueNode struct {
	value unsafe.Pointer
	_pad1 [7]int64
	next  unsafe.Pointer
	_pad2 [7]int64
}

func NewSubmissionQueue(n int) (sq *SubmissionQueue) {
	if n < 1 {
		n = 16384
	}
	n = RoundupPow2(n)
	sq = &SubmissionQueue{
		head:     nil,
		tail:     nil,
		entries:  0,
		capacity: int64(n),
	}
	hn := &submissionQueueNode{
		value: nil,
		next:  nil,
	}
	sq.head = unsafe.Pointer(hn)
	sq.tail = unsafe.Pointer(hn)

	for i := 1; i < n; i++ {
		next := &submissionQueueNode{}
		tail := (*submissionQueueNode)(atomic.LoadPointer(&sq.tail))
		tail.next = unsafe.Pointer(next)
		atomic.CompareAndSwapPointer(&sq.tail, sq.tail, unsafe.Pointer(next))
	}

	tail := (*submissionQueueNode)(atomic.LoadPointer(&sq.tail))
	tail.next = sq.head

	sq.tail = sq.head
	return
}

type SubmissionQueue struct {
	head     unsafe.Pointer
	_pad1    [7]int64
	tail     unsafe.Pointer
	_pad2    [7]int64
	entries  int64
	_pad3    [7]int64
	capacity int64
	_pad4    [7]int64
}

func (sq *SubmissionQueue) Enqueue(entry unsafe.Pointer) (ok bool) {
	for {
		if atomic.LoadInt64(&sq.entries) >= sq.capacity {
			return
		}
		tail := (*submissionQueueNode)(atomic.LoadPointer(&sq.tail))
		if tail.value != nil {
			continue
		}
		if atomic.CompareAndSwapPointer(&tail.value, tail.value, entry) {
			for {
				if atomic.CompareAndSwapPointer(&sq.tail, sq.tail, tail.next) {
					atomic.AddInt64(&sq.entries, 1)
					ok = true
					return
				}
			}
		}
	}
}

func (sq *SubmissionQueue) Dequeue() (entry unsafe.Pointer) {
	for {
		head := (*submissionQueueNode)(atomic.LoadPointer(&sq.head))
		if head.value == nil {
			break
		}
		target := atomic.LoadPointer(&head.value)
		if atomic.CompareAndSwapPointer(&sq.head, sq.head, head.next) {
			atomic.AddInt64(&sq.entries, -1)
			entry = target
			break
		}
	}
	return
}

func (sq *SubmissionQueue) PeekBatch(entries []unix.Kevent_t) (n int64) {
	size := int64(len(entries))
	if size == 0 {
		return
	}
	if num := atomic.LoadInt64(&sq.entries); num < size {
		size = num
	}
	for i := int64(0); i < size; i++ {
		ptr := sq.Dequeue()
		if ptr == nil {
			break
		}
		entries[i] = *((*unix.Kevent_t)(ptr))
		n++
	}
	return
}

func (sq *SubmissionQueue) Len() int64 {
	return atomic.LoadInt64(&sq.entries)
}

func (sq *SubmissionQueue) Cap() int64 {
	return sq.capacity
}
