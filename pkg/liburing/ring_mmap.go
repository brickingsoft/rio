//go:build linux

package liburing

import (
	"syscall"
	"unsafe"
)

func setupRingPointers(p *Params, sq *SubmissionQueue, cq *CompletionQueue) {
	sq.head = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.head)))
	sq.tail = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.tail)))
	sq.ringMask = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.ringMask)))
	sq.ringEntries = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.ringEntries)))
	sq.flags = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.flags)))
	sq.dropped = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.dropped)))
	sq.array = (*uint32)(unsafe.Pointer(uintptr(sq.ringPtr) + uintptr(p.sqOff.array)))

	cq.head = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.head)))
	cq.tail = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.tail)))
	cq.ringMask = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.ringMask)))
	cq.ringEntries = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.ringEntries)))
	cq.overflow = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.overflow)))
	cq.cqes = (*CompletionQueueEvent)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.cqes)))
	if p.cqOff.flags != 0 {
		cq.flags = (*uint32)(unsafe.Pointer(uintptr(cq.ringPtr) + uintptr(p.cqOff.flags)))
	}
}

const (
	offsqRing    uint64 = 0
	offcqRing    uint64 = 0x8000000
	offSQEs      uint64 = 0x10000000
	offPbufRing  uint64 = 0x80000000
	offPbufShift uint64 = 16
	offMmapMask  uint64 = 0xf8000000
)

func mmapRing(fd int, p *Params, sq *SubmissionQueue, cq *CompletionQueue) error {
	var size uintptr
	var err error

	size = unsafe.Sizeof(CompletionQueueEvent{})
	if p.flags&IORING_SETUP_CQE32 != 0 {
		size += unsafe.Sizeof(CompletionQueueEvent{})
	}

	sq.ringSize = uint(uintptr(p.sqOff.array) + uintptr(p.sqEntries)*unsafe.Sizeof(uint32(0)))
	cq.ringSize = uint(uintptr(p.cqOff.cqes) + uintptr(p.cqEntries)*size)

	if p.features&IORING_FEAT_SINGLE_MMAP != 0 {
		if cq.ringSize > sq.ringSize {
			sq.ringSize = cq.ringSize
		}
		cq.ringSize = sq.ringSize
	}

	sq.ringPtr, err = mmap(0, uintptr(sq.ringSize), syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE, fd,
		int64(offsqRing))
	if err != nil {
		return err
	}

	if p.features&IORING_FEAT_SINGLE_MMAP != 0 {
		cq.ringPtr = sq.ringPtr
	} else {
		cq.ringPtr, err = mmap(0, uintptr(cq.ringSize), syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE, fd,
			int64(offcqRing))
		if err != nil {
			cq.ringPtr = nil
			unmapRings(sq, cq)
			return err
		}
	}

	size = unsafe.Sizeof(SubmissionQueueEntry{})
	if p.flags&IORING_SETUP_SQE128 != 0 {
		size += 64
	}
	sqesPtr, sqesMmapErr := mmap(0, size*uintptr(p.sqEntries), syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE, fd, int64(offSQEs))
	if sqesMmapErr != nil {
		err = sqesMmapErr
		unmapRings(sq, cq)
		return err
	}
	sq.sqes = (*SubmissionQueueEntry)(sqesPtr)
	setupRingPointers(p, sq, cq)
	return nil
}

func unmapRings(sq *SubmissionQueue, cq *CompletionQueue) {
	if sq.ringSize > 0 {
		_ = munmap(uintptr(sq.ringPtr), uintptr(sq.ringSize))
	}
	if uintptr(cq.ringPtr) != 0 && cq.ringSize > 0 && cq.ringPtr != sq.ringPtr {
		_ = munmap(uintptr(cq.ringPtr), uintptr(cq.ringSize))
	}
}
