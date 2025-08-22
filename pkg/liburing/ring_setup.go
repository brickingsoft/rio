//go:build linux

package liburing

import (
	"bytes"
	"errors"
	"math/bits"
	"os"
	"syscall"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing/bytex"
)

const (
	sysSetup = 425
)

const (
	regRing       uint8 = 1
	doubleRegRing uint8 = 2
	appMemRing    uint8 = 4
)

func (ring *Ring) setup(entries uint32, params *Params, buf unsafe.Pointer, bufSize uint64) error {
	var fd int
	var sqEntries, index uint32
	var err error

	if params.flags&IORING_SETUP_REGISTERED_FD_ONLY != 0 && params.flags&IORING_SETUP_NO_MMAP == 0 {
		return syscall.EINVAL
	}

	if params.flags&IORING_SETUP_NO_MMAP != 0 {
		_, err = allocHuge(entries, params, ring.sqRing, ring.cqRing, buf, bufSize)
		if err != nil {
			return err
		}
		if buf != nil {
			ring.kind |= appMemRing
		}
	}

	fdPtr, _, errno := syscall.Syscall(sysSetup, uintptr(entries), uintptr(unsafe.Pointer(params)), 0)
	if errno != 0 {
		if params.flags&IORING_SETUP_NO_MMAP != 0 && ring.kind&appMemRing == 0 {
			_ = munmap(uintptr(unsafe.Pointer(ring.sqRing.sqes)), 1)
			unmapRings(ring.sqRing, ring.cqRing)
		}

		return errno
	}
	fd = int(fdPtr)

	if params.flags&IORING_SETUP_NO_MMAP == 0 {
		err = mmapRing(fd, params, ring.sqRing, ring.cqRing)
		if err != nil {
			_ = syscall.Close(fd)
			return err
		}
	} else {
		setupRingPointers(params, ring.sqRing, ring.cqRing)
	}

	sqEntries = *ring.sqRing.ringEntries
	for index = 0; index < sqEntries; index++ {
		*(*uint32)(
			unsafe.Add(unsafe.Pointer(ring.sqRing.array),
				index*uint32(unsafe.Sizeof(uint32(0))))) = index
	}

	ring.features = params.features
	ring.flags = params.flags
	ring.enterRingFd = fd
	if params.flags&IORING_SETUP_REGISTERED_FD_ONLY != 0 {
		ring.ringFd = -1
		ring.kind |= regRing | doubleRegRing
	} else {
		ring.ringFd = fd
		syscall.CloseOnExec(ring.ringFd)
	}
	return nil
}

func MLockSizeParams(entries uint32, p *Params) (uint64, error) {
	if entries == 0 {
		return 0, syscall.EINVAL
	}
	entries = RoundupPow2(entries)
	if entries > MaxEntries {
		if p.flags&IORING_SETUP_CLAMP == 0 {
			return 0, syscall.EINVAL
		}
		entries = MaxEntries
	}

	lp := &Params{}
	ring := &Ring{
		sqRing: &SubmissionQueue{},
		cqRing: &CompletionQueue{},
	}
	var cqEntries, sq uint32
	var pageSize uint64
	var err error

	err = ring.setup(entries, lp, nil, 0)
	if err != nil {
		_ = ring.Close()
	}

	if lp.features&IORING_FEAT_NATIVE_WORKERS != 0 {
		return 0, nil
	}

	sq, cqEntries, err = getSQAndCQEntries(entries, p)
	if err != nil {
		return 0, err
	}
	pageSize = uint64(os.Getpagesize())
	return sizeOfRing(p, sq, cqEntries, pageSize), nil
}

func MLockSize(entries, flags uint32) (uint64, error) {
	p := &Params{}
	p.flags = flags
	return MLockSizeParams(entries, p)
}

func fls(x int) int {
	if x == 0 {
		return 0
	}
	return 8*int(unsafe.Sizeof(x)) - bits.LeadingZeros32(uint32(x))
}

func npages(size uint64, pageSize uint64) uint64 {
	size--
	size /= pageSize
	return uint64(fls(int(size)))
}

const (
	ringSize      = 320
	ringSizeCQOff = 63
	not63ul       = 18446744073709551552
)

func sizeOfRing(p *Params, entries uint32, cqEntries uint32, pageSize uint64) uint64 {
	var pages, sqSize, cqSize uint64

	cqSize = uint64(unsafe.Sizeof(CompletionQueueEvent{}))
	if p.flags&IORING_SETUP_CQE32 != 0 {
		cqSize += uint64(unsafe.Sizeof(CompletionQueueEvent{}))
	}
	cqSize *= uint64(cqEntries)
	cqSize += ringSize
	cqSize = (cqSize + ringSizeCQOff) & not63ul
	pages = 1 << npages(cqSize, pageSize)

	sqSize = uint64(unsafe.Sizeof(SubmissionQueueEntry{}))
	if p.flags&IORING_SETUP_SQE128 != 0 {
		sqSize += 64
	}
	sqSize *= uint64(entries)
	pages += 1 << npages(sqSize, pageSize)

	return pages * pageSize
}

func getHugePagesize() (uint64, error) {
	b, rErr := os.ReadFile("/proc/meminfo")
	if rErr != nil {
		return 0, rErr
	}
	hugepagePrefix := []byte("Hugepagesize:")
	ss := bytes.Split(b, []byte("\n"))
	for i := 0; i < len(ss); i++ {
		if after, found := bytes.CutPrefix(ss[i], hugepagePrefix); found {
			return bytex.ParseBytes(string(after))
		}
	}
	return 0, errors.New("hugepagesize not found in /proc/meminfo")
}

func allocHuge(entries uint32, p *Params, sq *SubmissionQueue, cq *CompletionQueue, buf unsafe.Pointer, bufSize uint64) (uint, error) {
	hugePageSize, hugePageSizeErr := getHugePagesize()
	if hugePageSizeErr != nil {
		return 0, hugePageSizeErr
	}

	pageSize := uint64(os.Getpagesize())
	var sqEntries, cqEntries uint32
	var ringMem, sqesMem uint64
	var memUsed uint64
	var ptr unsafe.Pointer

	var err error
	sqEntries, cqEntries, err = getSQAndCQEntries(entries, p)
	if err != nil {
		return 0, err
	}

	sqesMem = uint64(sqEntries) * uint64(unsafe.Sizeof(SubmissionQueue{}))
	sqesMem = (sqesMem + pageSize - 1) &^ (pageSize - 1)
	ringMem = uint64(cqEntries) * uint64(unsafe.Sizeof(CompletionQueue{}))
	if p.flags&IORING_SETUP_CQE32 != 0 {
		ringMem *= 2
	}
	ringMem += uint64(sqEntries) * uint64(unsafe.Sizeof(uint32(0)))
	memUsed = sqesMem + ringMem
	memUsed = (memUsed + pageSize - 1) &^ (pageSize - 1)

	if buf == nil && (sqesMem > hugePageSize || ringMem > hugePageSize) {
		return 0, syscall.ENOMEM
	}

	if buf != nil {
		if memUsed > bufSize {
			return 0, syscall.ENOMEM
		}
		ptr = buf
	} else {
		var mapHugetlb int
		if sqesMem <= pageSize {
			bufSize = pageSize
		} else {
			bufSize = hugePageSize
			mapHugetlb = syscall.MAP_HUGETLB
		}
		ptr, err = mmap(
			0, uintptr(bufSize),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_ANONYMOUS|mapHugetlb, -1, 0)
		if err != nil {
			return 0, err
		}
	}

	sq.sqes = (*SubmissionQueueEntry)(ptr)
	if memUsed <= bufSize {
		sq.ringPtr = unsafe.Pointer(uintptr(unsafe.Pointer(sq.sqes)) + uintptr(sqesMem))
		cq.ringSize = 0
		sq.ringSize = 0
	} else {
		var mapHugetlb int
		if ringMem <= pageSize {
			bufSize = pageSize
		} else {
			bufSize = hugePageSize
			mapHugetlb = syscall.MAP_HUGETLB
		}
		ptr, err = mmap(
			0, uintptr(bufSize),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_ANONYMOUS|mapHugetlb, -1, 0)
		if err != nil {
			_ = munmap(uintptr(unsafe.Pointer(sq.sqes)), 1)
			return 0, err
		}
		sq.ringPtr = ptr
		sq.ringSize = uint(bufSize)
		cq.ringSize = 0
	}

	cq.ringPtr = sq.ringPtr
	p.sqOff.userAddr = uint64(uintptr(unsafe.Pointer(sq.sqes)))
	p.cqOff.userAddr = uint64(uintptr(sq.ringPtr))
	return uint(memUsed), nil
}

const (
	cqEntriesMultiplier = 2
	maxCQEntries        = cqEntriesMultiplier * MaxEntries
)

func getSQAndCQEntries(entries uint32, p *Params) (uint32, uint32, error) {
	var cqEntries uint32

	if entries == 0 {
		return 0, 0, syscall.EINVAL
	}
	if entries > MaxEntries {
		if p.flags&IORING_SETUP_CLAMP == 0 {
			return 0, 0, syscall.EINVAL
		}
		entries = MaxEntries
	}

	entries = RoundupPow2(entries)
	if p.flags&IORING_SETUP_CQSIZE != 0 {
		if p.cqEntries == 0 {
			return 0, 0, syscall.EINVAL
		}
		cqEntries = p.cqEntries
		if cqEntries > maxCQEntries {
			if p.flags&IORING_SETUP_CLAMP == 0 {
				return 0, 0, syscall.EINVAL
			}
			cqEntries = maxCQEntries
		}
		cqEntries = RoundupPow2(cqEntries)
		if cqEntries < entries {
			return 0, 0, syscall.EINVAL
		}
	} else {
		cqEntries = cqEntriesMultiplier * entries
	}
	return entries, cqEntries, nil
}
