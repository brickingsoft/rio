//go:build linux

package liburing

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	sysRegister = 427
)

const (
	IORING_REGISTER_BUFFERS uint32 = iota
	IORING_UNREGISTER_BUFFERS
	IORING_REGISTER_FILES
	IORING_UNREGISTER_FILES
	IORING_REGISTER_EVENTFD
	IORING_UNREGISTER_EVENTFD
	IORING_REGISTER_FILES_UPDATE
	IORING_REGISTER_EVENTFD_ASYNC
	IORING_REGISTER_PROBE
	IORING_REGISTER_PERSONALITY
	IORING_UNREGISTER_PERSONALITY
	IORING_REGISTER_RESTRICTIONS
	IORING_REGISTER_ENABLE_RINGS
	IORING_REGISTER_FILES2
	IORING_REGISTER_FILES_UPDATE2
	IORING_REGISTER_BUFFERS2
	IORING_REGISTER_BUFFERS_UPDATE
	IORING_REGISTER_IOWQ_AFF
	IORING_UNREGISTER_IOWQ_AFF
	IORING_REGISTER_IOWQ_MAX_WORKERS
	IORING_REGISTER_RING_FDS
	IORING_UNREGISTER_RING_FDS
	IORING_REGISTER_PBUF_RING
	IORING_UNREGISTER_PBUF_RING
	IORING_REGISTER_SYNC_CANCEL
	IORING_REGISTER_FILE_ALLOC_RANGE
	IORING_REGISTER_PBUF_STATUS
	IORING_REGISTER_NAPI
	IORING_UNREGISTER_NAPI
	IORING_REGISTER_CLOCK
	IORING_REGISTER_CLONE_BUFFERS
	IORING_REGISTER_SEND_MSG_RING
	IORING_REGISTER_ZCRX_IFQ
	IORING_REGISTER_RESIZE_RINGS
	IORING_REGISTER_MEM_REGION

	IORING_REGISTER_LAST
	IORING_REGISTER_USE_REGISTERED_RING = 1 << 31
)

const (
	IORING_MEM_REGION_TYPE_USER = 1
)

const (
	IORING_RESTRICTION_REGISTER_OP uint32 = iota
	IORING_RESTRICTION_SQE_OP
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED
	IORING_RESTRICTION_LAST
)

const IORING_RSRC_REGISTER_SPARSE uint32 = 1 << iota
const IORING_REGISTER_FILES_SKIP int = -2

const (
	IORING_REGISTER_SRC_REGISTERED uint32 = 1 << iota
	IORING_REGISTER_DST_REPLACE
)

const (
	IOU_PBUF_RING_MMAP = 1
	IOU_PBUF_RING_INC  = 2
)

const (
	IORING_REG_WAIT_TS uint32 = 1 << iota
)

type FilesUpdate struct {
	Offset uint32
	Resv   uint32
	Fds    uint64
}

type RsrcRegister struct {
	Nr    uint32
	Flags uint32
	Resv2 uint64
	Data  uint64
	Tags  uint64
}

type RsrcUpdate struct {
	Offset uint32
	Resv   uint32
	Data   uint64
}

type RsrcUpdate2 struct {
	Offset uint32
	Resv   uint32
	Data   uint64
	Tags   uint64
	Nr     uint32
	Resv2  uint32
}

type Restriction struct {
	OpCode  uint16
	OpFlags uint8
	Resv    uint8
	Resv2   [3]uint32
}

type SyncCancelReg struct {
	Addr    uint64
	Fd      int32
	Flags   uint32
	Timeout syscall.Timespec
	Pad     [4]uint64
}

type FileIndexRange struct {
	Off  uint32
	Len  uint32
	Resv uint64
}

func (ring *Ring) Register(fd int, opcode uint32, arg unsafe.Pointer, nrArgs uint32) (uint, syscall.Errno) {
	r1, _, errno := syscall.RawSyscall6(
		sysRegister,
		uintptr(fd),
		uintptr(opcode),
		uintptr(arg),
		uintptr(nrArgs),
		0,
		0,
	)
	return uint(r1), errno
}

func (ring *Ring) RegisterBuffersUpdateTag(off uint32, iovecs []syscall.Iovec, tags *uint64, nr uint32) (uint, error) {
	update := &RsrcUpdate2{
		Offset: off,
		Data:   uint64(uintptr(unsafe.Pointer(&iovecs[0]))),
		Tags:   *tags,
		Nr:     nr,
	}
	result, err := ring.doRegister(IORING_REGISTER_BUFFERS_UPDATE, unsafe.Pointer(update), uint32(unsafe.Sizeof(*update)))
	runtime.KeepAlive(update)
	return result, err
}

func (ring *Ring) RegisterBuffersTags(iovecs []syscall.Iovec, tags []uint64) (uint, error) {
	reg := &RsrcRegister{
		Nr:   uint32(len(tags)),
		Data: uint64(uintptr(unsafe.Pointer(&iovecs[0]))),
		Tags: uint64(uintptr(unsafe.Pointer(&tags[0]))),
	}
	result, err := ring.doRegister(IORING_REGISTER_BUFFERS2, unsafe.Pointer(reg), uint32(unsafe.Sizeof(*reg)))
	runtime.KeepAlive(reg)
	return result, err
}

func (ring *Ring) RegisterBuffersSparse(nr uint32) (uint, error) {
	reg := &RsrcRegister{
		Flags: IORING_RSRC_REGISTER_SPARSE,
		Nr:    nr,
	}
	result, err := ring.doRegister(IORING_REGISTER_BUFFERS2, unsafe.Pointer(reg), uint32(unsafe.Sizeof(*reg)))
	runtime.KeepAlive(reg)
	return result, err
}

func (ring *Ring) RegisterBuffers(iovecs []syscall.Iovec) (uint, error) {
	return ring.doRegister(IORING_REGISTER_BUFFERS, unsafe.Pointer(&iovecs[0]), uint32(len(iovecs)))
}

func (ring *Ring) UnregisterBuffers() (uint, error) {
	return ring.doRegister(IORING_UNREGISTER_BUFFERS, unsafe.Pointer(nil), 0)
}

func (ring *Ring) RegisterFilesUpdateTag(off uint, files []int, tags []uint64) (uint, error) {
	update := &RsrcUpdate2{
		Offset: uint32(off),
		Data:   uint64(uintptr(unsafe.Pointer(&files[0]))),
		Tags:   uint64(uintptr(unsafe.Pointer(&tags[0]))),
		Nr:     uint32(len(files)),
	}
	result, err := ring.doRegister(IORING_REGISTER_BUFFERS2, unsafe.Pointer(update), 1)
	runtime.KeepAlive(update)
	return result, err
}

func (ring *Ring) RegisterFilesUpdate(off uint, files []int) (uint, error) {
	update := &FilesUpdate{
		Offset: uint32(off),
		Fds:    uint64(uintptr(unsafe.Pointer(&files[0]))),
	}
	result, err := ring.doRegister(IORING_REGISTER_FILES_UPDATE, unsafe.Pointer(update), uint32(len(files)))
	runtime.KeepAlive(update)
	return result, err
}

func (ring *Ring) RegisterFilesSparse(nr uint32) (uint, error) {
	reg := &RsrcRegister{
		Flags: IORING_RSRC_REGISTER_SPARSE,
		Nr:    nr,
	}
	var (
		ret         uint
		err         error
		errno       syscall.Errno
		didIncrease bool
	)
	for {
		ret, errno = ring.doRegisterErrno(IORING_REGISTER_FILES2, unsafe.Pointer(reg), uint32(unsafe.Sizeof(*reg)))
		if errno != 0 {
			break
		}
		if errno == syscall.EMFILE && !didIncrease {
			didIncrease = true
			err = increaseRlimitNoFile(uint64(nr))
			if err != nil {
				break
			}
			continue
		}
		break
	}
	return ret, err
}

func (ring *Ring) RegisterFilesTags(files []int, tags []uint64) (uint, error) {
	nr := len(files)
	reg := &RsrcRegister{
		Nr:   uint32(nr),
		Data: uint64(uintptr(unsafe.Pointer(&files[0]))),
		Tags: uint64(uintptr(unsafe.Pointer(&tags[0]))),
	}
	var (
		ret         uint
		err         error
		errno       syscall.Errno
		didIncrease bool
	)
	for {
		ret, errno = ring.doRegisterErrno(IORING_REGISTER_FILES2, unsafe.Pointer(reg), uint32(unsafe.Sizeof(*reg)))
		if ret > 0 {
			break
		}
		if errno == syscall.EMFILE && !didIncrease {
			didIncrease = true
			err = increaseRlimitNoFile(uint64(nr))
			if err != nil {
				break
			}
			continue
		}
		break
	}
	return ret, err
}

func (ring *Ring) RegisterFiles(files []int) (uint, error) {
	var (
		ret         uint
		err         error
		errno       syscall.Errno
		didIncrease bool
	)
	for {
		ret, errno = ring.doRegisterErrno(IORING_REGISTER_FILES, unsafe.Pointer(&files[0]), uint32(len(files)))
		if ret > 0 {
			break
		}
		if errno == syscall.EMFILE && !didIncrease {
			didIncrease = true
			err = increaseRlimitNoFile(uint64(len(files)))
			if err != nil {
				break
			}
			continue
		}
		break
	}
	return ret, err
}

func (ring *Ring) UnregisterFiles() (uint, error) {
	return ring.doRegister(IORING_UNREGISTER_FILES, unsafe.Pointer(nil), 0)
}

func (ring *Ring) RegisterEventFd(fd int) (uint, error) {
	return ring.doRegister(IORING_REGISTER_EVENTFD, unsafe.Pointer(&fd), 1)
}

func (ring *Ring) UnregisterEventFd(fd int) (uint, error) {
	return ring.doRegister(IORING_UNREGISTER_EVENTFD, unsafe.Pointer(&fd), 1)
}

func (ring *Ring) RegisterEventFdAsync(fd int) (uint, error) {
	return ring.doRegister(IORING_REGISTER_EVENTFD_ASYNC, unsafe.Pointer(&fd), 1)
}

func (ring *Ring) RegisterProbe(probe *Probe, nrOps int) (uint, error) {
	result, err := ring.doRegister(IORING_REGISTER_PROBE, unsafe.Pointer(probe), uint32(nrOps))
	runtime.KeepAlive(probe)

	return result, err
}

func (ring *Ring) RegisterPersonality() (uint, error) {
	return ring.doRegister(IORING_REGISTER_PERSONALITY, unsafe.Pointer(nil), 0)
}

func (ring *Ring) UnregisterPersonality() (uint, error) {
	return ring.doRegister(IORING_UNREGISTER_PERSONALITY, unsafe.Pointer(nil), 0)
}

func (ring *Ring) RegisterRestrictions(res []Restriction) (uint, error) {
	return ring.doRegister(IORING_REGISTER_RESTRICTIONS, unsafe.Pointer(&res[0]), uint32(len(res)))
}

func (ring *Ring) doRegisterErrno(opCode uint32, arg unsafe.Pointer, nrArgs uint32) (uint, syscall.Errno) {
	var fd int
	if ring.kind&regRing != 0 {
		opCode |= IORING_REGISTER_USE_REGISTERED_RING
		fd = ring.enterRingFd
	} else {
		fd = ring.ringFd
	}
	return ring.Register(fd, opCode, arg, nrArgs)
}

func (ring *Ring) RegisterIOWQAff(cpusz uint64, mask *unix.CPUSet) error {
	if cpusz >= 1<<31 {
		return syscall.EINVAL
	}
	_, err := ring.doRegister(IORING_REGISTER_IOWQ_AFF, unsafe.Pointer(mask), uint32(cpusz))
	runtime.KeepAlive(mask)
	return err
}

func (ring *Ring) UnregisterIOWQAff() (uint, error) {
	return ring.doRegister(IORING_UNREGISTER_IOWQ_AFF, unsafe.Pointer(nil), 0)
}

const (
	IO_WQ_BOUND = iota
	IO_WQ_UNBOUND
)

const regIOWQMaxWorkersNrArgs = 2

func (ring *Ring) RegisterIOWQMaxWorkers(val []uint) (uint, error) {
	return ring.doRegister(IORING_REGISTER_IOWQ_MAX_WORKERS, unsafe.Pointer(&val[0]), regIOWQMaxWorkersNrArgs)
}

const registerRingFdOffset = uint32(4294967295)

func (ring *Ring) RegisterRingFd() (uint, error) {
	if (ring.kind & regRing) != 0 {
		return 0, syscall.EEXIST
	}
	update := &RsrcUpdate{
		Data:   uint64(ring.ringFd),
		Offset: registerRingFdOffset,
	}
	ret, err := ring.doRegister(IORING_REGISTER_RING_FDS, unsafe.Pointer(update), 1)
	if err != nil {
		return ret, err
	}
	if ret == 1 {
		ring.enterRingFd = int(update.Offset)
		ring.kind |= regRing

		if ring.features&IORING_FEAT_REG_REG_RING != 0 {
			ring.kind |= doubleRegRing
		}
	} else {
		return ret, fmt.Errorf("unexpected return from ring.Register: %d", ret)
	}
	return ret, nil
}

func (ring *Ring) UnregisterRingFd() (uint, error) {
	update := &RsrcUpdate{
		Offset: uint32(ring.enterRingFd),
	}
	if (ring.kind & regRing) != 0 {
		return 0, syscall.EINVAL
	}
	ret, err := ring.doRegister(IORING_UNREGISTER_RING_FDS, unsafe.Pointer(update), 1)
	if err != nil {
		return ret, err
	}
	if ret == 1 {
		ring.enterRingFd = ring.ringFd
		ring.kind &= ^(regRing | doubleRegRing)
	}
	return ret, nil
}

func (ring *Ring) RegisterBufferRing(reg *BufReg) (uint, error) {
	result, err := ring.doRegister(IORING_REGISTER_PBUF_RING, unsafe.Pointer(reg), 1)
	runtime.KeepAlive(reg)
	return result, err
}

func (ring *Ring) UnregisterBufferRing(bgid uint16) (uint, error) {
	reg := &BufReg{
		Bgid: bgid,
	}
	result, err := ring.doRegister(IORING_UNREGISTER_PBUF_RING, unsafe.Pointer(reg), 1)
	runtime.KeepAlive(reg)
	return result, err
}

func (ring *Ring) RegisterSyncCancel(reg *SyncCancelReg) (uint, error) {
	return ring.doRegister(IORING_REGISTER_SYNC_CANCEL, unsafe.Pointer(reg), 1)
}

func (ring *Ring) RegisterFileAllocRange(off, length uint32) (uint, error) {
	fileRange := &FileIndexRange{
		Off: off,
		Len: length,
	}
	result, err := ring.doRegister(IORING_REGISTER_FILE_ALLOC_RANGE, unsafe.Pointer(fileRange), 0)
	runtime.KeepAlive(fileRange)
	return result, err
}

type NAPI struct {
	BusyPollTo     uint32
	PreferBusyPoll uint8
	_pad           [3]uint8
	Resv           uint64
}

func (ring *Ring) RegisterNAPI(napi *NAPI) (uint, error) {
	return ring.doRegister(IORING_REGISTER_NAPI, unsafe.Pointer(napi), 1)
}

func (ring *Ring) UnregisterNAPI(napi *NAPI) (uint, error) {
	return ring.doRegister(IORING_UNREGISTER_NAPI, unsafe.Pointer(napi), 1)
}

func (ring *Ring) doRegister(opCode uint32, arg unsafe.Pointer, nrArgs uint32) (uint, error) {
	ret, errno := ring.doRegisterErrno(opCode, arg, nrArgs)
	if errno != 0 {
		return 0, os.NewSyscallError("io_uring_register", errno)
	}
	return ret, nil
}

func increaseRlimitNoFile(nr uint64) error {
	limit := syscall.Rlimit{}
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	if err != nil {
		return err
	}
	if limit.Cur < nr {
		limit.Cur += nr
		err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit)
		if err != nil {
			return err
		}
	}
	return nil
}
