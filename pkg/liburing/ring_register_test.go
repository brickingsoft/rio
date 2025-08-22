//go:build linux

package liburing_test

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func TestSubmissionQueueEntry_PrepareProvideBuffers(t *testing.T) {
	ring, ringErr := liburing.New(liburing.WithEntries(4))
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	var (
		sqe    *liburing.SubmissionQueueEntry
		sn     uint
		sErr   error
		cqe    *liburing.CompletionQueueEvent
		cqeErr error
	)

	buffers := make([]syscall.Iovec, 4)
	for i := range buffers {
		b := make([]byte, 4096)
		buffers[i] = syscall.Iovec{
			Base: &b[0],
			Len:  uint64(len(b)),
		}
	}

	addr := uintptr(unsafe.Pointer(&buffers[0]))
	addrLen := uint32(len(buffers))
	nr := 4

	sqe = ring.GetSQE()
	sqe.PrepareProvideBuffers(addr, addrLen, nr, 0, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	if cqe.Res < 0 {
		t.Error(syscall.Errno(-cqe.Res))
	}
	ring.CQAdvance(1)

	// remove
	sqe = ring.GetSQE()
	sqe.PrepareRemoveBuffers(4, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	if cqe.Res < 0 {
		t.Error(syscall.Errno(-cqe.Res))
	}
	ring.CQAdvance(1)
}

func TestRing_RegisterFileAllocRange(t *testing.T) {
	t.Log("kernel:", liburing.GetVersion())

	ring, ringErr := liburing.New(liburing.WithEntries(4))
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	if _, regErr := ring.RegisterFilesSparse(65535); regErr != nil {
		t.Error(regErr)
		return
	}

	defer ring.UnregisterFiles()

	if _, regErr := ring.RegisterFileAllocRange(5, 65535-5); regErr != nil {
		t.Error(regErr)
		return
	}

	var (
		sqe    *liburing.SubmissionQueueEntry
		sn     uint
		sErr   error
		cqe    *liburing.CompletionQueueEvent
		cqeErr error
	)

	sqe = ring.GetSQE()
	sqe.PrepareSocket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	ring.CQAdvance(1)

	if _, regErr := ring.RegisterFilesUpdate(1, []int{int(cqe.Res), -1, -1, -1}); regErr != nil {
		t.Error(regErr)
		return
	}

	sqe = ring.GetSQE()
	sqe.PrepareSocket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	ring.CQAdvance(1)

	if _, regErr := ring.RegisterFilesUpdate(2, []int{int(cqe.Res), -1, -1}); regErr != nil {
		t.Error(regErr)
		return
	}

	sqe = ring.GetSQE()
	sqe.PrepareSocketDirectAlloc(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	ring.CQAdvance(1)

}

func TestSubmissionQueueEntry_PrepareFilesUpdate(t *testing.T) {
	t.Log("kernel:", liburing.GetVersion())

	ring, ringErr := liburing.New(liburing.WithEntries(4))
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	if _, regErr := ring.RegisterFilesSparse(65535); regErr != nil {
		t.Error(regErr)
		return
	}

	defer ring.UnregisterFiles()

	if _, regErr := ring.RegisterFileAllocRange(5, 65535-5); regErr != nil {
		t.Error(regErr)
		return
	}

	var (
		sqe    *liburing.SubmissionQueueEntry
		sn     uint
		sErr   error
		cqe    *liburing.CompletionQueueEvent
		cqeErr error
	)

	// alloc
	sqe = ring.GetSQE()
	sqe.PrepareSocketDirect(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0, liburing.IORING_FILE_INDEX_ALLOC, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	ring.CQAdvance(1)

	// update
	sqe = ring.GetSQE()
	sock, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	fds := []int{0, sock, 0, 0, 0}
	sqe.PrepareFilesUpdate(fds, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	if cqe.Res < 0 {
		t.Error("cqe:", syscall.Errno(-cqe.Res))
	}
	ring.CQAdvance(1)

	// alloc
	sqe = ring.GetSQE()
	sqe.PrepareSocketDirect(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, 0, liburing.IORING_FILE_INDEX_ALLOC, 0)
	sn, sErr = ring.SubmitAndWait(1)
	if sErr != nil {
		t.Error(sErr)
		return
	}
	t.Log("submitted:", sn)
	cqe, cqeErr = ring.PeekCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)
	ring.CQAdvance(1)
}
