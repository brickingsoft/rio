//go:build linux

package liburing_test

import (
	"bytes"
	"errors"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func TestRing_SetupBufRing2(t *testing.T) {
	ring, ringErr := liburing.New()
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	wg := new(sync.WaitGroup)
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func(ring *liburing.Ring, wg *sync.WaitGroup, i int) {
			defer wg.Done()
			var (
				brn       = 4
				bgid      = i
				byteSize  = 4096
				byteCount = brn
				mask      = liburing.BufferRingMask(uint32(brn))
			)

			br, brErr := ring.SetupBufRing(uint32(brn), uint16(bgid), 0)
			if brErr != nil {
				t.Error(brErr)
				return
			}

			src := make([]byte, byteSize*byteCount)

			for j := 0; j < brn; j++ {
				addr := &src[byteSize*j : byteSize*(j+1)][0]
				br.BufRingAdd(unsafe.Pointer(addr), uint32(byteSize), uint16(j), uint16(mask), uint16(j))
			}
			br.BufRingAdvance(uint16(brn))
		}(ring, wg, i)
	}

	wg.Wait()
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func(ring *liburing.Ring, wg *sync.WaitGroup, i int) {
			defer wg.Done()
			n, err := ring.UnregisterBufferRing(uint16(i))
			if err != nil {
				t.Error(err)
				return
			}
			t.Log("unregister", n, i)
		}(ring, wg, i)
	}
	wg.Wait()
	t.Log("done")

}

func TestRing_SetupBufRing(t *testing.T) {
	ring, ringErr := liburing.New()
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	t.Log(ring.RegisterFilesSparse(65535))
	defer ring.UnregisterFiles()

	var (
		brn       = 4
		bgid      = 0
		byteSize  = 4096
		byteCount = brn
		mask      = liburing.BufferRingMask(uint32(brn))
	)

	br, brErr := ring.SetupBufRing(uint32(brn), uint16(bgid), 0)
	if brErr != nil {
		t.Error(brErr)
		return
	}

	src := make([]byte, byteSize*byteCount)

	for i := 0; i < brn; i++ {
		addr := &src[byteSize*i : byteSize*(i+1)][0]
		br.BufRingAdd(unsafe.Pointer(addr), uint32(byteSize), uint16(i), uint16(mask), uint16(i))
	}
	br.BufRingAdvance(uint16(brn))

	defer ring.UnregisterBufferRing(uint16(bgid))

	var pipe0 [2]int
	if pipeErr := syscall.Pipe2(pipe0[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); pipeErr != nil {
		t.Error(pipeErr)
		return
	}
	var (
		pipe0r = pipe0[0]
		pipe0w = pipe0[1]
	)
	defer syscall.Close(pipe0r)
	defer syscall.Close(pipe0w)

	p0wbs := make([][]byte, byteCount)
	for i := range p0wbs {
		p0wbs[i] = make([]byte, byteSize)
		//rand.Read(p0wbs[i])
		copy(p0wbs[i], []byte("p0:hello world:"+strconv.Itoa(i)))
	}

	var pipe1 [2]int
	if pipeErr := syscall.Pipe2(pipe1[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); pipeErr != nil {
		t.Error(pipeErr)
		return
	}
	var (
		pipe1r = pipe1[0]
		pipe1w = pipe1[1]
	)
	defer syscall.Close(pipe1r)
	defer syscall.Close(pipe1w)

	p1wbs := make([][]byte, byteCount)
	for i := range p1wbs {
		p1wbs[i] = make([]byte, byteSize)
		//rand.Read(p1wbs[i])
		copy(p1wbs[i], []byte("p1:hello world:"+strconv.Itoa(i)))
	}

	var (
		sqe        *liburing.SubmissionQueueEntry
		submiteErr error
		cqe        *liburing.CompletionQueueEvent
		cqeErr     error
	)

	// write p0 and p1
	for i := 0; i < brn; i++ {
		p0wb := p0wbs[i]
		addr0 := &p0wb[0]
		sqe = ring.GetSQE()
		sqe.PrepareWrite(pipe0w, uintptr(unsafe.Pointer(addr0)), uint32(byteSize), 0)
		t.Log("p0 write:", string(p0wb))

		p1wb := p1wbs[i]
		addr1 := &p1wb[0]
		sqe = ring.GetSQE()
		sqe.PrepareWrite(pipe1w, uintptr(unsafe.Pointer(addr1)), uint32(byteSize), 0)
		t.Log("p1 write:", string(p1wb))
	}

	_, submiteErr = ring.SubmitAndWait(uint32(brn * 2))
	if submiteErr != nil {
		t.Error(submiteErr)
		return
	}
	ring.CQAdvance(uint32(brn * 2))

	// read p0 2 and not adv br
	for i := 0; i < 2; i++ {
		sqe = ring.GetSQE()
		sqe.PrepareRead(pipe0r, 0, 0, 0)
		sqe.SetBufferGroup(uint16(bgid))
	}
	_, submiteErr = ring.SubmitAndWait(2)
	if submiteErr != nil {
		t.Error(submiteErr)
		return
	}
	for i := 0; i < 2; i++ {
		cqe, cqeErr = ring.PeekCQE()
		if cqeErr != nil {
			t.Error(cqeErr)
			return
		}
		if cqe.Res < 0 {
			t.Error(syscall.Errno(-cqe.Res))
			return
		}
		rn := int(cqe.Res)
		bid := int(cqe.Flags >> liburing.IORING_CQE_BUFFER_SHIFT)

		rb := make([]byte, rn)
		copy(rb, src[bid*byteSize:bid*byteSize+rn])

		if !bytes.Equal(rb, p0wbs[i]) {
			t.Error("p0 read not matched", bid, cqe.Flags, string(p0wbs[i][0:rn]), string(rb))
			return
		}
		//ring.BufRingCQAdvance(br, 1)
		ring.CQAdvance(1)
		t.Log("p0 read matched", bid, cqe.Flags, string(p0wbs[i][0:rn]), string(rb))
	}

	// read p1 full

	p1t := brn
	p1r := 0
READ_P1:
	for i := 0; i < p1t; i++ {
		sqe = ring.GetSQE()
		sqe.PrepareRead(pipe1r, 0, 0, 0)
		sqe.SetBufferGroup(uint16(bgid))
	}
	_, submiteErr = ring.SubmitAndWait(uint32(p1t))
	if submiteErr != nil {
		t.Error(submiteErr)
		return
	}
	for i := brn - p1t; i < brn; i++ {
		cqe, cqeErr = ring.PeekCQE()
		if cqeErr != nil {
			t.Error(cqeErr)
			return
		}
		if cqe.Res < 0 {
			cqeErr = syscall.Errno(-cqe.Res)
			if errors.Is(cqeErr, syscall.ENOBUFS) {
				t.Log("p1 read failed for no space, try again after badv", cqe.Flags, cqeErr, cqe.Flags&liburing.IORING_CQE_F_BUF_MORE)
				p1t--
				br.BufRingAdvance(1)
				ring.CQAdvance(1)
				continue
			} else {
				t.Error(cqeErr)
				return
			}
		}
		rn := int(cqe.Res)
		bid := int(cqe.Flags >> liburing.IORING_CQE_BUFFER_SHIFT)

		rb := make([]byte, rn)
		copy(rb, src[bid*byteSize:bid*byteSize+rn])

		if !bytes.Equal(rb, p1wbs[i]) {
			t.Error("p1 read not matched", cqe.Flags, bid, string(p1wbs[i][0:rn]), string(rb))
			return
		}
		br.BufRingAdvance(1)
		ring.CQAdvance(1)
		t.Log("p1 read matched", bid, cqe.Flags, string(p1wbs[i][0:rn]), string(rb))
		p1r++
	}
	if p1r != brn {
		goto READ_P1
	}

	// read p0 remains
	for i := 0; i < 2; i++ {
		sqe = ring.GetSQE()
		sqe.PrepareRead(pipe0r, 0, 0, 0)
		sqe.SetBufferGroup(uint16(bgid))
	}
	_, submiteErr = ring.SubmitAndWait(2)
	if submiteErr != nil {
		t.Error(submiteErr)
		return
	}
	for i := 2; i < 4; i++ {
		cqe, cqeErr = ring.PeekCQE()
		if cqeErr != nil {
			t.Error(cqeErr)
			return
		}
		if cqe.Res < 0 {
			t.Error(syscall.Errno(-cqe.Res))
			return
		}
		rn := int(cqe.Res)
		bid := int(cqe.Flags >> liburing.IORING_CQE_BUFFER_SHIFT)

		rb := make([]byte, rn)
		copy(rb, src[bid*byteSize:bid*byteSize+rn])

		if !bytes.Equal(rb, p0wbs[i]) {
			t.Error("p0 read not matched", bid, cqe.Flags, string(p0wbs[i][0:rn]), string(rb))
			return
		}
		br.BufRingAdvance(1)
		ring.CQAdvance(1)
		t.Log("p0 read matched", bid, cqe.Flags, string(p0wbs[i][0:rn]), string(rb))
	}

}
