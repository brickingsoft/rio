package aio

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

func (vortex *Vortex) Splice(ctx context.Context, dst int, src int, remain int64) (n int, err error) {

	return
}

const (
	MaxSpliceSize = 1 << 20
)

var (
	splicePipePool = sync.Pool{New: func() interface{} {
		p := NewSplicePipe()
		if p == nil {
			return nil
		}
		runtime.SetFinalizer(p, func(p *SplicePipe) {
			_ = p.Close()
		})
		return p
	}}
)

func AcquireSplicePipe() (*SplicePipe, error) {
	v := splicePipePool.Get()
	if v == nil {
		return nil, syscall.EINVAL
	}
	return v.(*SplicePipe), nil
}

func ReleaseSplicePipe(pipe *SplicePipe) {
	if pipe.data != 0 {
		runtime.SetFinalizer(pipe, nil)
		_ = pipe.Close()
		return
	}
	splicePipePool.Put(pipe)
}

func NewSplicePipe() *SplicePipe {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		return nil
	}

	// Splice will loop writing maxSpliceSize bytes from the source to the pipe,
	// and then write those bytes from the pipe to the destination.
	// Set the pipe buffer size to maxSpliceSize to optimize that.
	// Ignore errors here, as a smaller buffer size will work,
	// although it will require more system calls.
	Fcntl(fds[0], syscall.F_SETPIPE_SZ, MaxSpliceSize)

	return &SplicePipe{splicePipeFields: splicePipeFields{rfd: fds[0], wfd: fds[1]}}
}

type splicePipeFields struct {
	rfd  int
	wfd  int
	data int
}

type SplicePipe struct {
	splicePipeFields

	// We want to use a finalizer, so ensure that the size is
	// large enough to not use the tiny allocator.
	_ [24 - unsafe.Sizeof(splicePipeFields{})%24]byte
}

func (pipe *SplicePipe) ReaderFd() int {
	return pipe.rfd
}

func (pipe *SplicePipe) WriterFd() int {
	return pipe.wfd
}

func (pipe *SplicePipe) DrainN(n int) {
	pipe.data += n
}

func (pipe *SplicePipe) PumpN(n int) {
	pipe.data -= n
}

func (pipe *SplicePipe) Close() (err error) {
	err = syscall.Close(pipe.rfd)
	if werr := syscall.Close(pipe.wfd); werr != nil {
		if err == nil {
			err = werr
		} else {
			err = errors.Join(err, werr)
		}
	}
	return
}

func (pipe *SplicePipe) Splice(ctx context.Context, vortex *Vortex, src int, dst int, remain int64) (n int, err error) {
	written := int64(0)
	for err == nil && remain > 0 {
		chunk := int64(MaxSpliceSize)
		if chunk > remain {
			chunk = remain
		}
		// todo move into vortex.Splice
		// drain
		drained := 0
		var drainedErr error

		if drainedErr != nil || drained == 0 {
			break
		}
		pipe.DrainN(drained)
		// pump

		pumped := 0

		var pumpedErr error
		if pumped > 0 {
			written += int64(n)
			remain -= int64(n)
			pipe.PumpN(pumped)
		}
		err = pumpedErr
	}
	return
}
