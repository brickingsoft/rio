//go:build linux

package aio

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"runtime"
	"syscall"
)

func Sendfile(fd NetFd, filepath string, cb OperationCallback) {
	if len(filepath) == 0 {
		cb(Userdata{}, errors.New("aio.Sendfile: filepath is empty"))
		return
	}

	// src
	src, openErr := syscall.Open(filepath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NDELAY, 0777)
	if openErr != nil {
		cb(Userdata{}, os.NewSyscallError("open", openErr))
		return
	}
	curpos, seekToCurrentErr := syscall.Seek(src, 0, io.SeekCurrent)
	if seekToCurrentErr != nil {
		_ = syscall.Close(src)
		cb(Userdata{}, os.NewSyscallError("seek", seekToCurrentErr))
		return
	}
	remain, seekToEndErr := syscall.Seek(src, -curpos, io.SeekEnd)
	if seekToEndErr != nil {
		_ = syscall.Close(src)
		cb(Userdata{}, os.NewSyscallError("seek", seekToEndErr))
		return
	}
	// now seek back to the original position.
	if _, seekToStart := syscall.Seek(src, curpos, io.SeekStart); seekToStart != nil {
		_ = syscall.Close(src)
		cb(Userdata{}, os.NewSyscallError("seek", seekToStart))
		return
	}

	// pipe
	pipe := make([]int, 2)
	if pipeErr := Pipe2(pipe); pipeErr != nil {
		_ = syscall.Close(src)
		cb(Userdata{}, pipeErr)
		return
	}

	// op
	op := fd.WriteOperator()
	op.callback = cb
	op.completion = completeSendfileToPipe

	op.handle = src
	op.n = uint32(remain)
	op.msg.Iovlen = uint64(pipe[0])
	op.msg.Controllen = uint64(pipe[1])

	// cylinder
	cylinder := nextIOURingCylinder()
	entry, getErr := cylinder.getSQE()
	if getErr != nil {
		_ = syscall.Close(src)
		_ = syscall.Close(pipe[0])
		_ = syscall.Close(pipe[1])
		cb(Userdata{}, getErr)
		op.reset()
		return
	}
	prepareSplice(entry, src, -1, pipe[1], -1, op.n, unix.SPLICE_F_NONBLOCK, op.ptr())
}

func completeSendfileToPipe(_ int, op *Operator, err error) {
	// src
	src := op.handle
	// pipe
	pipe := []int{
		int(op.msg.Iovlen),
		int(op.msg.Controllen),
	}
	if err != nil {
		_ = syscall.Close(src)
		_ = syscall.Close(pipe[0])
		_ = syscall.Close(pipe[1])
		op.callback(Userdata{}, err)
		return
	}
	fd := op.fd.(*netFd)
	nop := newOperator(fd)
	nop.handle = op.handle
	nop.n = op.n                           // size
	nop.msg.Iovlen = op.msg.Iovlen         // pipe 0
	nop.msg.Controllen = op.msg.Controllen // pipe 1
	nop.callback = op.callback
	nop.completion = func(result int, cop *Operator, err error) {
		completeSendfileFromPipe(result, cop, err)
		runtime.KeepAlive(nop)
	}
	// dst
	dst := nop.fd.Fd()
	// size
	size := nop.n

	// cylinder
	cylinder := nextIOURingCylinder()
	entry, getErr := cylinder.getSQE()
	if getErr != nil {
		_ = syscall.Close(src)
		_ = syscall.Close(pipe[0])
		_ = syscall.Close(pipe[1])
		nop.callback(Userdata{}, getErr)
		nop.reset()
		return
	}

	prepareSplice(entry, pipe[0], -1, dst, -1, size, unix.SPLICE_F_NONBLOCK, nop.ptr())
	runtime.KeepAlive(nop)
	return
}

func completeSendfileFromPipe(result int, op *Operator, err error) {
	// src
	src := op.handle
	_ = syscall.Close(src)
	// pipe
	pipe := []int{
		int(op.msg.Iovlen),
		int(op.msg.Controllen),
	}
	_ = syscall.Close(pipe[0])
	_ = syscall.Close(pipe[1])
	// handle
	if err != nil {
		op.callback(Userdata{}, err)
		return
	}
	op.callback(Userdata{QTY: result}, nil)
	return
}

func prepareSplice(entry *SubmissionQueueEntry, fdIn int, offIn int64, fdOut int, offOut int64, nbytes uint32, spliceFlags uint32, userdata uint64) {
	entry.prepareRW(opSplice, fdOut, 0, nbytes, uint64(offOut), userdata, 0)
	entry.Addr = uint64(offIn)
	entry.SpliceFdIn = int32(fdIn)
	entry.OpcodeFlags = spliceFlags
}
