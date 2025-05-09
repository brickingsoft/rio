//go:build linux

package aio

import (
	"errors"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
	"golang.org/x/sys/unix"
	"runtime"
	"strconv"
	"syscall"
)

func (fd *Fd) Splice(src *Fd, remain int64) (n int64, err error) {
	pipe, pipeErr := sys.AcquirePipe()
	if pipeErr != nil {
		return 0, pipeErr
	}
	defer sys.ReleasePipe(pipe)

	srcFd := src.direct
	srcFixed := srcFd != -1
	if !srcFixed {
		srcFd = src.regular
	}
	dst := fd.FileDescriptor()

	for err == nil && remain > 0 {
		chunk := int64(sys.MaxSpliceSize)
		if chunk > remain {
			chunk = remain
		}
		// drain
	DRAIN:
		drainParams := SpliceParams{
			FdIn:       srcFd,
			FdInFixed:  srcFixed,
			OffIn:      -1,
			FdOut:      pipe.WriterFd(),
			FdOutFixed: false,
			OffOut:     -1,
			NBytes:     uint32(chunk),
			Flags:      unix.SPLICE_F_NONBLOCK,
		}
		opDrain := AcquireOperation()
		opDrain.PrepareSplice(&drainParams)
		drained, _, drainedErr := poller.SubmitAndWait(opDrain)
		ReleaseOperation(opDrain)
		if drainedErr != nil || drained == 0 {
			if errors.Is(drainedErr, syscall.EAGAIN) {
				pn, pErr := src.Poll(unix.POLLIN | unix.POLLERR | unix.POLLHUP)
				if pErr != nil {
					err = pErr
					break
				}
				if pn&unix.POLLIN != 0 {
					goto DRAIN
				}
				err = errors.New("polled " + strconv.Itoa(pn))
				break
			}
			err = drainedErr
			break
		}
		pipe.DrainN(drained)
		// pump
	PUMP:
		pumpParams := SpliceParams{
			FdIn:       pipe.ReaderFd(),
			FdInFixed:  false,
			OffIn:      -1,
			FdOut:      dst,
			FdOutFixed: true,
			OffOut:     -1,
			NBytes:     uint32(drained),
			Flags:      unix.SPLICE_F_NONBLOCK,
		}
		opPump := AcquireOperation()
		opPump.PrepareSplice(&pumpParams)
		pumped, _, pumpedErr := poller.SubmitAndWait(opPump)
		ReleaseOperation(opPump)
		if pumped > 0 {
			n += int64(pumped)
			remain -= int64(pumped)
			pipe.PumpN(pumped)
		}
		if pumpedErr != nil {
			if errors.Is(pumpedErr, syscall.EAGAIN) {
				pn, pErr := fd.Poll(unix.POLLOUT | unix.POLLERR | unix.POLLHUP)
				if pErr != nil {
					err = pErr
					break
				}
				if pn&unix.POLLOUT != 0 {
					goto PUMP
				}
				err = errors.New("polled " + strconv.Itoa(pn))
				break
			}
			err = pumpedErr
		}
	}
	runtime.KeepAlive(src)
	return
}
