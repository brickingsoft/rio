//go:build windows

package aio

import (
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"runtime"
	"unsafe"
)

func Sendfile(fd NetFd, filepath string, cb OperationCallback) {
	if len(filepath) == 0 {
		cb(Userdata{}, errors.New("aio.Sendfile: filepath is empty"))
		return
	}
	src, openErr := windows.Open(filepath, windows.O_RDONLY|windows.O_NONBLOCK|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0777)
	if openErr != nil {
		cb(Userdata{}, os.NewSyscallError("open", openErr))
		return
	}

	curpos, seekToCurrentErr := windows.Seek(src, 0, io.SeekCurrent)
	if seekToCurrentErr != nil {
		_ = windows.Close(src)
		cb(Userdata{}, os.NewSyscallError("seek", seekToCurrentErr))
		return
	}
	// find the number of bytes offset from curpos until the end of the file.
	remain, seekToEndErr := windows.Seek(src, -curpos, io.SeekEnd)
	if seekToEndErr != nil {
		_ = windows.Close(src)
		cb(Userdata{}, os.NewSyscallError("seek", seekToEndErr))
		return
	}
	// now seek back to the original position.
	if _, seekToStart := windows.Seek(src, curpos, io.SeekStart); seekToStart != nil {
		_ = windows.Close(src)
		cb(Userdata{}, os.NewSyscallError("seek", seekToStart))
		return
	}

	sendfile(fd, src, curpos, remain, 0, cb)
}

const maxChunkSizePerCall = int64(0x7fffffff - 1)

func sendfile(fd NetFd, file windows.Handle, curpos int64, remain int64, written int, cb OperationCallback) {
	op := fd.WriteOperator()
	op.handle = int(file)
	op.completion = completeSendfile
	op.callback = cb

	chunkSize := maxChunkSizePerCall
	if chunkSize > remain {
		chunkSize = remain
	}

	op.msg.BufferCount = uint32(remain)
	op.msg.Control.Len = uint32(curpos)
	op.msg.WSAMsg.Flags = uint32(written)

	op.n = uint32(chunkSize)
	op.overlapped.Offset = uint32(curpos)
	op.overlapped.OffsetHigh = uint32(curpos >> 32)

	wsaOverlapped := (*windows.Overlapped)(unsafe.Pointer(op))

	dst := windows.Handle(fd.Fd())

	// timeout
	op.tryPrepareTimeout()

	// syscall.TransmitFile(o.fd.Sysfd, o.handle, o.qty, 0, &o.o, nil, syscall.TF_WRITE_BEHIND)
	err := windows.TransmitFile(dst, file, op.n, 0, wsaOverlapped, nil, windows.TF_WRITE_BEHIND)
	if err != nil && !errors.Is(windows.ERROR_IO_PENDING, err) {
		_ = windows.Close(file)
		// handle err
		cb(Userdata{}, os.NewSyscallError("transmit_file", err))
		// clean op
		op.clean()
	}
	runtime.KeepAlive(op)
}

func completeSendfile(result int, op *Operator, err error) {
	src := windows.Handle(op.handle)

	if err != nil {
		_ = windows.Close(src)
		err = os.NewSyscallError("transmit_file", err)
		op.callback(Userdata{}, err)
		return
	}

	curpos := int64(op.msg.Control.Len)
	remain := int64(op.msg.BufferCount)
	written := int(op.msg.WSAMsg.Flags) + result

	curpos += int64(result)

	if _, seekToStart := windows.Seek(src, curpos, io.SeekStart); seekToStart != nil {
		_ = windows.Close(src)
		op.callback(Userdata{QTY: written}, os.NewSyscallError("seek", seekToStart))
		return
	}

	remain -= int64(result)
	if remain > 0 {
		dstFd := op.fd.(*netFd)
		cb := op.callback
		nop := newOperator(dstFd)
		nop.timeout = dstFd.wop.timeout
		dstFd.wop = nop
		sendfile(dstFd, src, curpos, remain, written, cb)
		return
	}

	_ = windows.Close(src)
	op.callback(Userdata{QTY: written}, nil)
	return
}
