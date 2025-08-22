//go:build linux

package aio

import (
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
	"golang.org/x/sys/unix"
)

const (
	maxSendfileSize   = 4 << 20
	maxMMapSize       = int(^uint(0) >> 1)
	sendFileChunkSize = 1<<31 - 1
)

var (
	pagesize = os.Getpagesize()
)

func (fd *Fd) Sendfile(r io.Reader) (written int64, err error) {
	var remain int64 = 0
	lr, ok := r.(*io.LimitedReader)
	if ok {
		remain, r = lr.N, lr.R
		if remain <= 0 {
			return 0, nil
		}
	}

	file, isFile := r.(*os.File)
	if !isFile {
		return 0, errors.New("cannot send file to non-file destination")
	}
	if remain == 0 {
		info, infoErr := file.Stat()
		if infoErr != nil {
			err = infoErr
			return
		}
		remain = info.Size()
	}

	offset := int64(0)

	if remain < sendFileChunkSize {
		if !fd.Installed() {
			if err = fd.Install(); err != nil {
				return
			}
		}
		if sc, scErr := file.SyscallConn(); scErr == nil {
			var (
				wn   int
				wErr error
			)
			err = sc.Read(func(ffd uintptr) (done bool) {
				wn, wErr = unix.Sendfile(fd.regular, int(ffd), nil, int(remain))
				return true
			})
			if err == nil {
				err = wErr
			}
			written = int64(wn)
			if err != nil && !errors.Is(err, syscall.EAGAIN) {
				err = os.NewSyscallError("sendfile", err)
				return
			}
			if written == remain {
				return
			}
			remain -= written
			offset = written
		}
	}

	srcFd := int(file.Fd())

	if remain > int64(maxMMapSize) {
		written, err = fd.sendfileChunk(srcFd, offset, remain)
		if written > 0 {
			_, _ = file.Seek(written, io.SeekCurrent)
		}
		if lr != nil {
			lr.N -= written
		}
		return
	}
	// mmap
	b, mmapErr := sys.Mmap(srcFd, offset, int(remain), syscall.PROT_READ, syscall.MAP_SHARED)
	if mmapErr != nil {
		err = os.NewSyscallError("mmap", mmapErr)
		return
	}
	defer func(b []byte) {
		_ = sys.Munmap(b)
	}(b)
	// madvise
	if advErr := sys.Madvise(b, syscall.MADV_WILLNEED|syscall.MADV_SEQUENTIAL); advErr != nil {
		err = os.NewSyscallError("madvise", mmapErr)
		return
	}

	chunk, chunkErr := syscall.GetsockoptInt(fd.regular, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if chunkErr != nil {
		chunk = maxSendfileSize
	}

	for err == nil && remain > 0 {
		if int64(chunk) > remain {
			chunk = int(remain)
		}
		n, wErr := fd.Write(b[written : written+int64(chunk)])
		if n > 0 {
			written += int64(n)
			remain -= int64(n)
		}
		err = wErr
	}

	if written > 0 {
		_, _ = file.Seek(written, io.SeekCurrent)
	}

	if lr != nil {
		lr.N -= written
	}

	return
}

func (fd *Fd) sendfileChunk(src int, offset int64, remain int64) (written int64, err error) {
	chunk := int64(pagesize)
	for err == nil && remain > 0 {
		if chunk > remain {
			chunk = remain
		}
		offset += written
		b, mmapErr := sys.Mmap(src, offset, int(chunk), syscall.PROT_READ, syscall.MAP_SHARED)
		if mmapErr != nil {
			err = os.NewSyscallError("mmap", mmapErr)
			break
		}
		_ = sys.Madvise(b, syscall.MADV_WILLNEED|syscall.MADV_SEQUENTIAL)
		n, wErr := fd.Write(b)
		if n > 0 {
			written += int64(n)
			remain -= int64(n)
		}
		err = wErr

		if munmapErr := sys.Munmap(b); munmapErr != nil {
			err = os.NewSyscallError("munmap", munmapErr)
			break
		}
	}
	return
}
