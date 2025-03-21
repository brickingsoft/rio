//go:build linux

package aio

import "github.com/brickingsoft/rio/pkg/iouring"

func (op *Operation) Name() string {
	switch op.kind {
	case iouring.OpNop:
		return "nop"
	case iouring.OpReadv:
		return "readv"
	case iouring.OpWritev:
		return "writev"
	case iouring.OpFsync:
		return "fsync"
	case iouring.OpReadFixed:
		return "read_fixed"
	case iouring.OpWriteFixed:
		return "write_fixed"
	case iouring.OpPollAdd:
		return "poll_add"
	case iouring.OpPollRemove:
		return "poll_remove"
	case iouring.OpSyncFileRange:
		return "sync_file_range"
	case iouring.OpSendmsg:
		return "sendmsg"
	case iouring.OpRecvmsg:
		return "recvmsg"
	case iouring.OpTimeout:
		return "timeout"
	case iouring.OpTimeoutRemove:
		return "timeout_remove"
	case iouring.OpAccept:
		return "accept"
	case iouring.OpAsyncCancel:
		return "async_cancel"
	case iouring.OpLinkTimeout:
		return "link_timeout"
	case iouring.OpConnect:
		return "connect"
	case iouring.OpFallocate:
		return "fallocate"
	case iouring.OpOpenat:
		return "openat"
	case iouring.OpClose:
		return "close"
	case iouring.OpFilesUpdate:
		return "files_update"
	case iouring.OpStatx:
		return "statx"
	case iouring.OpRead:
		return "read"
	case iouring.OpWrite:
		return "write"
	case iouring.OpFadvise:
		return "fadvise"
	case iouring.OpMadvise:
		return "madvise"
	case iouring.OpSend:
		return "send"
	case iouring.OpRecv:
		return "recv"
	case iouring.OpOpenat2:
		return "openat2"
	case iouring.OpEpollCtl:
		return "epollctl"
	case iouring.OpSplice:
		return "splice"
	case iouring.OpProvideBuffers:
		return "provide_buffers"
	case iouring.OpRemoveBuffers:
		return "remove_buffers"
	case iouring.OpTee:
		return "tee"
	case iouring.OpShutdown:
		return "shutdown"
	case iouring.OpRenameat:
		return "renameat"
	case iouring.OpUnlinkat:
		return "unlinkat"
	case iouring.OpMkdirat:
		return "mkdirat"
	case iouring.OpSymlinkat:
		return "symlinkat"
	case iouring.OpLinkat:
		return "linkat"
	case iouring.OpMsgRing:
		return "msgring"
	case iouring.OpFsetxattr:
		return "fsetxattr"
	case iouring.OpSetxattr:
		return "setxattr"
	case iouring.OpFgetxattr:
		return "fgetxattr"
	case iouring.OpGetxattr:
		return "getxattr"
	case iouring.OpSocket:
		return "socket"
	case iouring.OpUringCmd:
		return "uringcmd"
	case iouring.OpSendZC:
		return "sendzc"
	case iouring.OpSendMsgZC:
		return "sendmsgzc"
	case iouring.OpReadMultishot:
		return "read_multishot"
	case iouring.OpWaitId:
		return "wait_id"
	case iouring.OpFutexWait:
		return "futex_wait"
	case iouring.OpFutexWake:
		return "futex_wake"
	case iouring.OpFutexWaitv:
		return "futex_waitv"
	case iouring.OPFixedFdInstall:
		return "fixed_fd_install"
	case iouring.OpFtuncate:
		return "ftuncate"
	case iouring.OpBind:
		return "bind"
	case iouring.OpListen:
		return "listen"
	case iouring.OpRecvZC:
		return "recvzc"
	case iouring.OpEpollWait:
		return "epollwait"
	case iouring.OpReadvFixed:
		return "readv_fixed"
	case iouring.OpWritevFixed:
		return "writev_fixed"
	default:
		return "unknown"
	}
}
