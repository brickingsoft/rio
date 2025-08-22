//go:build linux

package liburing

import (
	"math"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	IORING_OP_NOP uint8 = iota
	IORING_OP_READV
	IORING_OP_WRITEV
	IORING_OP_FSYNC
	IORING_OP_READ_FIXED
	IORING_OP_WRITE_FIXED
	IORING_OP_POLL_ADD
	IORING_OP_POLL_REMOVE
	IORING_OP_SYNC_FILE_RANGE
	IORING_OP_SENDMSG
	IORING_OP_RECVMSG
	IORING_OP_TIMEOUT
	IORING_OP_TIMEOUT_REMOVE
	IORING_OP_ACCEPT
	IORING_OP_ASYNC_CANCEL
	IORING_OP_LINK_TIMEOUT
	IORING_OP_CONNECT
	IORING_OP_FALLOCATE
	IORING_OP_OPENAT
	IORING_OP_CLOSE
	IORING_OP_FILES_UPDATE
	IORING_OP_STATX
	IORING_OP_READ
	IORING_OP_WRITE
	IORING_OP_FADVISE
	IORING_OP_MADVISE
	IORING_OP_SEND
	IORING_OP_RECV
	IORING_OP_OPENAT2
	IORING_OP_EPOLL_CTL
	IORING_OP_SPLICE
	IORING_OP_PROVIDE_BUFFERS
	IORING_OP_REMOVE_BUFFERS
	IORING_OP_TEE
	IORING_OP_SHUTDOWN
	IORING_OP_RENAMEAT
	IORING_OP_UNLINKAT
	IORING_OP_MKDIRAT
	IORING_OP_SYMLINKAT
	IORING_OP_LINKAT
	IORING_OP_MSG_RING
	IORING_OP_FSETXATTR
	IORING_OP_SETXATTR
	IORING_OP_FGETXATTR
	IORING_OP_GETXATTR
	IORING_OP_SOCKET
	IORING_OP_URING_CMD
	IORING_OP_SEND_ZC
	IORING_OP_SENDMSG_ZC
	IORING_OP_READ_MULTISHOT
	IORING_OP_WAITID
	IORING_OP_FUTEX_WAIT
	IORING_OP_FUTEX_WAKE
	IORING_OP_FUTEX_WAITV
	IORING_OP_FIXED_FD_INSTALL
	IORING_OP_FTRUNCATE
	IORING_OP_BIND
	IORING_OP_LISTEN
	IORING_OP_RECV_ZC
	IORING_OP_EPOLL_WAIT
	IORING_OP_READV_FIXED
	IORING_OP_WRITEV_FIXED

	IORING_OP_LAST = math.MaxUint8
)

const IORING_URING_CMD_FIXED uint32 = 1 << 0
const IORING_URING_CMD_MASK = IORING_URING_CMD_FIXED

const IORING_FSYNC_DATASYNC uint32 = 1 << 0

const (
	IORING_TIMEOUT_ABS uint32 = 1 << iota
	IORING_TIMEOUT_UPDATE
	IORING_TIMEOUT_BOOTTIME
	IORING_TIMEOUT_REALTIME
	IORING_LINK_TIMEOUT_UPDATE
	IORING_TIMEOUT_ETIME_SUCCESS
	IORING_TIMEOUT_MULTISHOT
	IORING_TIMEOUT_CLOCK_MASK  = IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME
	IORING_TIMEOUT_UPDATE_MASK = IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE
)

const SPLICE_F_FD_IN_FIXED uint32 = 1 << 31

const (
	IORING_POLL_ADD_MULTI uint32 = 1 << iota
	IORING_POLL_UPDATE_EVENTS
	IORING_POLL_UPDATE_USER_DATA
	IORING_POLL_ADD_LEVEL
)

const (
	IORING_ASYNC_CANCEL_ALL uint32 = 1 << iota
	IORING_ASYNC_CANCEL_FD
	IORING_ASYNC_CANCEL_ANY
	IORING_ASYNC_CANCEL_FD_FIXED
	IORING_ASYNC_CANCEL_USERDATA
	IORING_ASYNC_CANCEL_OP
)

const (
	IORING_RECVSEND_POLL_FIRST uint16 = 1 << iota
	IORING_RECV_MULTISHOT
	IORING_RECVSEND_FIXED_BUF
	IORING_SEND_ZC_REPORT_USAGE
	IORING_RECVSEND_BUNDLE
)

const IORING_NOTIF_USAGE_ZC_COPIED uint32 = 1 << 31

const (
	IORING_ACCEPT_MULTISHOT uint16 = 1 << iota
	IORING_ACCEPT_DONTWAIT
	IORING_ACCEPT_POLL_FIRST
)

const (
	IORING_MSG_DATA uint32 = iota
	IORING_MSG_SEND_FD
)

const (
	IORING_MSG_RING_CQE_SKIP uint32 = 1 << iota
	IORING_MSG_RING_FLAGS_PASS
)

const (
	IORING_FIXED_FD_NO_CLOEXEC uint32 = 1 << iota
)

const (
	IORING_NOP_INJECT_RESULT = 1 << iota
)

const IORING_FILE_INDEX_ALLOC uint32 = 4294967295

const (
	SOCKET_URING_OP_SIOCINQ = iota
	SOCKET_URING_OP_SIOCOUTQ
	SOCKET_URING_OP_GETSOCKOPT
	SOCKET_URING_OP_SETSOCKOPT
)

const (
	IOSQE_FIXED_FILE uint8 = 1 << iota
	IOSQE_IO_DRAIN
	IOSQE_IO_LINK
	IOSQE_IO_HARDLINK
	IOSQE_ASYNC
	IOSQE_BUFFER_SELECT
	IOSQE_CQE_SKIP_SUCCESS
)

type union64_2 struct {
	n1 uint32
	n2 uint32
}

func mergeUint32ToUint64(n1 uint32, n2 uint32) uint64 {
	n := union64_2{n1, n2}
	np := unsafe.Pointer(&n)
	return uint64(*(*uint64)(np))
}

var (
	submissionQueueEntrySize = unsafe.Sizeof(SubmissionQueueEntry{})
)

type SubmissionQueueEntry struct {
	OpCode      uint8
	Flags       uint8
	IoPrio      uint16
	Fd          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	OpcodeFlags uint32
	UserData    uint64
	BufIG       uint16
	Personality uint16
	SpliceFdIn  int32
	Addr3       uint64
	_pad2       [1]uint64
}

func (entry *SubmissionQueueEntry) SetData(data unsafe.Pointer) {
	entry.UserData = uint64(uintptr(data))
}

func (entry *SubmissionQueueEntry) SetData64(data uint64) {
	entry.UserData = data
}

func (entry *SubmissionQueueEntry) SetFlags(flags uint8) {
	entry.Flags |= flags
}

func (entry *SubmissionQueueEntry) SetIoPrio(flags uint16) {
	entry.IoPrio |= flags
}

func (entry *SubmissionQueueEntry) SetBufferIndex(bid uint16) {
	entry.BufIG = bid
}

func (entry *SubmissionQueueEntry) SetBufferGroup(bgid uint16) {
	entry.BufIG = bgid
	entry.Flags |= IOSQE_BUFFER_SELECT
}

func (entry *SubmissionQueueEntry) SetPersonality(personality uint16) {
	entry.Personality = personality
}

// [Nop] ***************************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareNop() {
	entry.prepareRW(IORING_OP_NOP, -1, 0, 0, 0)
}

// [Net] ***************************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareSetsockoptInt(fd int, level int, optName int, optValue *int) {
	entry.prepareRW(IORING_OP_URING_CMD, fd, 0, 0, 0)
	entry.Addr3 = uint64(uintptr(unsafe.Pointer(optValue)))          // optval
	entry.Addr = mergeUint32ToUint64(uint32(level), uint32(optName)) // level, optname
	entry.SpliceFdIn = int32(unsafe.Sizeof(optValue))                // optlen
	entry.Off = SOCKET_URING_OP_SETSOCKOPT                           // cmd_op
}

func (entry *SubmissionQueueEntry) PrepareSetsockopt(fd int, level int, optName int, optValue unsafe.Pointer, optValueLen int32) {
	entry.prepareRW(IORING_OP_URING_CMD, fd, 0, 0, 0)
	entry.Addr3 = uint64(uintptr(optValue))                          // optval
	entry.Addr = mergeUint32ToUint64(uint32(level), uint32(optName)) // level, optname
	entry.SpliceFdIn = optValueLen                                   // optlen
	entry.Off = SOCKET_URING_OP_SETSOCKOPT                           // cmd_op
}

func (entry *SubmissionQueueEntry) PrepareGetsockoptInt(fd int, level int, optName int, optValue *int) {
	optValueLen := unsafe.Sizeof(optValue)
	entry.prepareRW(IORING_OP_URING_CMD, fd, 0, 0, 0)
	entry.Addr3 = uint64(uintptr(unsafe.Pointer(optValue)))               // optval
	entry.Addr = mergeUint32ToUint64(uint32(level), uint32(optName))      // level, optname
	entry.SpliceFdIn = int32(unsafe.Sizeof(unsafe.Pointer(&optValueLen))) // optlen
	entry.Off = SOCKET_URING_OP_GETSOCKOPT                                // cmd_op
}

func (entry *SubmissionQueueEntry) PrepareGetsockopt(fd int, level int, optName int, optValue unsafe.Pointer, optValueLen *int32) {
	entry.prepareRW(IORING_OP_URING_CMD, fd, 0, 0, 0)
	entry.Addr3 = uint64(uintptr(optValue))                          // optval
	entry.Addr = mergeUint32ToUint64(uint32(level), uint32(optName)) // level, optname
	entry.SpliceFdIn = int32(unsafe.Sizeof(&optValueLen))            // optlen
	entry.Off = SOCKET_URING_OP_GETSOCKOPT                           // cmd_op
}

func (entry *SubmissionQueueEntry) PrepareBind(fd int, addr *syscall.RawSockaddrAny, addrLen uint64) {
	entry.prepareRW(IORING_OP_BIND, fd, uintptr(unsafe.Pointer(addr)), 0, addrLen)
}

func (entry *SubmissionQueueEntry) PrepareListen(fd int, backlog uint32) {
	entry.prepareRW(IORING_OP_LISTEN, fd, 0, backlog, 0)
}

func (entry *SubmissionQueueEntry) PrepareAccept(fd int, addr *syscall.RawSockaddrAny, addrLen uint64, flags int) {
	entry.prepareRW(IORING_OP_ACCEPT, fd, uintptr(unsafe.Pointer(addr)), 0, addrLen)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareAcceptDirect(fd int, addr *syscall.RawSockaddrAny, addrLen uint64, flags int, fileIndex uint32) {
	entry.PrepareAccept(fd, addr, addrLen, flags)
	if fileIndex == IORING_FILE_INDEX_ALLOC {
		fileIndex--
	}
	entry.setTargetFixedFile(fileIndex)
}

func (entry *SubmissionQueueEntry) PrepareAcceptDirectAlloc(fd int, addr *syscall.RawSockaddrAny, addrLen uint64, flags int) {
	entry.PrepareAccept(fd, addr, addrLen, flags)
	entry.setTargetFixedFile(IORING_FILE_INDEX_ALLOC - 1)
}

func (entry *SubmissionQueueEntry) PrepareAcceptMultishot(fd int, addr *syscall.RawSockaddrAny, addrLen uint64, flags int) {
	entry.PrepareAccept(fd, addr, addrLen, flags)
	entry.IoPrio |= IORING_ACCEPT_MULTISHOT
}

func (entry *SubmissionQueueEntry) PrepareAcceptMultishotDirect(fd int, addr *syscall.RawSockaddrAny, addrLen uint64, flags int) {
	entry.PrepareAcceptMultishot(fd, addr, addrLen, flags)
	entry.setTargetFixedFile(IORING_FILE_INDEX_ALLOC - 1)
}

func (entry *SubmissionQueueEntry) PrepareConnect(fd int, addr *syscall.RawSockaddrAny, addrLen uint64) {
	entry.prepareRW(IORING_OP_CONNECT, fd, uintptr(unsafe.Pointer(addr)), 0, addrLen)
}

func (entry *SubmissionQueueEntry) PrepareRecv(fd int, buf uintptr, length uint32, flags int) {
	entry.prepareRW(IORING_OP_RECV, fd, buf, length, 0)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareRecvMultishot(fd int, addr uintptr, length uint32, flags int) {
	entry.PrepareRecv(fd, addr, length, flags)
	entry.IoPrio |= IORING_RECV_MULTISHOT
}

func (entry *SubmissionQueueEntry) PrepareRecvMsg(fd int, msg *syscall.Msghdr, flags uint32) {
	entry.prepareRW(IORING_OP_RECVMSG, fd, uintptr(unsafe.Pointer(msg)), 1, 0)
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareRecvMsgMultishot(fd int, msg *syscall.Msghdr, flags uint32) {
	entry.PrepareRecvMsg(fd, msg, flags)
	entry.IoPrio |= IORING_RECV_MULTISHOT
}

func (entry *SubmissionQueueEntry) PrepareSend(fd int, addr uintptr, length uint32, flags int) {
	entry.prepareRW(IORING_OP_SEND, fd, addr, length, 0)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareSendBundle(fd int, length uint32, flags int) {
	entry.PrepareSend(fd, 0, length, flags)
	entry.IoPrio |= IORING_RECVSEND_BUNDLE
}

func (entry *SubmissionQueueEntry) PrepareSendZC(sockFd int, addr uintptr, length uint32, flags int, zcFlags uint32) {
	entry.prepareRW(IORING_OP_SEND_ZC, sockFd, addr, length, 0)
	entry.OpcodeFlags = uint32(flags)
	entry.IoPrio = uint16(zcFlags)
}

func (entry *SubmissionQueueEntry) PrepareSendZCFixed(sockFd int, addr uintptr, length uint32, flags int, zcFlags, bufIndex uint32) {
	entry.PrepareSendZC(sockFd, addr, length, flags, zcFlags)
	entry.IoPrio |= IORING_RECVSEND_FIXED_BUF
	entry.BufIG = uint16(bufIndex)
}

func (entry *SubmissionQueueEntry) PrepareSendMsg(fd int, msg *syscall.Msghdr, flags int) {
	entry.prepareRW(IORING_OP_SENDMSG, fd, uintptr(unsafe.Pointer(msg)), 1, 0)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareSendmsgZC(fd int, msg *syscall.Msghdr, flags int) {
	entry.PrepareSendMsg(fd, msg, flags)
	entry.OpCode = IORING_OP_SENDMSG_ZC
}

func (entry *SubmissionQueueEntry) PrepareShutdown(fd, how int) {
	entry.prepareRW(IORING_OP_SHUTDOWN, fd, 0, uint32(how), 0)
}

func (entry *SubmissionQueueEntry) PrepareSocket(domain, socketType, protocol int, flags uint32) {
	entry.prepareRW(IORING_OP_SOCKET, domain, 0, uint32(protocol), uint64(socketType))
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareSocketDirect(domain, socketType, protocol int, fileIndex, flags uint32) {
	entry.PrepareSocket(domain, socketType, protocol, flags)
	if fileIndex == IORING_FILE_INDEX_ALLOC {
		fileIndex--
	}
	entry.setTargetFixedFile(fileIndex)
}

func (entry *SubmissionQueueEntry) PrepareSocketDirectAlloc(domain, socketType, protocol int, flags uint32) {
	entry.PrepareSocket(domain, socketType, protocol, flags)
	entry.setTargetFixedFile(IORING_FILE_INDEX_ALLOC - 1)
}

func (entry *SubmissionQueueEntry) PrepareSplice(fdIn int, offIn int64, fdOut int, offOut int64, nbytes, spliceFlags uint32) {
	entry.prepareRW(IORING_OP_SPLICE, fdOut, 0, nbytes, uint64(offOut))
	entry.Addr = uint64(offIn)
	entry.SpliceFdIn = int32(fdIn)
	entry.OpcodeFlags = spliceFlags
}

func (entry *SubmissionQueueEntry) PrepareTee(fdIn, fdOut int, nbytes, spliceFlags uint32) {
	entry.prepareRW(IORING_OP_TEE, fdOut, 0, nbytes, 0)
	entry.Addr = 0
	entry.SpliceFdIn = int32(fdIn)
	entry.OpcodeFlags = spliceFlags
}

func RecvmsgValidate(buf unsafe.Pointer, bufLen int, msgh *syscall.Msghdr) *RecvmsgOut {
	header := uintptr(msgh.Controllen) + uintptr(msgh.Namelen) + unsafe.Sizeof(RecvmsgOut{})
	if bufLen < 0 || uintptr(bufLen) < header {
		return nil
	}
	return (*RecvmsgOut)(buf)
}

type RecvmsgOut struct {
	Namelen    uint32
	ControlLen uint32
	PayloadLen uint32
	Flags      uint32
}

func (o *RecvmsgOut) CmsgNexthdr(msgh *syscall.Msghdr, cmsg *syscall.Cmsghdr) *syscall.Cmsghdr {
	if cmsg.Len < syscall.SizeofCmsghdr {
		return nil
	}
	end := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(o.CmsgFirsthdr(msgh))) + uintptr(o.ControlLen)))
	cmsg = (*syscall.Cmsghdr)(unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(cmsgAlign(cmsg.Len))))
	if uintptr(unsafe.Pointer(cmsg))+unsafe.Sizeof(*cmsg) > uintptr(unsafe.Pointer(end)) {
		return nil
	}
	if uintptr(unsafe.Pointer(cmsg))+uintptr(cmsgAlign(cmsg.Len)) > uintptr(unsafe.Pointer(end)) {
		return nil
	}

	return cmsg
}

func (o *RecvmsgOut) Name() unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(o)) + unsafe.Sizeof(*o))
}

func (o *RecvmsgOut) CmsgFirsthdr(msgh *syscall.Msghdr) *syscall.Cmsghdr {
	if o.ControlLen < syscall.SizeofCmsghdr {
		return nil
	}

	return (*syscall.Cmsghdr)(unsafe.Pointer(uintptr(o.Name()) + uintptr(msgh.Namelen)))
}

func (o *RecvmsgOut) Payload(msgh *syscall.Msghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(o)) +
		unsafe.Sizeof(*o) +
		uintptr(msgh.Namelen) +
		uintptr(msgh.Controllen))
}

func (o *RecvmsgOut) PayloadLength(bufLen int, msgh *syscall.Msghdr) uint32 {
	payloadStart := uintptr(o.Payload(msgh))
	payloadEnd := uintptr(unsafe.Pointer(o)) + uintptr(bufLen)

	return uint32(payloadEnd - payloadStart)
}

func cmsgAlign(length uint64) uint64 {
	return (length + uint64(unsafe.Sizeof(uintptr(0))) - 1) & ^(uint64(unsafe.Sizeof(uintptr(0))) - 1)
}

// [cancelOperation] ************************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareCancel(userdata uintptr, flags uint32) {
	entry.PrepareCancel64(uint64(userdata), flags)
}

func (entry *SubmissionQueueEntry) PrepareCancel64(userdata uint64, flags uint32) {
	entry.prepareRW(IORING_OP_ASYNC_CANCEL, -1, 0, 0, 0)
	entry.Addr = userdata
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareCancelFd(fd int, flags uint32) {
	entry.prepareRW(IORING_OP_ASYNC_CANCEL, fd, 0, 0, 0)
	entry.OpcodeFlags = flags | IORING_ASYNC_CANCEL_FD
}

func (entry *SubmissionQueueEntry) PrepareCancelFdFixed(fileIndex uint32, flags uint32) {
	entry.prepareRW(IORING_OP_ASYNC_CANCEL, int(fileIndex), 0, 0, 0)
	entry.OpcodeFlags = flags | IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_FD_FIXED
}

func (entry *SubmissionQueueEntry) PrepareCancelALL() {
	entry.prepareRW(IORING_OP_ASYNC_CANCEL, 0, 0, 0, 0)
	entry.OpcodeFlags = IORING_ASYNC_CANCEL_ALL
}

// [Timeout] ***********************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareLinkTimeout(spec *syscall.Timespec, flags uint32) {
	entry.prepareRW(IORING_OP_LINK_TIMEOUT, -1, uintptr(unsafe.Pointer(spec)), 1, 0)
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareLinkTimeoutUpdate(spec *syscall.Timespec, userdata unsafe.Pointer) {
	entry.PrepareTimeoutUpdate(spec, userdata, IORING_LINK_TIMEOUT_UPDATE)
}

func (entry *SubmissionQueueEntry) PrepareTimeout(spec *syscall.Timespec, count, flags uint32) {
	entry.prepareRW(IORING_OP_TIMEOUT, -1, uintptr(unsafe.Pointer(spec)), 1, uint64(count))
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareTimeoutRemove(userdata unsafe.Pointer, flags uint32) {
	entry.prepareRW(IORING_OP_TIMEOUT_REMOVE, -1, uintptr(0), 0, 0)
	entry.Addr = uint64(uintptr(userdata))
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareTimeoutUpdate(spec *syscall.Timespec, userdata unsafe.Pointer, flags uint32) {
	entry.prepareRW(IORING_OP_TIMEOUT_REMOVE, -1, uintptr(0), 0, uint64(uintptr(unsafe.Pointer(spec))))
	entry.Addr = uint64(uintptr(userdata))
	entry.OpcodeFlags = flags | IORING_TIMEOUT_UPDATE
}

// [Close] *************************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareClose(fd int) {
	entry.prepareRW(IORING_OP_CLOSE, fd, 0, 0, 0)
}

func (entry *SubmissionQueueEntry) PrepareCloseDirect(fileIndex uint32) {
	entry.PrepareClose(0)
	entry.setTargetFixedFile(fileIndex)
}

// [MsgRing] ***********************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareMsgRing(fd int, length uint32, userdata unsafe.Pointer, flags uint32) {
	entry.prepareRW(IORING_OP_MSG_RING, fd, 0, length, uint64(uintptr(userdata)))
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareMsgRingCQEFlags(fd int, length uint32, userdata unsafe.Pointer, flags, cqeFlags uint32) {
	entry.prepareRW(IORING_OP_MSG_RING, fd, 0, length, uint64(uintptr(userdata)))
	entry.OpcodeFlags = IORING_MSG_RING_FLAGS_PASS | flags
	entry.SpliceFdIn = int32(cqeFlags)
}

func (entry *SubmissionQueueEntry) PrepareMsgRingFd(fd int, sourceFd int, targetFd int, userdata unsafe.Pointer, flags uint32) {
	entry.prepareRW(IORING_OP_MSG_RING, fd, uintptr(IORING_MSG_SEND_FD), 0, uint64(uintptr(userdata)))
	entry.Addr3 = uint64(sourceFd)
	if uint32(targetFd) == IORING_FILE_INDEX_ALLOC {
		targetFd--
	}
	entry.setTargetFixedFile(uint32(targetFd))
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareMsgRingFdAlloc(fd int, sourceFd int, userdata unsafe.Pointer, flags uint32) {
	entry.PrepareMsgRingFd(fd, sourceFd, int(IORING_FILE_INDEX_ALLOC), userdata, flags)
}

// [File] **************************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareOpenat(dfd int, path []byte, flags int, mode uint32) {
	entry.prepareRW(IORING_OP_OPENAT, dfd, uintptr(unsafe.Pointer(&path)), mode, 0)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareOpenat2(dfd int, path []byte, openHow *unix.OpenHow) {
	entry.prepareRW(IORING_OP_OPENAT, dfd, uintptr(unsafe.Pointer(&path)),
		uint32(unsafe.Sizeof(*openHow)), uint64(uintptr(unsafe.Pointer(openHow))))
}

func (entry *SubmissionQueueEntry) PrepareOpenat2Direct(dfd int, path []byte, openHow *unix.OpenHow, fileIndex uint32) {
	entry.PrepareOpenat2(dfd, path, openHow)
	if fileIndex == IORING_FILE_INDEX_ALLOC {
		fileIndex--
	}
	entry.setTargetFixedFile(fileIndex)
}

func (entry *SubmissionQueueEntry) PrepareOpenatDirect(dfd int, path []byte, flags int, mode uint32, fileIndex uint32) {
	entry.PrepareOpenat(dfd, path, flags, mode)
	if fileIndex == IORING_FILE_INDEX_ALLOC {
		fileIndex--
	}
	entry.setTargetFixedFile(fileIndex)
}

func (entry *SubmissionQueueEntry) PrepareRead(fd int, buf uintptr, nbytes uint32, offset uint64) {
	entry.prepareRW(IORING_OP_READ, fd, buf, nbytes, offset)
}

func (entry *SubmissionQueueEntry) PrepareReadFixed(fd int, buf uintptr, nbytes uint32, offset uint64, bufIndex int) {
	entry.prepareRW(IORING_OP_READ_FIXED, fd, buf, nbytes, offset)
	entry.BufIG = uint16(bufIndex)
}

func (entry *SubmissionQueueEntry) PrepareReadv(fd int, iovecs uintptr, nrVecs uint32, offset uint64) {
	entry.prepareRW(IORING_OP_READV, fd, iovecs, nrVecs, offset)
}

func (entry *SubmissionQueueEntry) PrepareReadv2(fd int, iovecs uintptr, nrVecs uint32, offset uint64, flags int) {
	entry.PrepareReadv(fd, iovecs, nrVecs, offset)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareWrite(fd int, buf uintptr, nbytes uint32, offset uint64) {
	entry.prepareRW(IORING_OP_WRITE, fd, buf, nbytes, offset)
}

func (entry *SubmissionQueueEntry) PrepareWriteFixed(
	fd int, vectors uintptr, length uint32, offset uint64, index int) {
	entry.prepareRW(IORING_OP_WRITE_FIXED, fd, vectors, length, offset)
	entry.BufIG = uint16(index)
}

func (entry *SubmissionQueueEntry) PrepareWritev(
	fd int, iovecs uintptr, nrVecs uint32, offset uint64) {
	entry.prepareRW(IORING_OP_WRITEV, fd, iovecs, nrVecs, offset)
}

func (entry *SubmissionQueueEntry) PrepareWritev2(
	fd int, iovecs uintptr, nrVecs uint32, offset uint64, flags int) {
	entry.PrepareWritev(fd, iovecs, nrVecs, offset)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareRename(oldPath, netPath []byte) {
	entry.PrepareRenameat(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, netPath, 0)
}

func (entry *SubmissionQueueEntry) PrepareRenameat(oldFd int, oldPath []byte, newFd int, newPath []byte, flags uint32) {
	entry.prepareRW(IORING_OP_RENAMEAT, oldFd,
		uintptr(unsafe.Pointer(&oldPath)), uint32(newFd), uint64(uintptr(unsafe.Pointer(&newPath))))
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareLink(oldPath, newPath []byte, flags int) {
	entry.PrepareLinkat(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, flags)
}

func (entry *SubmissionQueueEntry) PrepareLinkat(oldFd int, oldPath []byte, newFd int, newPath []byte, flags int) {
	entry.prepareRW(IORING_OP_LINKAT, oldFd, uintptr(unsafe.Pointer(&oldPath)),
		uint32(newFd), uint64(uintptr(unsafe.Pointer(&newPath))))
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareUnlink(path uintptr, flags int) {
	entry.PrepareUnlinkat(unix.AT_FDCWD, path, flags)
}

func (entry *SubmissionQueueEntry) PrepareUnlinkat(dfd int, path uintptr, flags int) {
	entry.prepareRW(IORING_OP_UNLINKAT, dfd, path, 0, 0)
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareMkdir(path []byte, mode uint32) {
	entry.PrepareMkdirat(unix.AT_FDCWD, path, mode)
}

func (entry *SubmissionQueueEntry) PrepareMkdirat(dfd int, path []byte, mode uint32) {
	entry.prepareRW(IORING_OP_MKDIRAT, dfd, uintptr(unsafe.Pointer(&path)), mode, 0)
}

func (entry *SubmissionQueueEntry) PrepareFilesUpdate(fds []int, offset int) {
	entry.prepareRW(IORING_OP_FILES_UPDATE, -1, uintptr(unsafe.Pointer(&fds[0])), uint32(len(fds)), uint64(offset))
}

func (entry *SubmissionQueueEntry) PrepareStatx(dfd int, path []byte, flags int, mask uint32, statx *unix.Statx_t) {
	entry.prepareRW(IORING_OP_STATX, dfd, uintptr(unsafe.Pointer(&path)), mask, uint64(uintptr(unsafe.Pointer(statx))))
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareSymlink(target, linkpath []byte) {
	entry.PrepareSymlinkat(target, unix.AT_FDCWD, linkpath)
}

func (entry *SubmissionQueueEntry) PrepareSymlinkat(target []byte, newdirfd int, linkpath []byte) {
	entry.prepareRW(IORING_OP_SYMLINKAT, newdirfd, uintptr(unsafe.Pointer(&target)), 0, uint64(uintptr(unsafe.Pointer(&linkpath))))
}

func (entry *SubmissionQueueEntry) PrepareSyncFileRange(fd int, length uint32, offset uint64, flags int) {
	entry.prepareRW(IORING_OP_SYNC_FILE_RANGE, fd, 0, length, offset)
	entry.OpcodeFlags = uint32(flags)
}

// [F] *****************************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareFixedFdInstall(fd int, flags uint32) {
	entry.prepareRW(IORING_OP_FIXED_FD_INSTALL, fd, 0, 0, 0)
	entry.Flags = IOSQE_FIXED_FILE
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareFadvise(fd int, offset uint64, length int, advise uint32) {
	entry.prepareRW(IORING_OP_FADVISE, fd, 0, uint32(length), offset)
	entry.OpcodeFlags = advise
}

func (entry *SubmissionQueueEntry) PrepareFallocate(fd int, mode int, offset, length uint64) {
	entry.prepareRW(IORING_OP_FALLOCATE, fd, 0, uint32(mode), offset)
	entry.Addr = length
}

func (entry *SubmissionQueueEntry) PrepareFgetxattr(fd int, name, value []byte) {
	entry.prepareRW(IORING_OP_FGETXATTR, fd, uintptr(unsafe.Pointer(&name)),
		uint32(len(value)), uint64(uintptr(unsafe.Pointer(&value))))
}

func (entry *SubmissionQueueEntry) PrepareSetxattr(name, value, path []byte, flags int, length uint32) {
	entry.prepareRW(IORING_OP_SETXATTR, 0, uintptr(unsafe.Pointer(&name)), length, uint64(uintptr(unsafe.Pointer(&value))))
	entry.Addr3 = uint64(uintptr(unsafe.Pointer(&path)))
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareFsetxattr(fd int, name, value []byte, flags int) {
	entry.prepareRW(
		IORING_OP_FSETXATTR, fd, uintptr(unsafe.Pointer(&name)), uint32(len(value)), uint64(uintptr(unsafe.Pointer(&value))))
	entry.OpcodeFlags = uint32(flags)
}

func (entry *SubmissionQueueEntry) PrepareFsync(fd int, flags uint32) {
	entry.prepareRW(IORING_OP_FSYNC, fd, 0, 0, 0)
	entry.OpcodeFlags = flags
}

func (entry *SubmissionQueueEntry) PrepareGetxattr(name, value, path []byte) {
	entry.prepareRW(IORING_OP_GETXATTR, 0, uintptr(unsafe.Pointer(&name)),
		uint32(len(value)), uint64(uintptr(unsafe.Pointer(&value))))
	entry.Addr3 = uint64(uintptr(unsafe.Pointer(&path)))
	entry.OpcodeFlags = 0
}

func (entry *SubmissionQueueEntry) PrepareMadvise(addr uintptr, length uint, advice int) {
	entry.prepareRW(IORING_OP_MADVISE, -1, addr, uint32(length), 0)
	entry.OpcodeFlags = uint32(advice)
}

// [Kernel Buffer] *****************************************************************************************************

func (entry *SubmissionQueueEntry) PrepareProvideBuffers(addr uintptr, addrLength uint32, nr, bgid, bid int) {
	entry.prepareRW(IORING_OP_PROVIDE_BUFFERS, nr, addr, addrLength, uint64(bid))
	entry.BufIG = uint16(bgid)
}

func (entry *SubmissionQueueEntry) PrepareRemoveBuffers(nr int, bgid int) {
	entry.prepareRW(IORING_OP_REMOVE_BUFFERS, nr, 0, 0, 0)
	entry.BufIG = uint16(bgid)
}

// [Poll] **************************************************************************************************************

func (entry *SubmissionQueueEntry) PreparePollAdd(fd int, pollMask uint32) {
	entry.prepareRW(IORING_OP_POLL_ADD, fd, 0, 0, 0)
	entry.OpcodeFlags = pollMask
}

func (entry *SubmissionQueueEntry) PreparePollMultishot(fd int, pollMask uint32) {
	entry.PreparePollAdd(fd, pollMask)
	entry.Len = IORING_POLL_ADD_MULTI
}

func (entry *SubmissionQueueEntry) PreparePollRemove(userData uint64) {
	entry.prepareRW(IORING_OP_POLL_REMOVE, -1, 0, 0, 0)
	entry.Addr = userData
}

func (entry *SubmissionQueueEntry) PreparePollUpdate(oldUserData, newUserData uint64, pollMask, flags uint32) {
	entry.prepareRW(IORING_OP_POLL_REMOVE, -1, 0, flags, newUserData)
	entry.Addr = oldUserData
	entry.OpcodeFlags = pollMask
}

func (entry *SubmissionQueueEntry) PrepareEPollWait(fd int, events []syscall.EpollEvent, flags uint32) {
	addr := unsafe.Pointer(&events[0])
	length := uint32(len(events))
	entry.prepareRW(IORING_OP_EPOLL_WAIT, fd, uintptr(addr), length, 0)
	entry.OpcodeFlags = flags
}

// [private] ***********************************************************************************************************

func (entry *SubmissionQueueEntry) prepareRW(opcode uint8, fd int, addr uintptr, length uint32, offset uint64) {
	entry.OpCode = opcode
	entry.Flags = 0
	entry.IoPrio = 0
	entry.Fd = int32(fd)
	entry.Off = offset
	entry.Addr = uint64(addr)
	entry.Len = length
	entry.UserData = 0
	entry.BufIG = 0
	entry.Personality = 0
	entry.SpliceFdIn = 0
}

func (entry *SubmissionQueueEntry) setTargetFixedFile(fileIndex uint32) {
	entry.SpliceFdIn = int32(fileIndex + 1)
}

const (
	IORING_SQ_NEED_WAKEUP uint32 = 1 << iota
	IORING_SQ_CQ_OVERFLOW
	IORING_SQ_TASKRUN
)

type SQRingOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	userAddr    uint64
}

type SubmissionQueue struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	flags       *uint32
	dropped     *uint32
	array       *uint32
	sqes        *SubmissionQueueEntry
	ringSize    uint
	ringPtr     unsafe.Pointer
	sqeHead     uint32
	sqeTail     uint32
	pad         [2]uint32
}
