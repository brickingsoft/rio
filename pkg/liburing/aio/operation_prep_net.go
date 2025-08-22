//go:build linux

package aio

import (
	"syscall"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func (op *Operation) PrepareConnect(conn *Conn, addr *syscall.RawSockaddrAny, addrLen int) {
	op.code = liburing.IORING_OP_CONNECT
	op.fd = conn.direct
	op.addr = unsafe.Pointer(addr)
	op.addrLen = uint32(addrLen)
	return
}

func (op *Operation) packingConnect(sqe *liburing.SubmissionQueueEntry) (err error) {
	addrPtr := (*syscall.RawSockaddrAny)(op.addr)
	addrLenPtr := uint64(op.addrLen)
	sqe.PrepareConnect(op.fd, addrPtr, addrLenPtr)
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareListen(ln *Listener, backlog int) {
	op.code = liburing.IORING_OP_LISTEN
	op.fd = ln.direct
	op.addrLen = uint32(backlog)
	return
}

func (op *Operation) packingListen(sqe *liburing.SubmissionQueueEntry) (err error) {
	sqe.PrepareListen(op.fd, op.addrLen)
	sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareBind(nfd *NetFd, addr *syscall.RawSockaddrAny, addrLen int) {
	op.code = liburing.IORING_OP_BIND
	op.fd = nfd.direct
	op.addr = unsafe.Pointer(addr)
	op.addrLen = uint32(addrLen)
	return
}

func (op *Operation) packingBind(sqe *liburing.SubmissionQueueEntry) (err error) {
	addrPtr := (*syscall.RawSockaddrAny)(op.addr)
	addrLenPtr := uint64(op.addrLen)
	sqe.PrepareBind(op.fd, addrPtr, addrLenPtr)
	sqe.SetFlags(liburing.IOSQE_FIXED_FILE)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareAccept(ln *Listener, addr *syscall.RawSockaddrAny, addrLen *int) {
	op.code = liburing.IORING_OP_ACCEPT
	op.fd = ln.direct
	op.addr = unsafe.Pointer(addr)
	op.addr2 = unsafe.Pointer(addrLen)
	return
}

func (op *Operation) PrepareAcceptMultishot(ln *Listener, addr *syscall.RawSockaddrAny, addrLen *int) {
	op.kind = op_kind_multishot
	op.code = liburing.IORING_OP_ACCEPT
	op.fd = ln.direct
	op.addr = unsafe.Pointer(addr)
	op.addr2 = unsafe.Pointer(addrLen)
	return
}

func (op *Operation) packingAccept(sqe *liburing.SubmissionQueueEntry) (err error) {
	addrPtr := (*syscall.RawSockaddrAny)(op.addr)
	addrLenPtr := uint64(uintptr(op.addr2))
	if op.kind == op_kind_multishot {
		sqe.PrepareAcceptMultishotDirect(op.fd, addrPtr, addrLenPtr, syscall.SOCK_NONBLOCK)
	} else {
		sqe.PrepareAcceptDirectAlloc(op.fd, addrPtr, addrLenPtr, syscall.SOCK_NONBLOCK)
	}
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareReceive(conn *Conn, b []byte) {
	op.code = liburing.IORING_OP_RECV
	op.fd = conn.direct
	op.addr = unsafe.Pointer(&b[0])
	op.addrLen = uint32(len(b))
	return
}

func (op *Operation) PrepareReceiveMultishot(conn *Conn, r *MultishotReceiveAdaptor) {
	op.kind = op_kind_multishot
	op.code = liburing.IORING_OP_RECV
	op.fd = conn.direct
	op.addr = unsafe.Pointer(r)
	return
}

func (op *Operation) packingReceive(sqe *liburing.SubmissionQueueEntry) (err error) {
	if op.kind == op_kind_multishot {
		r := (*MultishotReceiveAdaptor)(op.addr)
		op.channel.adaptor = r
		sqe.PrepareRecvMultishot(op.fd, 0, 0, 0)
		sqe.SetIoPrio(liburing.IORING_RECVSEND_BUNDLE)
		sqe.SetBufferGroup(r.br.bgid)
	} else {
		b := uintptr(op.addr)
		bLen := op.addrLen
		sqe.PrepareRecv(op.fd, b, bLen, 0)
	}
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareSend(conn *Conn, b []byte) {
	op.code = liburing.IORING_OP_SEND
	op.fd = conn.direct
	op.addr = unsafe.Pointer(&b[0])
	op.addrLen = uint32(len(b))
	return
}

func (op *Operation) PrepareSendBundle(conn *Conn, br *BufferAndRing) {
	op.code = liburing.IORING_OP_SEND
	op.cmd = op_cmd_send_bundle
	op.fd = conn.direct
	op.addr = unsafe.Pointer(br)
	return
}

func (op *Operation) packingSend(sqe *liburing.SubmissionQueueEntry) (err error) {
	opFlags := 0
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		opFlags = syscall.MSG_WAITALL
		flags |= liburing.IOSQE_IO_LINK
	}
	if op.cmd == op_cmd_send_bundle {
		br := (*BufferAndRing)(op.addr)
		sqe.PrepareSendBundle(op.fd, 0, opFlags)
		sqe.SetBufferGroup(br.bgid)
	} else {
		b := uintptr(op.addr)
		bLen := op.addrLen
		sqe.PrepareSend(op.fd, b, bLen, opFlags)
	}
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareSendZC(conn *Conn, b []byte) {
	op.code = liburing.IORING_OP_SEND_ZC
	op.fd = conn.direct
	op.addr = unsafe.Pointer(&b[0])
	op.addrLen = uint32(len(b))
	return
}

func (op *Operation) packingSendZC(sqe *liburing.SubmissionQueueEntry) (err error) {
	b := uintptr(op.addr)
	bLen := op.addrLen
	opFlags := 0
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		opFlags = syscall.MSG_WAITALL
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.PrepareSendZC(op.fd, b, bLen, opFlags, 0)
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareReceiveMsg(conn *Conn, msg *syscall.Msghdr) {
	op.code = liburing.IORING_OP_RECVMSG
	op.fd = conn.direct
	op.addr = unsafe.Pointer(msg)
	return
}

func (op *Operation) PrepareReceiveMsgMultishot(conn *Conn, r *MultishotMsgReceiveAdaptor) {
	op.kind = op_kind_multishot
	op.code = liburing.IORING_OP_RECVMSG
	op.fd = conn.direct
	op.addr = unsafe.Pointer(r)
	return
}

func (op *Operation) packingReceiveMsg(sqe *liburing.SubmissionQueueEntry) (err error) {
	if op.kind == op_kind_multishot {
		r := (*MultishotMsgReceiveAdaptor)(op.addr)
		op.channel.adaptor = r
		sqe.PrepareRecvMsgMultishot(op.fd, r.msg, 0)
		sqe.SetBufferGroup(r.br.bgid)
	} else {
		msg := (*syscall.Msghdr)(op.addr)
		sqe.PrepareRecvMsg(op.fd, msg, 0)
	}
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareSendMsg(conn *Conn, msg *syscall.Msghdr) {
	op.code = liburing.IORING_OP_SENDMSG
	op.fd = conn.direct
	op.addr = unsafe.Pointer(msg)
	return
}

func (op *Operation) packingSendMsg(sqe *liburing.SubmissionQueueEntry) (err error) {
	msg := (*syscall.Msghdr)(op.addr)
	opFlags := 0
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		opFlags = syscall.MSG_WAITALL
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.PrepareSendMsg(op.fd, msg, opFlags)
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}

func (op *Operation) PrepareSendMsgZC(conn *Conn, msg *syscall.Msghdr) {
	op.code = liburing.IORING_OP_SENDMSG_ZC
	op.fd = conn.direct
	op.addr = unsafe.Pointer(msg)
	return
}

func (op *Operation) packingSendMsgZC(sqe *liburing.SubmissionQueueEntry) (err error) {
	msg := (*syscall.Msghdr)(op.addr)
	opFlags := 0
	flags := liburing.IOSQE_FIXED_FILE
	if op.timeout != nil {
		opFlags = syscall.MSG_WAITALL
		flags |= liburing.IOSQE_IO_LINK
	}
	sqe.PrepareSendmsgZC(op.fd, msg, opFlags)
	sqe.SetFlags(flags)
	sqe.SetData(unsafe.Pointer(op))
	return
}
