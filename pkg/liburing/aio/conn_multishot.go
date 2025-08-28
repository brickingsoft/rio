//go:build linux

package aio

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/brickingsoft/bytebuffers"
	"github.com/brickingsoft/rio/pkg/liburing"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

type MultishotReceiveAdaptor struct {
	br *BufferAndRing
}

func (adaptor *MultishotReceiveAdaptor) Handle(n int, flags uint32, err error) (bool, int, uint32, unsafe.Pointer, error) {
	if err != nil || flags&liburing.IORING_CQE_F_BUFFER == 0 {
		return true, n, flags, nil, err
	}

	var (
		br  = adaptor.br
		bid = uint16(flags >> liburing.IORING_CQE_BUFFER_SHIFT)
	)

	if n == 0 {
		br.Advance(bid)
		return true, n, flags, nil, nil
	}

	buf := bytebuffers.AcquirePageSize()
	br.WriteTo(bid, n, buf)
	return true, n, flags, unsafe.Pointer(&buf), nil
}

func (adaptor *MultishotReceiveAdaptor) HandleCompletionEvent(event CompletionEvent, b []byte, overflow io.Writer) (n int, interrupted bool, err error) {
	// handle error
	if event.Err != nil {
		err = event.Err
		return
	}

	// handle attachment
	if attachment := event.Attachment; attachment != nil {
		buf := *(*bytebuffers.Buffer)(attachment)
		n, _ = buf.Read(b)
		if buf.Len() > 0 {
			_, _ = buf.WriteTo(overflow)
		}
		event.Attachment = nil
		bytebuffers.ReleasePageSize(buf)
	}

	// handle IORING_CQE_F_MORE is 0
	if event.Flags&liburing.IORING_CQE_F_MORE == 0 {
		if event.N == 0 {
			err = io.EOF
			return
		}
		interrupted = true
	}
	return
}

const (
	recvMultishotReady = iota
	recvMultishotProcessing
	recvMultishotCanceled
)

func newMultishotReceiver(conn *Conn) (receiver *MultishotReceiver, err error) {
	// acquire buffer and ring
	br, brErr := poller.AcquireBufferAndRing()
	if brErr != nil {
		err = brErr
		return
	}
	// adaptor
	adaptor := &MultishotReceiveAdaptor{br: br}
	// op
	op := AcquireOperation()
	op.PrepareReceiveMultishot(conn, adaptor)
	// receiver
	receiver = &MultishotReceiver{
		status:        recvMultishotReady,
		locker:        sync.Mutex{},
		operationLock: sync.Mutex{},
		buffer:        bytebuffers.AcquirePageSize(),
		adaptor:       adaptor,
		operation:     op,
		future:        nil,
		err:           nil,
	}
	return
}

type MultishotReceiver struct {
	status        int
	locker        sync.Mutex
	operationLock sync.Mutex
	adaptor       *MultishotReceiveAdaptor
	buffer        bytebuffers.Buffer
	operation     *Operation
	future        Future
	err           error
}

func (r *MultishotReceiver) Recv(b []byte, deadline time.Time) (n int, err error) {
	bLen := len(b)
	if bLen == 0 {
		return
	}

	r.locker.Lock()
	// handle canceled
	if r.status == recvMultishotCanceled {
		if r.buffer == nil {
			err = r.err
			r.locker.Unlock()
			return
		}
		n, _ = r.buffer.Read(b)
		if n == 0 {
			r.releaseBuffer()
			err = r.err
		}
		r.locker.Unlock()
		return
	}

	// read buffer
	if r.buffer.Len() > 0 {
		n, _ = r.buffer.Read(b)
		if n == bLen {
			r.locker.Unlock()
			return
		}
	}

	// start
	if r.status == recvMultishotReady {
		r.submit()
		r.status = recvMultishotProcessing
	}

	// await
	hungry := n == 0 // when n > 0, then try await
	events := r.future.AwaitBatch(hungry, deadline)
	// handle events
	eventsLen := len(events)
	if eventsLen == 0 { // nothing received
		r.locker.Unlock()
		return
	}

	// note: when event contains err, means it is the last in events, so break loop is ok
	for i := 0; i < eventsLen; i++ {
		event := events[i]
		nn, interrupted, handleErr := r.adaptor.HandleCompletionEvent(event, b[n:], r.buffer)
		n += nn
		if handleErr != nil {
			if errors.Is(handleErr, syscall.ENOBUFS) { // set ready to resubmit next receive time
				r.status = recvMultishotReady
				break
			}

			r.status = recvMultishotCanceled // set done when receive failed
			r.err = handleErr

			if IsTimeout(handleErr) { // timeout is not iouring err, means op is alive, then cancel it
				if r.cancel() {
					for { // await cancel
						_, _, _, err = r.future.Await()
						if IsCanceled(err) { // op canceled
							err = nil
							break
						}
					}
				}
			}

			r.releaseRuntime() // release runtime

			if n == 0 {
				r.releaseBuffer()
				err = handleErr
			}
			break
		}
		if interrupted { // set ready to resubmit next read time
			r.status = recvMultishotReady
			break
		}
	}
	r.locker.Unlock()
	return
}

func (r *MultishotReceiver) submit() {
	r.future = poller.Submit(r.operation)
}

func (r *MultishotReceiver) cancel() bool {
	r.operationLock.Lock()
	if op := r.operation; op != nil {
		ok := poller.Cancel(r.operation) == nil
		r.operationLock.Unlock()
		return ok
	}
	r.operationLock.Unlock()
	return false
}

func (r *MultishotReceiver) releaseRuntime() {
	// release op
	if op := r.operation; op != nil {
		r.operation = nil
		r.future = nil
		ReleaseOperation(op)
	}
	// release br
	if adaptor := r.adaptor; adaptor != nil {
		br := adaptor.br
		adaptor.br = nil
		r.adaptor = nil
		poller.ReleaseBufferAndRing(br)
	}
}

func (r *MultishotReceiver) releaseBuffer() {
	if buffer := r.buffer; buffer != nil {
		r.buffer = nil
		bytebuffers.ReleasePageSize(buffer)
	}
}

func (r *MultishotReceiver) Close() (err error) {
	if r.locker.TryLock() { // locked means no reader lock the mr
		switch r.status {
		case recvMultishotReady: // un submitted, then mark canceled.
			r.releaseRuntime()
			r.releaseBuffer()

			r.status = recvMultishotCanceled
			r.err = ErrCanceled
			break
		case recvMultishotProcessing: // cancel and handle events
			if r.cancel() {
				for {
					_, _, _, err = r.future.Await()
					if IsCanceled(err) { // op canceled
						err = nil
						break
					}
				}
			}
			r.releaseRuntime()
			r.releaseBuffer()
			r.status = recvMultishotCanceled
			r.err = ErrCanceled
			break
		case recvMultishotCanceled: // canceled, then pass
			break
		default:
			r.locker.Unlock()
			panic("unreachable multishot receiver status")
			return
		}
		r.locker.Unlock()
		return
	}
	// unlocked means reading, then cancel it
	r.cancel()
	return
}

type Message struct {
	B     bytebuffers.Buffer
	OOB   bytebuffers.Buffer
	Addr  syscall.Sockaddr
	Flags int
	Err   error
}

func (msg *Message) Read(fd *NetFd, b []byte, oob []byte) (n int, oobn int, flags int, addr net.Addr, err error) {
	if msg.Err != nil {
		err = msg.Err
		return
	}
	bLen := len(b)
	if bLen > 0 && msg.B != nil {
		if bLen < msg.B.Len() {
			err = io.ErrShortBuffer
			return
		}
		n, _ = msg.B.Read(b)
	}
	oobLen := len(oob)
	if oobLen > 0 && msg.OOB != nil {
		if oobLen < msg.OOB.Len() {
			err = io.ErrShortBuffer
			return
		}
		oobLen, _ = msg.OOB.Read(oob)
	}
	flags = msg.Flags
	if msg.Addr != nil {
		addr = sys.SockaddrToAddr(fd.net, msg.Addr)
	}
	return
}

var (
	messages = sync.Pool{}
	msghdrs  sync.Pool
)

func acquireMessage() *Message {
	v := messages.Get()
	if v == nil {
		return &Message{}
	}
	return v.(*Message)
}

func releaseMessage(m *Message) {
	if m == nil {
		return
	}
	if b := m.B; b != nil {
		m.B = nil
		bytebuffers.ReleasePageSize(b)
	}
	if b := m.OOB; b != nil {
		m.OOB = nil
		bytebuffers.Release(b)
	}
	m.Addr = nil
	m.Flags = 0
	m.Err = nil
	messages.Put(m)
}

func acquireMsg(b []byte, oob []byte, addr *syscall.RawSockaddrAny, addrLen int, flags int32) *syscall.Msghdr {
	var msg *syscall.Msghdr
	v := msghdrs.Get()
	if v == nil {
		msg = &syscall.Msghdr{}
	} else {
		msg = v.(*syscall.Msghdr)
	}
	bLen := len(b)
	if bLen > 0 {
		msg.Iov = &syscall.Iovec{
			Base: &b[0],
			Len:  uint64(bLen),
		}
		msg.Iovlen = 1
	}
	oobLen := len(oob)
	if oobLen > 0 {
		msg.Control = &oob[0]
		msg.SetControllen(oobLen)
	}
	if addr != nil {
		msg.Name = (*byte)(unsafe.Pointer(addr))
		msg.Namelen = uint32(addrLen)
	}
	msg.Flags = flags
	return msg
}

func releaseMsg(msg *syscall.Msghdr) {
	msg.Name = nil
	msg.Namelen = 0
	msg.Iov = nil
	msg.Iovlen = 0
	msg.Control = nil
	msg.Controllen = 0
	msg.Flags = 0
	msghdrs.Put(msg)
	return
}

type MultishotMsgReceiveAdaptor struct {
	br  *BufferAndRing
	msg *syscall.Msghdr
}

func (adaptor *MultishotMsgReceiveAdaptor) Handle(n int, flags uint32, err error) (bool, int, uint32, unsafe.Pointer, error) {
	if err != nil || flags&liburing.IORING_CQE_F_BUFFER == 0 {
		return true, n, flags, nil, err
	}

	var (
		br      = adaptor.br
		bid     = uint16(flags >> liburing.IORING_CQE_BUFFER_SHIFT)
		msg     = acquireMsg(nil, nil, nil, 0, 0)
		message = acquireMessage()
	)
	// buffer
	b := br.BufferOfBid(bid)
	// msg
	msg.Namelen = adaptor.msg.Namelen
	msg.Controllen = adaptor.msg.Controllen
	out := liburing.RecvmsgValidate(unsafe.Pointer(&b[0]), n, msg)

	// name
	if name := out.Name(); name != nil {
		addr := (*syscall.RawSockaddrAny)(name)
		sa, saErr := sys.RawSockaddrAnyToSockaddr(addr)
		if saErr != nil {
			message.Err = saErr
			// release bid
			br.Advance(bid)
			// release msg
			releaseMsg(msg)
			return true, n, flags, unsafe.Pointer(message), nil
		}
		message.Addr = sa
		addr = nil
	}

	// flags
	message.Flags = int(out.Flags)

	// control
	if cmsg := out.CmsgFirsthdr(msg); cmsg != nil {
		message.OOB = bytebuffers.Acquire()
		_, _ = message.OOB.Write(b[:out.ControlLen])
		// release bid
		br.Advance(bid)
		// release msg
		releaseMsg(msg)
		return true, n, flags, unsafe.Pointer(message), nil
	}

	// payload
	n = int(out.PayloadLength(n, msg))
	if n > 0 {
		payload := unsafe.Slice((*byte)(out.Payload(msg)), n)
		message.B = bytebuffers.AcquirePageSize()
		_, _ = message.B.Write(payload)
	}

	// release bid
	br.Advance(bid)
	// release msg
	releaseMsg(msg)
	return true, n, flags, unsafe.Pointer(message), nil
}

func (adaptor *MultishotMsgReceiveAdaptor) HandleCompletionEvent(event CompletionEvent) (msg *Message, interrupted bool, err error) {
	// handle error
	if event.Err != nil {
		err = event.Err
		return
	}

	// handle attachment
	if attachment := event.Attachment; attachment != nil {
		msg = (*Message)(attachment)
	}

	// handle IORING_CQE_F_MORE is 0
	if event.Flags&liburing.IORING_CQE_F_MORE == 0 {
		if event.N == 0 {
			err = io.EOF
			return
		}
		interrupted = true
	}
	return
}

func (adaptor *MultishotMsgReceiveAdaptor) HandleMsg(msg *Message, fd *NetFd, b []byte, oob []byte) (n int, oobn int, flags int, addr net.Addr, err error) {
	n, oobn, flags, addr, err = msg.Read(fd, b, oob)
	releaseMessage(msg)
	return
}

func newMultishotMsgReceiver(conn *Conn) (receiver *MultishotMsgReceiver, err error) {
	// acquire buffer and ring
	br, brErr := poller.AcquireBufferAndRing()
	if brErr != nil {
		err = brErr
		return
	}
	oobLen := syscall.CmsgLen(syscall.SizeofSockaddrAny) + syscall.SizeofCmsghdr
	// adaptor
	adaptor := &MultishotMsgReceiveAdaptor{br: br, msg: &syscall.Msghdr{Namelen: syscall.SizeofSockaddrAny, Controllen: uint64(oobLen)}}
	// op
	op := AcquireOperation()
	op.PrepareReceiveMsgMultishot(conn, adaptor)
	// receiver
	receiver = &MultishotMsgReceiver{
		status:        recvMultishotReady,
		locker:        sync.Mutex{},
		operationLock: sync.Mutex{},
		adaptor:       adaptor,
		buffer:        make([]*Message, 0, 8),
		operation:     op,
		future:        nil,
		err:           nil,
	}
	return
}

type MultishotMsgReceiver struct {
	status        int
	locker        sync.Mutex
	adaptor       *MultishotMsgReceiveAdaptor
	buffer        []*Message
	operation     *Operation
	operationLock sync.Mutex
	future        Future
	err           error
}

func (r *MultishotMsgReceiver) ReceiveMsg(fd *NetFd, b []byte, oob []byte, deadline time.Time) (n int, oobn int, flags int, addr net.Addr, err error) {
	bLen := len(b)
	oobLen := len(oob)
	if bLen == 0 && oobLen == 0 {
		return
	}

	r.locker.Lock()
	// handle canceled
	if r.status == recvMultishotCanceled {
		if len(r.buffer) > 0 {
			msg := r.buffer[0]
			r.buffer = r.buffer[1:]
			n, oobn, flags, addr, err = r.adaptor.HandleMsg(msg, fd, b, oob)
			r.locker.Unlock()
			return
		}
		err = r.err
		r.locker.Unlock()
		return
	}

	// read buffer
	if len(r.buffer) > 0 {
		msg := r.buffer[0]
		r.buffer = r.buffer[1:]
		n, oobn, flags, addr, err = r.adaptor.HandleMsg(msg, fd, b, oob)
		r.locker.Unlock()
		return
	}

	// start
	if r.status == recvMultishotReady {
		r.submit()
		r.status = recvMultishotProcessing
	}

	// await
	events := r.future.AwaitBatch(true, deadline)
	// handle events
	eventsLen := len(events)
	if eventsLen == 0 { // nothing received
		r.locker.Unlock()
		return
	}

	for i := 0; i < eventsLen; i++ {
		event := events[i]
		msg, interrupted, handleErr := r.adaptor.HandleCompletionEvent(event)
		if msg != nil {
			r.buffer = append(r.buffer, msg)
		}

		if handleErr != nil {
			if errors.Is(handleErr, syscall.ENOBUFS) { // set ready to resubmit next receive time
				r.status = recvMultishotReady
				break
			}

			r.status = recvMultishotCanceled // set done when receive failed
			r.err = handleErr

			if IsTimeout(handleErr) { // timeout is not iouring err, means op is alive, then cancel it
				if r.cancel() {
					for { // await cancel
						_, _, _, err = r.future.Await()
						if IsCanceled(err) { // op canceled
							err = nil
							break
						}
					}
				}
			}

			r.releaseRuntime() // release runtime

			if len(r.buffer) == 0 {
				err = handleErr
			}

			break
		}

		if interrupted { // set ready to resubmit next read time
			r.status = recvMultishotReady
			break
		}
	}

	// read buffer
	if len(r.buffer) > 0 {
		msg := r.buffer[0]
		r.buffer = r.buffer[1:]
		n, oobn, flags, addr, err = r.adaptor.HandleMsg(msg, fd, b, oob)
	}

	r.locker.Unlock()
	return
}

func (r *MultishotMsgReceiver) Close() (err error) {
	if r.locker.TryLock() { // locked means no reader lock the mr
		switch r.status {
		case recvMultishotReady: // un submitted, then mark canceled.
			r.releaseRuntime()

			r.status = recvMultishotCanceled
			r.err = ErrCanceled
			break
		case recvMultishotProcessing: // cancel and handle events
			if r.cancel() {
				for {
					_, _, _, err = r.future.Await()
					if IsCanceled(err) { // op canceled
						err = nil
						break
					}
				}
			}
			r.releaseRuntime()
			r.status = recvMultishotCanceled
			r.err = ErrCanceled
			break
		case recvMultishotCanceled: // canceled, then pass
			break
		default:
			r.locker.Unlock()
			panic("unreachable multishot receiver status")
			return
		}
		r.locker.Unlock()
		return
	}
	// unlocked means reading, then cancel it
	r.cancel()
	return
}

func (r *MultishotMsgReceiver) submit() {
	r.future = poller.Submit(r.operation)
}

func (r *MultishotMsgReceiver) cancel() bool {
	r.operationLock.Lock()
	if op := r.operation; op != nil {
		ok := poller.Cancel(r.operation) == nil
		r.operationLock.Unlock()
		return ok
	}
	r.operationLock.Unlock()
	return false
}

func (r *MultishotMsgReceiver) releaseRuntime() {
	// release op
	if op := r.operation; op != nil {
		r.operation = nil
		r.future = nil
		ReleaseOperation(op)
	}
	// release br
	if adaptor := r.adaptor; adaptor != nil {
		br := adaptor.br
		adaptor.br = nil
		r.adaptor = nil
		poller.ReleaseBufferAndRing(br)
	}
}
