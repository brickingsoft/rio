package rio

import (
	"context"
	"crypto/tls"
	"github.com/brickingsoft/rio/pkg/async"
	"github.com/brickingsoft/rio/pkg/bytebufferpool"
	"github.com/brickingsoft/rio/pkg/maxprocs"
	"github.com/brickingsoft/rio/pkg/rate/timeslimiter"
	"github.com/brickingsoft/rio/pkg/security"
	"github.com/brickingsoft/rio/pkg/sockets"
	"net"
	"time"
)

// tcp: unix,unixpacket
// udp: unixgram

type UnixInbound interface {
	Buffer() (buf bytebufferpool.Buffer)
	Received() (n int)
	Addr() (addr *net.UnixAddr)
}

type UnixMsgInbound interface {
	Buffer() (buf bytebufferpool.Buffer)
	Received() (n int)
	OOBBytes() (n int)
	Flags() (n int)
	Addr() (addr *net.UnixAddr)
}

type UnixConnection interface {
	Connection
	PacketConnection
	// ReadFromUnix acts like [UnixConn.ReadFrom] but returns a [UnixAddr].
	ReadFromUnix() (future async.Future[UnixInbound])
	// ReadMsgUnix reads a message from c, copying the payload into b and
	// the associated out-of-band data into oob. It returns the number of
	// bytes copied into b, the number of bytes copied into oob, the flags
	// that were set on the message and the source address of the message.
	//
	// Note that if len(b) == 0 and len(oob) > 0, this function will still
	// read (and discard) 1 byte from the connection.
	ReadMsgUnix() (future async.Future[UnixMsgInbound])
	// WriteToUnix acts like [UnixConn.WriteTo] but takes a [UnixAddr].
	WriteToUnix(b []byte, addr *net.UnixAddr) (future async.Future[Outbound])
	// WriteMsgUnix writes a message to addr via c, copying the payload
	// from b and the associated out-of-band data from oob. It returns the
	// number of payload and out-of-band bytes written.
	//
	// Note that if len(b) == 0 and len(oob) > 0, this function will still
	// write 1 byte to the connection.
	WriteMsgUnix(b, oob []byte, addr *net.UnixAddr) (future async.Future[MsgOutbound])
}

func newUnixConnection(ctx context.Context, conn sockets.UnixConnection, onClose ConnectionOnClose) (uc *unixConnection) {

	return
}

type unixConnection struct {
	onClose ConnectionOnClose
}

func (conn *unixConnection) Context() (ctx context.Context) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) LocalAddr() (addr net.Addr) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) RemoteAddr() (addr net.Addr) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) SetDeadline(t time.Time) (err error) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) SetReadDeadline(t time.Time) (err error) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) SetWriteDeadline(t time.Time) (err error) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) SetReadBufferSize(size int) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) Read() (future async.Future[Inbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) Write(p []byte) (future async.Future[Outbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) Close() (err error) {
	conn.onClose(conn)
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) ReadFrom() (future async.Future[PacketInbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) WriteTo(p []byte, addr net.Addr) (future async.Future[Outbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) ReadFromUnix() (future async.Future[UnixInbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) ReadMsgUnix() (future async.Future[UnixMsgInbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) WriteToUnix(b []byte, addr *net.UnixAddr) (future async.Future[Outbound]) {
	//TODO implement me
	panic("implement me")
}

func (conn *unixConnection) WriteMsgUnix(b, oob []byte, addr *net.UnixAddr) (future async.Future[MsgOutbound]) {
	//TODO implement me
	panic("implement me")
}

type unixListener struct {
	ctx                           context.Context
	cancel                        context.CancelFunc
	inner                         sockets.UnixListener
	connectionsLimiter            *timeslimiter.Bucket
	connectionsLimiterWaitTimeout time.Duration
	executors                     async.Executors
	tlsConfig                     *tls.Config
	promises                      []async.Promise[Connection]
	maxprocsUndo                  maxprocs.Undo
}

func (ln *unixListener) Addr() (addr net.Addr) {
	addr = ln.inner.Addr()
	return
}

func (ln *unixListener) Accept() (future async.Future[Connection]) {
	ctx := ln.ctx
	promisesLen := len(ln.promises)
	for i := 0; i < promisesLen; i++ {
		promise, promiseErr := async.MustInfinitePromise[Connection](ctx)
		if promiseErr != nil {
			future = async.FailedImmediately[Connection](ctx, promiseErr)
			_ = ln.Close()
			return
		}
		ln.acceptOne(promise)
		ln.promises[i] = promise
	}
	future = async.Group[Connection](ln.promises)
	return
}

func (ln *unixListener) Close() (err error) {
	for _, promise := range ln.promises {
		promise.Cancel()
	}
	err = ln.inner.Close()
	ln.executors.GracefulClose()
	ln.maxprocsUndo()
	return
}

func (ln *unixListener) ok() bool {
	return ln.ctx.Err() == nil
}

func (ln *unixListener) acceptOne(infinitePromise async.Promise[Connection]) {
	if !ln.ok() {
		return
	}
	ctx, cancel := context.WithTimeout(ln.ctx, ln.connectionsLimiterWaitTimeout)
	waitErr := ln.connectionsLimiter.Wait(ctx)
	cancel()
	if waitErr != nil {
		ln.acceptOne(infinitePromise)
		return
	}
	ln.inner.AcceptUnix(func(sock sockets.UnixConnection, err error) {
		if err != nil {
			infinitePromise.Fail(err)
			return
		}
		if ln.tlsConfig != nil {
			sock = security.Serve(ln.ctx, sock, ln.tlsConfig).(sockets.UnixConnection)
		}
		conn := newUnixConnection(ln.ctx, sock, func(_ Connection) {
			ln.connectionsLimiter.Revert()
		})
		infinitePromise.Succeed(conn)
		ln.acceptOne(infinitePromise)
		return
	})
}
