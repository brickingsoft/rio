package rio

import (
	"context"
	"github.com/brickingsoft/errors"
	"github.com/brickingsoft/rio/pkg/aio"
	"github.com/brickingsoft/rio/transport"
	"github.com/brickingsoft/rxp/async"
	"net"
)

type PacketConnection interface {
	transport.PacketConnection
}

const (
	defaultOOBBufferSize = 1024
)

func newPacketConnection(ctx context.Context, fd aio.NetFd) (conn PacketConnection) {
	conn = &packetConnection{
		connection: newConnection(ctx, fd),
		oob:        transport.NewInboundBuffer(),
		oobn:       defaultOOBBufferSize,
	}
	return
}

type packetConnection struct {
	connection
	oob  transport.InboundBuffer
	oobn int
}

func (conn *packetConnection) ReadFrom() (future async.Future[transport.PacketInbound]) {
	if conn.disconnected() {
		err := errors.New(
			"read from failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrClosed),
		)
		future = async.FailedImmediately[transport.PacketInbound](conn.ctx, err)
		return
	}
	b, allocateErr := conn.rb.Allocate(conn.rbs)
	if allocateErr != nil {
		err := errors.New(
			"read from failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrAllocate),
		)
		future = async.FailedImmediately[transport.PacketInbound](conn.ctx, err)
		return
	}
	var promise async.Promise[transport.PacketInbound]
	var promiseErr error
	if conn.readTimeout > 0 {
		promise, promiseErr = async.Make[transport.PacketInbound](conn.ctx, async.WithTimeout(conn.readTimeout))
	} else {
		promise, promiseErr = async.Make[transport.PacketInbound](conn.ctx)
	}
	if promiseErr != nil {
		conn.rb.AllocatedWrote(0)
		err := errors.New(
			"read from failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(promiseErr),
		)
		future = async.FailedImmediately[transport.PacketInbound](conn.ctx, err)
		return
	}
	promise.SetErrInterceptor(conn.readFromErrInterceptor)

	aio.RecvFrom(conn.fd, b, func(userdata aio.Userdata, err error) {
		if err != nil {
			promise.Fail(err)
			return
		}
		n := userdata.N
		conn.rb.AllocatedWrote(n)
		addr := userdata.Addr
		inbound := transport.NewPacketInbound(conn.rb, addr, n)
		promise.Succeed(inbound)
		return
	})

	future = promise.Future()
	return
}

func (conn *packetConnection) readFromErrInterceptor(ctx context.Context, _ transport.PacketInbound, err error) (future async.Future[transport.PacketInbound]) {
	conn.rb.AllocatedWrote(conn.rbs)
	err = errors.New(
		"read from failed",
		errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
		errors.WithWrap(err),
	)
	future = async.Immediately[transport.PacketInbound](ctx, nil, err)
	return
}

func (conn *packetConnection) WriteTo(b []byte, addr net.Addr) (future async.Future[int]) {
	if len(b) == 0 {
		err := errors.New(
			"write to failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrEmptyBytes),
		)
		future = async.FailedImmediately[int](conn.ctx, err)
		return
	}
	if addr == nil {
		err := errors.New(
			"write to failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrNilAddr),
		)
		future = async.FailedImmediately[int](conn.ctx, err)
		return
	}
	if conn.disconnected() {
		err := errors.New(
			"write to failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrClosed),
		)
		future = async.FailedImmediately[int](conn.ctx, err)
		return
	}
	var promise async.Promise[int]
	var promiseErr error
	if conn.writeTimeout > 0 {
		promise, promiseErr = async.Make[int](conn.ctx, async.WithTimeout(conn.writeTimeout))
	} else {
		promise, promiseErr = async.Make[int](conn.ctx)
	}
	if promiseErr != nil {
		err := errors.New(
			"write to failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(promiseErr),
		)
		future = async.FailedImmediately[int](conn.ctx, err)
		return
	}
	promise.SetErrInterceptor(conn.writeToErrInterceptor)

	aio.SendTo(conn.fd, b, addr, func(userdata aio.Userdata, err error) {
		if err != nil {
			promise.Fail(err)
			return
		}
		n := userdata.N
		promise.Complete(n, err)
		return
	})

	future = promise.Future()
	return
}

func (conn *packetConnection) writeToErrInterceptor(ctx context.Context, n int, err error) (future async.Future[int]) {
	err = errors.New(
		"write to failed",
		errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
		errors.WithWrap(err),
	)
	future = async.Immediately[int](ctx, n, err)
	return
}

func (conn *packetConnection) SetReadMsgOOBBufferSize(size int) {
	if size < 1 {
		return
	}
	conn.oobn = size
}

func (conn *packetConnection) ReadMsg() (future async.Future[transport.PacketMsgInbound]) {
	if conn.disconnected() {
		err := errors.New(
			"read message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrClosed),
		)
		future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, err)
		return
	}

	b, allocateErr := conn.rb.Allocate(conn.rbs)
	if allocateErr != nil {
		err := errors.New(
			"read message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrAllocate),
		)
		future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, err)
		return
	}
	oob, allocateOOBErr := conn.oob.Allocate(conn.oobn)
	if allocateOOBErr != nil {
		conn.rb.AllocatedWrote(0)
		err := errors.New(
			"read message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrAllocate),
		)
		future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, err)
		return
	}

	var promise async.Promise[transport.PacketMsgInbound]
	var promiseErr error
	if conn.readTimeout > 0 {
		promise, promiseErr = async.Make[transport.PacketMsgInbound](conn.ctx, async.WithTimeout(conn.readTimeout))
	} else {
		promise, promiseErr = async.Make[transport.PacketMsgInbound](conn.ctx)
	}
	if promiseErr != nil {
		conn.rb.AllocatedWrote(0)
		conn.oob.AllocatedWrote(0)
		err := errors.New(
			"read message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(promiseErr),
		)
		future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, err)
		return
	}
	promise.SetErrInterceptor(conn.readMsgErrInterceptor)

	aio.RecvMsg(conn.fd, b, oob, func(userdata aio.Userdata, err error) {
		if err != nil {
			promise.Fail(err)
			return
		}
		n := userdata.N
		conn.rb.AllocatedWrote(n)
		oobn := userdata.OOBN
		conn.oob.AllocatedWrote(oobn)
		addr := userdata.Addr
		flags := userdata.MessageFlags
		inbound := transport.NewPacketMsgInbound(conn.rb, conn.oob, addr, n, oobn, flags)
		promise.Succeed(inbound)
		return
	})

	future = promise.Future()
	return
}

func (conn *packetConnection) readMsgErrInterceptor(ctx context.Context, _ transport.PacketMsgInbound, err error) (future async.Future[transport.PacketMsgInbound]) {
	conn.rb.AllocatedWrote(conn.rbs)
	conn.oob.AllocatedWrote(conn.oobn)
	err = errors.New(
		"read msg failed",
		errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
		errors.WithWrap(err),
	)
	future = async.Immediately[transport.PacketMsgInbound](ctx, nil, err)
	return
}

func (conn *packetConnection) WriteMsg(b []byte, oob []byte, addr net.Addr) (future async.Future[transport.PacketMsgOutbound]) {
	if len(b) == 0 && len(oob) == 0 {
		err := errors.New(
			"write message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrEmptyBytes),
		)
		future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, err)
		return
	}

	if addr == nil {
		err := errors.New(
			"write message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrNilAddr),
		)
		future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, err)
		return
	}
	if conn.disconnected() {
		err := errors.New(
			"write message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(ErrClosed),
		)
		future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, err)
		return
	}

	var promise async.Promise[transport.PacketMsgOutbound]
	var promiseErr error
	if conn.writeTimeout > 0 {
		promise, promiseErr = async.Make[transport.PacketMsgOutbound](conn.ctx, async.WithTimeout(conn.writeTimeout))
	} else {
		promise, promiseErr = async.Make[transport.PacketMsgOutbound](conn.ctx)
	}
	if promiseErr != nil {
		err := errors.New(
			"write message failed",
			errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
			errors.WithWrap(promiseErr),
		)
		future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, err)
		return
	}
	promise.SetErrInterceptor(conn.writeMsgErrInterceptor)

	aio.SendMsg(conn.fd, b, oob, addr, func(userdata aio.Userdata, err error) {
		n := userdata.N
		oobn := userdata.OOBN
		if err != nil {
			promise.Fail(err)
			return
		}
		outbound := transport.NewPacketMsgOutbound(n, oobn)
		promise.Succeed(outbound)
		return
	})

	future = promise.Future()
	return
}

func (conn *packetConnection) writeMsgErrInterceptor(ctx context.Context, _ transport.PacketMsgOutbound, err error) (future async.Future[transport.PacketMsgOutbound]) {
	err = errors.New(
		"write msg failed",
		errors.WithMeta(errMetaPkgKey, errMetaPkgVal),
		errors.WithWrap(err),
	)
	future = async.Immediately[transport.PacketMsgOutbound](ctx, nil, err)
	return
}

func (conn *packetConnection) Close() (future async.Future[async.Void]) {
	promise, promiseErr := async.Make[async.Void](conn.ctx, async.WithUnlimitedMode())
	if promiseErr != nil {
		aio.CloseImmediately(conn.fd)
		conn.rb.Close()
		conn.oob.Close()
		future = async.SucceedImmediately[async.Void](conn.ctx, async.Void{})
		return
	}
	conn.connection.Close().OnComplete(func(ctx context.Context, entry async.Void, cause error) {
		if cause != nil {
			promise.Fail(cause)
		} else {
			promise.Succeed(async.Void{})
		}
		conn.oob.Close()
	})
	future = promise.Future()
	return
}
