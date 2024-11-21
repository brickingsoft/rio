package rio

import (
	"context"
	"errors"
	"github.com/brickingsoft/rio/pkg/sockets"
	"github.com/brickingsoft/rio/transport"
	"github.com/brickingsoft/rxp"
	"github.com/brickingsoft/rxp/async"
	"net"
)

// ListenPacket
func ListenPacket(ctx context.Context, network string, addr string, options ...Option) (conn PacketConnection, err error) {
	opt := Options{}
	for _, o := range options {
		err = o(&opt)
		if err != nil {
			return
		}
	}

	// executors
	ctx = rxp.With(ctx, getExecutors())
	// inner
	inner, innerErr := sockets.ListenPacket(network, addr, sockets.Options{})
	if innerErr != nil {
		err = errors.Join(errors.New("rio: listen packet failed"), innerErr)
		return
	}

	conn = newPacketConnection(ctx, inner)
	return
}

type PacketConnection interface {
	Connection
	ReadFrom() (future async.Future[transport.PacketInbound])
	WriteTo(p []byte, addr net.Addr) (future async.Future[transport.Outbound])
	SetReadMsgOOBBufferSize(size int)
	ReadMsg() (future async.Future[transport.PacketMsgInbound])
	WriteMsg(p []byte, oob []byte, addr net.Addr) (future async.Future[transport.PacketMsgOutbound])
}

const (
	defaultOOBBufferSize = 1024
)

func newPacketConnection(ctx context.Context, inner sockets.PacketConnection) (conn PacketConnection) {
	conn = &packetConnection{
		connection: *newConnection(ctx, inner),
		inner:      inner,
		oob:        transport.NewInboundBuffer(),
		oobn:       defaultOOBBufferSize,
	}
	return
}

type packetConnection struct {
	connection
	inner sockets.PacketConnection
	oob   transport.InboundBuffer
	oobn  int
}

func (conn *packetConnection) ReadFrom() (future async.Future[transport.PacketInbound]) {
	p, allocateErr := conn.rb.Allocate(conn.rbs)
	if allocateErr != nil {
		future = async.FailedImmediately[transport.PacketInbound](conn.ctx, errors.Join(ErrAllocate, allocateErr))
		return
	}
	promise, promiseErr := async.Make[transport.PacketInbound](conn.ctx)
	if promiseErr != nil {
		conn.rb.AllocatedWrote(0)
		if async.IsBusy(promiseErr) {
			future = async.FailedImmediately[transport.PacketInbound](conn.ctx, ErrBusy)
		} else {
			future = async.FailedImmediately[transport.PacketInbound](conn.ctx, promiseErr)
		}
		return
	}

	conn.inner.ReadFrom(p, func(n int, addr net.Addr, err error) {
		if err != nil {
			conn.rb.AllocatedWrote(0)
			promise.Fail(err)
			return
		}
		conn.rb.AllocatedWrote(n)
		inbound := transport.NewPacketInbound(conn.rb, addr, n)
		promise.Succeed(inbound)
		return
	})
	future = promise.Future()
	return
}

func (conn *packetConnection) WriteTo(p []byte, addr net.Addr) (future async.Future[transport.Outbound]) {
	if len(p) == 0 {
		future = async.FailedImmediately[transport.Outbound](conn.ctx, ErrEmptyPacket)
		return
	}
	if addr == nil {
		future = async.FailedImmediately[transport.Outbound](conn.ctx, ErrNilAddr)
		return
	}

	promise, promiseErr := async.Make[transport.Outbound](conn.ctx)
	if promiseErr != nil {
		if async.IsBusy(promiseErr) {
			future = async.FailedImmediately[transport.Outbound](conn.ctx, ErrBusy)
		} else {
			future = async.FailedImmediately[transport.Outbound](conn.ctx, promiseErr)
		}
		return
	}

	conn.inner.WriteTo(p, addr, func(n int, err error) {
		if err != nil {
			if n == 0 {
				promise.Fail(err)
			} else {
				outbound := transport.NewOutBound(n, err)
				promise.Succeed(outbound)
			}
			return
		}
		outbound := transport.NewOutBound(n, nil)
		promise.Succeed(outbound)
		return
	})

	future = promise.Future()
	return
}

func (conn *packetConnection) SetReadMsgOOBBufferSize(size int) {
	if size < 1 {
		return
	}
	conn.oobn = size
}

func (conn *packetConnection) ReadMsg() (future async.Future[transport.PacketMsgInbound]) {
	p, allocateErr := conn.rb.Allocate(conn.rbs)
	if allocateErr != nil {
		future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, errors.Join(ErrAllocate, allocateErr))
		return
	}
	oob, allocateOOBErr := conn.oob.Allocate(conn.oobn)
	if allocateOOBErr != nil {
		conn.rb.AllocatedWrote(0)
		future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, errors.Join(ErrAllocate, allocateOOBErr))
		return
	}
	promise, promiseErr := async.Make[transport.PacketMsgInbound](conn.ctx)
	if promiseErr != nil {
		conn.rb.AllocatedWrote(0)
		conn.oob.AllocatedWrote(0)
		if async.IsBusy(promiseErr) {
			future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, ErrBusy)
		} else {
			future = async.FailedImmediately[transport.PacketMsgInbound](conn.ctx, promiseErr)
		}
		return
	}

	conn.inner.ReadMsg(p, oob, func(n int, oobn int, flags int, addr net.Addr, err error) {
		if err != nil {
			conn.rb.AllocatedWrote(0)
			conn.oob.AllocatedWrote(0)
			promise.Fail(err)
			return
		}
		conn.rb.AllocatedWrote(n)
		conn.oob.AllocatedWrote(oobn)
		inbound := transport.NewPacketMsgInbound(conn.rb, conn.oob, addr, n, oobn, flags)
		promise.Succeed(inbound)
		return
	})
	future = promise.Future()
	return
}

func (conn *packetConnection) WriteMsg(p []byte, oob []byte, addr net.Addr) (future async.Future[transport.PacketMsgOutbound]) {
	if len(p) == 0 {
		future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, ErrEmptyPacket)
		return
	}
	if addr == nil {
		future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, ErrNilAddr)
		return
	}

	promise, promiseErr := async.Make[transport.PacketMsgOutbound](conn.ctx)
	if promiseErr != nil {
		if async.IsBusy(promiseErr) {
			future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, ErrBusy)
		} else {
			future = async.FailedImmediately[transport.PacketMsgOutbound](conn.ctx, promiseErr)
		}
		return
	}

	conn.inner.WriteMsg(p, oob, addr, func(n int, oobn int, err error) {
		if err != nil {
			if n == 0 {
				promise.Fail(err)
			} else {
				outbound := transport.NewPacketMsgOutbound(n, oobn, err)
				promise.Succeed(outbound)
			}
			return
		}
		outbound := transport.NewPacketMsgOutbound(n, oobn, nil)
		promise.Succeed(outbound)
		return
	})

	future = promise.Future()
	return
}

func (conn *packetConnection) Close() (future async.Future[async.Void]) {
	promise := async.UnlimitedPromise[async.Void](conn.ctx)
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
