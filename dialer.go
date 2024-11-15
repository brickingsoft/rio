package rio

import (
	"context"
	"github.com/brickingsoft/rio/pkg/sockets"
	"github.com/brickingsoft/rxp"
	"github.com/brickingsoft/rxp/async"
	"runtime"
	"sync"
)

var (
	defaultExecutors           rxp.Executors = nil
	createDefaultExecutorsOnce sync.Once
)

func Dial(ctx context.Context, network string, address string, options ...Option) (future async.Future[Connection]) {
	_, exist := rxp.TryFrom(ctx)
	if !exist {
		createDefaultExecutorsOnce.Do(func() {
			defaultExecutors = rxp.New()
			runtime.SetFinalizer(defaultExecutors, defaultExecutors.Close)
		})
		ctx = rxp.With(ctx, defaultExecutors)
	}

	opts := Options{}
	for _, o := range options {
		err := o(&opts)
		if err != nil {
			future = async.FailedImmediately[Connection](ctx, err)
			return
		}
	}

	promise, promiseOk := async.TryPromise[Connection](ctx)
	if !promiseOk {
		future = async.FailedImmediately[Connection](ctx, ErrBusy)
		return
	}

	socketOpts := sockets.Options{
		MultipathTCP:            opts.MultipathTCP,
		DialPacketConnLocalAddr: opts.DialPacketConnLocalAddr,
	}

	executed := rxp.TryExecute(ctx, func() {
		sockets.Dial(network, address, socketOpts, func(inner sockets.Connection, err error) {
			if err != nil {
				promise.Fail(err)
				return
			}
			switch network {
			case "tcp", "tcp4", "tcp6":
				promise.Succeed(newTCPConnection(ctx, inner))
				break
			case "udp", "udp4", "udp6":
				// todo
				break
			case "unix", "unixgram", "unixpacket":
				// todo
				break
			case "ip", "ip4", "ip6":
				// todo
				break
			}
		})
	})

	future = promise.Future()

	if !executed {
		promise.Fail(ErrBusy)
		return
	}

	return
}
