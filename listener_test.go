package rio_test

import (
	"context"
	"github.com/brickingsoft/rio"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestListen(t *testing.T) {
	ctx := context.Background()
	ln, lnErr := rio.Listen(ctx, "tcp", ":9000", rio.WithParallelAcceptors(1))
	if lnErr != nil {
		t.Error(lnErr)
		return
	}
	defer func(ln rio.Listener) {
		closeErr := ln.Close()
		if closeErr != nil {
			t.Error(closeErr)
		}
	}(ln)
	wg := &sync.WaitGroup{}
	count := atomic.Int64{}
	ln.Accept().OnComplete(func(ctx context.Context, conn rio.Connection, err error) {
		var addr net.Addr
		if conn != nil {
			addr = conn.RemoteAddr()
		}
		t.Log("accepted:", count.Add(1), addr, err, ctx.Err())
		if conn != nil {
			wg.Done()
		}
	})
	for i := 0; i < 10; i++ {
		wg.Add(1)
		conn, dialErr := net.Dial("tcp", ":9000")
		if dialErr != nil {
			t.Error(dialErr)
			return
		}
		t.Log("dialed:", i+1, conn.LocalAddr())
		_ = conn.Close()
	}
	wg.Wait()
}
