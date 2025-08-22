//go:build linux

package rio

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"github.com/brickingsoft/rio/pkg/liburing/aio/sys"
)

func (d *Dialer) dial(ctx context.Context, network string, laddr, raddr net.Addr) (c net.Conn, err error) {
	switch a := raddr.(type) {
	case *net.TCPAddr:
		la, _ := laddr.(*net.TCPAddr)
		c, err = d.DialTCP(ctx, network, la, a)
		break
	case *net.UDPAddr:
		la, _ := laddr.(*net.UDPAddr)
		c, err = d.DialUDP(ctx, network, la, a)
		break
	case *net.UnixAddr:
		la, _ := laddr.(*net.UnixAddr)
		c, err = d.DialUnix(ctx, network, la, a)
		break
	case *net.IPAddr:
		la, _ := laddr.(*net.IPAddr)
		c, err = d.DialIP(ctx, network, la, a)
		break
	default:
		err = &net.OpError{Op: "dial", Net: network, Source: nil, Addr: raddr, Err: &net.AddrError{Err: "unexpected address type", Addr: raddr.String()}}
		break
	}
	return
}

func (d *Dialer) dialParallel(ctx context.Context, network string, laddr net.Addr, raddrs []net.Addr) (c net.Conn, err error) {
	var primaries, fallbacks []net.Addr
	if d.dualStack() && network == "tcp" {
		primaries, fallbacks = sys.PartitionAddrs(raddrs, sys.IsIPv4)
	} else {
		primaries = raddrs
	}
	if len(fallbacks) == 0 {
		c, err = d.dialSerial(ctx, network, laddr, primaries)
		return
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		primary bool
		done    bool
	}
	results := make(chan dialResult) // unbuffered

	startRacer := func(ctx context.Context, primary bool) {
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		cc, dialErr := d.dialSerial(ctx, network, laddr, ras)
		select {
		case results <- dialResult{Conn: cc, error: dialErr, primary: primary, done: true}:
		case <-returned:
			if c != nil {
				_ = c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(d.fallbackDelay())
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			if primary.done && fallback.done {
				return nil, primary.error
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// partialDeadline returns the deadline to use for a single address,
// when multiple addresses are pending.
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, aio.ErrTimeout
	}
	// Tentatively allocate equal time to each remaining address.
	timeout := timeRemaining / time.Duration(addrsRemaining)
	// If the time per address is too short, steal from the end of the list.
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}

func (d *Dialer) dialSerial(ctx context.Context, network string, laddr net.Addr, ras []net.Addr) (net.Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for i, ra := range ras {
		select {
		case <-ctx.Done():
			return nil, &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: ra, Err: aio.MapErr(ctx.Err())}
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline0, err := partialDeadline(time.Now(), deadline, len(ras)-i)
			if err != nil {
				// Ran out of time.
				if firstErr == nil {
					firstErr = &net.OpError{Op: "dial", Net: network, Source: laddr, Addr: ra, Err: err}
				}
				break
			}
			if partialDeadline0.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline0)
				defer cancel()
			}
		}

		c, err := d.dial(dialCtx, network, laddr, ra)
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = &net.OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: errors.New("missing address")}
	}
	return nil, firstErr
}
