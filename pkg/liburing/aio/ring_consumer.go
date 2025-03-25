//go:build linux

package aio

import (
	"errors"
	"github.com/brickingsoft/rio/pkg/liburing"
	"golang.org/x/sys/unix"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type CQEConsumer interface {
	handle()
	Close() (err error)
}

func newCQEPushTypedConsumer(ring *liburing.Ring, curve Curve) (CQEConsumer, error) {
	// exit
	exitFd, exitFdErr := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.FD_CLOEXEC)
	if exitFdErr != nil {
		return nil, NewRingErr(os.NewSyscallError("eventfd", exitFdErr))
	}
	// eventFd
	eventFd, eventFdErr := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.FD_CLOEXEC)
	if eventFdErr != nil {
		_ = unix.Close(exitFd)
		return nil, NewRingErr(os.NewSyscallError("eventfd", eventFdErr))
	}
	// epoll
	epollFd, epollErr := unix.EpollCreate1(0)
	if epollErr != nil {
		_ = unix.Close(exitFd)
		_ = unix.Close(eventFd)
		return nil, NewRingErr(os.NewSyscallError("epoll_create1", epollErr))
	}
	if ctlErr := unix.EpollCtl(
		epollFd,
		unix.EPOLL_CTL_ADD, eventFd,
		&unix.EpollEvent{Fd: int32(eventFd), Events: unix.EPOLLIN | unix.EPOLLET},
	); ctlErr != nil {
		_ = unix.Close(exitFd)
		_ = unix.Close(eventFd)
		_ = unix.Close(epollFd)
		return nil, NewRingErr(os.NewSyscallError("epoll_ctl", ctlErr))
	}
	// register
	_, regEventFdErr := ring.RegisterEventFd(eventFd)
	if regEventFdErr != nil {
		_ = unix.Close(exitFd)
		_ = unix.Close(eventFd)
		_ = unix.Close(epollFd)
		return nil, NewRingErr(os.NewSyscallError("ring_register_eventfd", regEventFdErr))
	}

	// curve
	if len(curve) == 0 {
		curve = Curve{
			{512, 100 * time.Microsecond},
			{1024, 200 * time.Microsecond},
			{4096, 400 * time.Microsecond},
		}
	}
	c := &CQEPushTypedConsumer{
		ring:          ring,
		eventFd:       eventFd,
		exitFd:        exitFd,
		epollFd:       epollFd,
		wg:            new(sync.WaitGroup),
		exitOp:        new(Operation),
		waitTimeCurve: curve,
	}

	go c.handle()
	c.wg.Add(1)
	return c, nil
}

type CQEPushTypedConsumer struct {
	ring          *liburing.Ring
	eventFd       int
	exitFd        int
	epollFd       int
	wg            *sync.WaitGroup
	exitOp        *Operation
	waitTimeCurve Curve
}

func (c *CQEPushTypedConsumer) handle() {
	defer c.wg.Done()

	var (
		ring         = c.ring
		eventFd      = int32(c.eventFd)
		exitFd       = int32(c.exitFd)
		buf          = make([]byte, 8)
		events       = make([]unix.EpollEvent, 1024)
		cqes         = make([]*liburing.CompletionQueueEvent, 1024)
		transmission = NewCurveTransmission(c.waitTimeCurve)
		stopped      = false
	)

	for {
		if stopped {
			break
		}
		n, waitErr := unix.EpollWait(c.epollFd, events, -1)
		if waitErr != nil {
			if errors.Is(waitErr, unix.EINTR) {
				continue
			}
			return
		}

		for i := 0; i < n; i++ {
			event := &events[i]
			switch event.Fd {
			case exitFd:
				_, _ = unix.Read(c.exitFd, buf)
				stopped = true
				break
			case eventFd:
				completed := uint32(0)
			PEEK:
				if peeked := ring.PeekBatchCQE(cqes); peeked > 0 {
					for j := uint32(0); j < peeked; j++ {
						// get cqe
						cqe := cqes[j]
						cqes[j] = nil
						// check userdata
						if cqe.UserData == 0 { // no userdata means no op
							continue
						}
						if cqe.IsInternalUpdateTimeoutUserdata() { // userdata means not op
							continue
						}
						if cqe.UserData == uint64(uintptr(unsafe.Pointer(c.exitOp))) { // exit by op
							stopped = true
							continue
						}
						// get op from cqe
						copPtr := cqe.GetData()
						cop := (*Operation)(copPtr)
						// handle
						var (
							opN     int
							opFlags = cqe.Flags
							opErr   error
						)
						if cqe.Res < 0 {
							opErr = os.NewSyscallError(cop.Name(), syscall.Errno(-cqe.Res))
						} else {
							opN = int(cqe.Res)
						}
						cop.complete(opN, opFlags, opErr)
					}
					// cq advance
					ring.CQAdvance(peeked)
					completed += peeked
					// try to peek more
					goto PEEK
				}
				// read
				_, _ = unix.Read(c.eventFd, buf)
				// wait when matched
				if _, waitTime := transmission.Match(completed); waitTime > 0 {
					time.Sleep(waitTime)
					goto PEEK
				}
				break
			default:
				_, _ = unix.Read(int(event.Fd), buf)
				break
			}
		}
	}
	return
}

func (c *CQEPushTypedConsumer) Close() (err error) {
EXIT:
	if _, writeExitErr := unix.Write(c.exitFd, []byte{1}); writeExitErr != nil {
		if errors.Is(writeExitErr, unix.EAGAIN) || errors.Is(writeExitErr, unix.EINTR) {
			goto EXIT
		}
		// use op
		for i := 0; i < 10; i++ {
			sqe := c.ring.GetSQE()
			if sqe == nil {
				_, _ = c.ring.Submit()
				time.Sleep(1 * time.Microsecond)
				continue
			}
			sqe.PrepareNop()
			sqe.SetData(unsafe.Pointer(&c.exitOp))
			if _, submitErr := c.ring.Submit(); submitErr != nil {
				continue
			}
			break
		}
	}

	_, err = c.ring.UnregisterEventFd(c.eventFd)

	_ = unix.Close(c.exitFd)
	_ = unix.Close(c.eventFd)
	_ = unix.Close(c.epollFd)

	c.wg.Wait()
	return
}

func newCQEPollTypedConsumer(ring *liburing.Ring, idleTime time.Duration, curve Curve) (CQEConsumer, error) {
	// idle
	if idleTime < 1 {
		idleTime = defaultCQEPullTypedConsumeIdleTime
	}
	// curve
	if len(curve) == 0 {
		curve = Curve{
			{8, 1 * time.Microsecond},
			{16, 10 * time.Microsecond},
			{32, 200 * time.Microsecond},
			{64, 300 * time.Microsecond},
			{96, 500 * time.Microsecond},
		}
	}

	c := &CQEPollTypedConsumer{
		ring:          ring,
		idleTime:      idleTime,
		wg:            new(sync.WaitGroup),
		done:          make(chan struct{}),
		waitTimeCurve: curve,
	}

	go c.handle()

	c.wg.Add(1)

	return c, nil
}

type CQEPollTypedConsumer struct {
	ring          *liburing.Ring
	wg            *sync.WaitGroup
	idleTime      time.Duration
	done          chan struct{}
	waitTimeCurve Curve
}

func (c *CQEPollTypedConsumer) handle() {
	defer c.wg.Done()

	var (
		ring                            = c.ring
		cqes                            = make([]*liburing.CompletionQueueEvent, 1024)
		idleTime                        = syscall.NsecToTimespec(c.idleTime.Nanoseconds())
		needToIdle                      = false
		transmission                    = NewCurveTransmission(c.waitTimeCurve)
		cqeWaitMaxCount, cqeWaitTimeout = transmission.Up()
		waitZeroTimes                   = 10
		stopped                         = false
	)

	for {
		if stopped {
			break
		}
		select {
		case <-c.done:
			stopped = true
			break
		default:
		PEEK:
			if peeked := ring.PeekBatchCQE(cqes); peeked > 0 {
				for i := uint32(0); i < peeked; i++ {
					cqe := cqes[i]
					cqes[i] = nil

					if cqe.UserData == 0 { // no userdata means no op
						continue
					}
					if cqe.IsInternalUpdateTimeoutUserdata() { // userdata means not op
						continue
					}

					// get op from cqe
					copPtr := cqe.GetData()
					cop := (*Operation)(copPtr)
					// handle
					var (
						opN     int
						opFlags = cqe.Flags
						opErr   error
					)
					if cqe.Res < 0 {
						opErr = os.NewSyscallError(cop.Name(), syscall.Errno(-cqe.Res))
					} else {
						opN = int(cqe.Res)
					}
					cop.complete(opN, opFlags, opErr)
				}
				// CQAdvance
				ring.CQAdvance(peeked)
				goto PEEK
			} else {
				if needToIdle {
					if _, waitErr := ring.WaitCQETimeout(&idleTime); waitErr != nil {
						break
					} else { // reset idle
						needToIdle = false
						waitZeroTimes = 10
					}
				}
				if cqeWaitMaxCount < 1 {
					cqeWaitMaxCount = 1
				}
				if cqeWaitTimeout < 1 {
					cqeWaitTimeout = time.Duration(cqeWaitMaxCount) * time.Microsecond
				}
				ns := syscall.NsecToTimespec(cqeWaitTimeout.Nanoseconds())
				if _, waitErr := ring.WaitCQEs(cqeWaitMaxCount, &ns, nil); waitErr != nil {
					cqeWaitMaxCount, cqeWaitTimeout = transmission.Down()
					waitZeroTimes--
					if waitZeroTimes < 1 {
						needToIdle = true
					}
				} else {
					cqeWaitMaxCount, cqeWaitTimeout = transmission.Up()
				}
			}
			break
		}
	}
	return
}

func (c *CQEPollTypedConsumer) Close() (err error) {
	close(c.done)
	c.wg.Wait()
	return
}
