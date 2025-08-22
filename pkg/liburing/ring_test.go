//go:build linux

package liburing_test

import (
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

func TestNew(t *testing.T) {
	ring, ringErr := liburing.New(liburing.WithEntries(4))
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	reg, regErr := ring.RegisterRingFd()
	if regErr != nil {
		t.Error(regErr)
		return
	}
	defer ring.UnregisterRingFd()
	t.Log("register ring fd success:", reg)

	t.Log("sq:", ring.SQEntries())
	t.Log("cq:", ring.CQEntries())
	probe, probeErr := ring.Probe()
	if probeErr != nil {
		t.Error(probeErr)
		return
	}
	t.Log("bind:", probe.IsSupported(liburing.IORING_OP_BIND))
	t.Log("listen:", probe.IsSupported(liburing.IORING_OP_LISTEN))
	t.Log("recv_zc:", probe.IsSupported(liburing.IORING_OP_RECV_ZC))

	sq := ring.GetSQE()
	if sq == nil {
		t.Error("SQE is nil")
		return
	}
	sq.PrepareNop()
	sq.SetData64(1)

	n, subErr := ring.Submit()
	if subErr != nil {
		t.Error(subErr)
		return
	}
	t.Log("sub:", n)

	cqe, waitErr := ring.WaitCQE()
	if waitErr != nil {
		t.Error(waitErr)
		return
	}
	if cqe.UserData == sq.UserData {
		t.Log("succeed")
	} else {
		t.Error("UserData not equal")
	}
}

func TestRing_SubmitAndWaitMinTimeout(t *testing.T) {
	flags := liburing.IORING_SETUP_COOP_TASKRUN | liburing.IORING_SETUP_SINGLE_ISSUER
	ring, ringErr := liburing.New(liburing.WithEntries(4), liburing.WithFlags(flags))
	if ringErr != nil {
		t.Error(ringErr)
		return
	}
	defer ring.Close()

	_, regErr := ring.RegisterRingFd()
	if regErr != nil {
		t.Error(regErr)
		return
	}
	sq := ring.GetSQE()
	if sq == nil {
		t.Error("SQE is nil")
		return
	}
	sts := syscall.NsecToTimespec((10 * time.Millisecond).Nanoseconds())
	sq.PrepareTimeout(&sts, 1, 0)
	sq.SetData64(1)

	cts := syscall.NsecToTimespec((100 * time.Millisecond).Nanoseconds())
	minTimeout := 1 * time.Second
	now := time.Now()
	cqe, submitErr := ring.SubmitAndWaitMinTimeout(1, &cts, minTimeout, nil)
	t.Log("wait latency:", time.Since(now))
	if submitErr != nil {
		t.Error(submitErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.UserData)
	ring.CQAdvance(1)
}

func TestRing_MSGRing(t *testing.T) {
	flags := liburing.IORING_SETUP_COOP_TASKRUN |
		liburing.IORING_SETUP_TASKRUN_FLAG |
		liburing.IORING_SETUP_SINGLE_ISSUER |
		liburing.IORING_SETUP_DEFER_TASKRUN
	r1, r1Err := liburing.New(liburing.WithEntries(4), liburing.WithFlags(flags))
	if r1Err != nil {
		t.Error(r1Err)
		return
	}
	defer r1.Close()

	_, reg1Err := r1.RegisterRingFd()
	if reg1Err != nil {
		t.Error(reg1Err)
		return
	}
	t.Log("register ring fd success:", r1.Fd())

	r2, r2Err := liburing.New(liburing.WithEntries(4))
	if r2Err != nil {
		t.Error(r2Err)
		return
	}
	defer r2.Close()

	_, reg2Err := r2.RegisterRingFd()
	if reg2Err != nil {
		t.Error(reg2Err)
		return
	}
	t.Log("register ring fd success:", r2.Fd())

	sqe := r1.GetSQE()
	sqe.PrepareMsgRingCQEFlags(r2.Fd(), 1, nil, 0, 3)
	sqe.SetData(unsafe.Pointer(uintptr(r1.Fd())))
	_, swErr := r1.SubmitAndWait(1)
	if swErr != nil {
		t.Error(swErr)
		return
	}
	ts := syscall.NsecToTimespec(time.Duration(1 * time.Millisecond).Nanoseconds())
	cqe, cqeErr := r1.WaitCQEsMinTimeout(10, &ts, 10*time.Microsecond, nil)
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.UserData)

	cqe, cqeErr = r2.WaitCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("cqe:", cqe.Res, cqe.Flags)

}

func TestMsgRingFd(t *testing.T) {
	flags := liburing.IORING_SETUP_COOP_TASKRUN |
		liburing.IORING_SETUP_TASKRUN_FLAG |
		liburing.IORING_SETUP_SINGLE_ISSUER |
		liburing.IORING_SETUP_DEFER_TASKRUN
	r1, r1Err := liburing.New(liburing.WithEntries(4), liburing.WithFlags(flags))
	if r1Err != nil {
		t.Error(r1Err)
		return
	}
	defer r1.Close()

	_, reg1Err := r1.RegisterRingFd()
	if reg1Err != nil {
		t.Error(reg1Err)
		return
	}
	t.Log("register ring fd success:", r1.Fd())

	_, _ = r1.RegisterFilesSparse(10)

	r2, r2Err := liburing.New(liburing.WithEntries(4))
	if r2Err != nil {
		t.Error(r2Err)
		return
	}
	defer r2.Close()

	_, reg2Err := r2.RegisterRingFd()
	if reg2Err != nil {
		t.Error(reg2Err)
		return
	}
	t.Log("register ring fd success:", r2.Fd())

	_, _ = r2.RegisterFilesSparse(10)

	var sqe *liburing.SubmissionQueueEntry
	var cqe *liburing.CompletionQueueEvent
	var cqeErr error
	var sock1 int
	for i := 0; i < 2; i++ {
		sqe = r1.GetSQE()
		sqe.PrepareSocketDirectAlloc(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, syscall.IPPROTO_TCP, 0)
		_, _ = r1.SubmitAndWait(1)
		cqe, cqeErr = r1.WaitCQE()
		if cqeErr != nil {
			t.Error(cqeErr)
			return
		}
		sock1 = int(cqe.Res)
		r1.CQAdvance(1)
		t.Log("sock1:", sock1)
	}
	for i := 0; i < 3; i++ {
		sqe = r2.GetSQE()
		sqe.PrepareSocketDirectAlloc(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, syscall.IPPROTO_TCP, 0)
		_, _ = r2.SubmitAndWait(1)
		cqe, cqeErr = r2.WaitCQE()
		if cqeErr != nil {
			t.Error(cqeErr)
			return
		}
		r2.CQAdvance(1)
		t.Log("sock2:", int(cqe.Res))
	}

	now := time.Now()

	sqe = r1.GetSQE()
	sqe.PrepareMsgRingFdAlloc(r2.Fd(), int(sock1), unsafe.Pointer(&now), 0)
	_, _ = r1.SubmitAndWait(1)
	cqe, cqeErr = r1.WaitCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("r1 socket:", cqe.Res)
	r1.CQAdvance(1)

	cqe, cqeErr = r2.WaitCQE()
	if cqeErr != nil {
		t.Error(cqeErr)
		return
	}
	t.Log("r2 socket:", cqe.Res, *(*time.Time)(cqe.GetData()))
	r2.CQAdvance(1)
}
