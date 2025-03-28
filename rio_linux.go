//go:build linux

package rio

import (
	"github.com/brickingsoft/rio/pkg/liburing"
	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"github.com/brickingsoft/rio/pkg/reference"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Pin() {
	rc, rcErr := getVortex()
	if rcErr != nil {
		panic(rcErr)
		return
	}
	rc.Pin()
}

func Unpin() {
	rc, rcErr := getVortex()
	if rcErr != nil {
		panic(rcErr)
		return
	}
	rc.Unpin()
}

var (
	vortexInstanceErr  error
	vortexInstanceOnce sync.Once
)

const (
	envEntries                            = "RIO_IOURING_ENTRIES"
	envFlags                              = "RIO_IOURING_SETUP_FLAGS"
	envSQThreadCPU                        = "RIO_IOURING_SQ_THREAD_CPU"
	envSQThreadIdle                       = "RIO_IOURING_SQ_THREAD_IDLE"
	envSendZC                             = "RIO_IOURING_SENDZC"
	envDisableIOURingDirectAllocBlackList = "RIO_IOURING_DISABLE_IOURING_DIRECT_ALLOC_BLACKLIST"
	envRegisterFixedFiles                 = "RIO_IOURING_REG_FIXED_FILES"
	envIOURingHeartbeatTimeout            = "RIO_IOURING_HEARTBEAT_TIMEOUT"
	envSQEProducerLockOSThread            = "RIO_PRODUCER_LOCK_OSTHREAD"
	envSQEProducerBatchSize               = "RIO_PRODUCER_BATCH_SIZE"
	envSQEProducerBatchTimeWindow         = "RIO_PRODUCER_BATCH_TIME_WINDOW"
	envSQEProducerBatchIdleTime           = "RIO_PRODUCER_BATCH_IDLE_TIME"
	envCQEConsumerType                    = "RIO_CONSUMER_TYPE"
	envCQEPullTypedConsumeTimeCurve       = "RIO_PULL_TYPED_CONSUMER_CURVE"
	envCQEPullTypedConsumeIdleTime        = "RIO_PULL_TYPED_CONSUMER_IDLE_TIME"
)

func getVortex() (*reference.Pointer[*aio.Vortex], error) {
	vortexInstanceOnce.Do(func() {
		if len(vortexInstanceOptions) == 0 { // use env
			vortexInstanceOptions = make([]aio.Option, 0, 1)

			// ring >>>
			if v, has := envLoadUint32(envEntries); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithEntries(v))
			}

			if v, has := envLoadFlags(envFlags); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithFlags(v))
			} else {
				if cpus := runtime.NumCPU(); cpus > 1 { // use sq_poll
					v = liburing.IORING_SETUP_SQPOLL | liburing.IORING_SETUP_SINGLE_ISSUER
					if cpus > 3 {
						v |= liburing.IORING_SETUP_SQ_AFF
					}
				} else { // use coop task run
					v = liburing.IORING_SETUP_COOP_TASKRUN | liburing.IORING_SETUP_TASKRUN_FLAG
				}
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithFlags(v))
			}

			if v, has := envLoadUint32(envSQThreadCPU); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSQThreadCPU(v))
			}
			if v, has := envLoadDuration(envSQThreadIdle); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSQThreadIdle(v))
			}
			if ok := envLoadBool(envSendZC); ok {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSendZC(ok))
			}
			if v, has := envLoadStrings(envDisableIOURingDirectAllocBlackList); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithDisableDirectAllocFeatKernelFlavorBlackList(v))
			} else {
				v = []string{"microsoft-standard-WSL2"}
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithDisableDirectAllocFeatKernelFlavorBlackList(v))
			}
			// ring <<<

			// fixed >>>
			if v, has := envLoadUint32(envRegisterFixedFiles); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithRegisterFixedFiles(v))
			}
			// fixed <<<

			// heartbeat
			if v, has := envLoadDuration(envIOURingHeartbeatTimeout); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithHeartBeatTimeout(v))
			}

			// sqe >>>
			if v := envLoadBool(envSQEProducerLockOSThread); v {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSQEProducerLockOSThread(v))
			}

			if v, has := envLoadUint32(envSQEProducerBatchSize); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSQEProducerBatchSize(v))
			}
			if v, has := envLoadDuration(envSQEProducerBatchTimeWindow); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSQEProducerBatchTimeWindow(v))
			}
			if v, has := envLoadDuration(envSQEProducerBatchIdleTime); has {
				vortexInstanceOptions = append(vortexInstanceOptions, aio.WithSQEProducerBatchIdleTime(v))
			}
			// sqe <<<

			// cqe >>>
			cqeConsumerType, _ := envLoadString(envCQEConsumerType)
			cqeConsumerType = strings.ToUpper(strings.TrimSpace(cqeConsumerType))
			if cqeConsumerType == aio.CQEConsumerPushType {
				aio.WithCQEPushTypedConsumer()
			} else {
				curve, _ := envLoadCurve(envCQEPullTypedConsumeTimeCurve)
				idleTimeout, _ := envLoadDuration(envCQEPullTypedConsumeIdleTime)
				aio.WithCQEPullTypedConsumer(curve, idleTimeout)
			}
			// cqe <<<

		}
		// open
		vortex, vortexErr := aio.Open(vortexInstanceOptions...)
		if vortexErr != nil {
			vortexInstanceErr = vortexErr
			return
		}
		vortexInstance = reference.Make(vortex)
	})
	return vortexInstance, vortexInstanceErr
}

func envLoadString(name string) (string, bool) {
	s, has := os.LookupEnv(name)
	if !has {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func envLoadUint32(name string) (uint32, bool) {
	s, has := os.LookupEnv(name)
	if !has {
		return 0, false
	}
	u, parseErr := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if parseErr != nil {
		return 0, false
	}
	return uint32(u), true
}

func envLoadBool(name string) bool {
	s, has := os.LookupEnv(name)
	if !has {
		return false
	}
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "1", "y", "yes":
		return true
	default:
		return false
	}
}

func envLoadFlags(name string) (uint32, bool) {
	s, has := os.LookupEnv(name)
	if !has {
		return 0, false
	}
	flags := uint32(0)
	ss := strings.Split(s, ",")
	for _, s0 := range ss {
		parsed := liburing.ParseSetupFlags(s0)
		if parsed > 0 {
			flags |= parsed
		}
	}
	return flags, true
}

func envLoadStrings(name string) ([]string, bool) {
	s, has := os.LookupEnv(name)
	if !has {
		return nil, false
	}
	ss := strings.Split(s, ",")
	for i := range ss {
		ss[i] = strings.TrimSpace(ss[i])
	}
	return ss, len(ss) > 0
}

func envLoadDuration(name string) (time.Duration, bool) {
	s, has := os.LookupEnv(name)
	if !has {
		return 0, false
	}
	d, parseErr := time.ParseDuration(strings.TrimSpace(s))
	if parseErr != nil {
		return 0, false
	}
	return d, true
}

func envLoadCurve(name string) (aio.Curve, bool) {
	s, has := os.LookupEnv(name)
	if !has {
		return nil, false
	}
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	ss := strings.Split(s, ",")
	curve := make(aio.Curve, 0, 1)
	for _, s0 := range ss {
		i := strings.Index(s0, ":")
		if i == -1 {
			return nil, false
		}
		ns := strings.TrimSpace(s0[:i])
		n, nErr := strconv.ParseUint(ns, 10, 32)
		if nErr != nil {
			return nil, false
		}
		ts := strings.TrimSpace(s0[i+1:])
		t, tErr := time.ParseDuration(ts)
		if tErr != nil {
			return nil, false
		}
		curve = append(curve, struct {
			N       uint32
			Timeout time.Duration
		}{N: uint32(n), Timeout: t})
	}
	return curve, true
}
