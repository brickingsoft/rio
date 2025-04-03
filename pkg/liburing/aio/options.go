package aio

import (
	"time"
)

type Options struct {
	Entries                 uint32
	Flags                   uint32
	SQThreadCPU             uint32
	SQThreadIdle            uint32
	SendZC                  bool
	KernelFlavorBlackList   []string
	RegisterFixedFiles      uint32
	BufferAndRingConfig     BufferAndRingConfig
	ProducerLockOSThread    bool
	ProducerBatchSize       uint32
	ProducerBatchTimeWindow time.Duration
	ProducerBatchIdleTime   time.Duration
	ConsumeBatchTimeCurve   Curve
	HeartbeatTimeout        time.Duration
	AttachRingFd            int
}

type Option func(*Options)

// WithAttach
// attach ring.
// see https://man.archlinux.org/man/extra/liburing/io_uring_setup.2.en#IORING_SETUP_ATTACH_WQ.
func WithAttach(v *Vortex) Option {
	return func(o *Options) {
		if v == nil {
			return
		}
		fd := v.Fd()
		if fd < 1 {
			return
		}
		o.AttachRingFd = fd
	}
}

// WithEntries
// setup iouring's entries.
func WithEntries(entries uint32) Option {
	return func(opts *Options) {
		opts.Entries = entries
	}
}

// WithFlags
// setup iouring's flags.
// see https://man.archlinux.org/listing/extra/liburing/
func WithFlags(flags uint32) Option {
	return func(opts *Options) {
		opts.Flags |= flags
	}
}

// WithSQThreadCPU
// setup iouring's sq thread cpu.
func WithSQThreadCPU(cpuId uint32) Option {
	return func(opts *Options) {
		opts.SQThreadCPU = cpuId
	}
}

// WithSQThreadIdle
// setup iouring's sq thread idle, the unit is millisecond.
func WithSQThreadIdle(idle time.Duration) Option {
	return func(opts *Options) {
		if idle < time.Millisecond {
			idle = 10000 * time.Millisecond
		}
		opts.SQThreadIdle = uint32(idle.Milliseconds())
	}
}

// WithSendZC
// setup to use send_zc and sendmsg_zc op insteadof send and sendmsg
func WithSendZC(ok bool) Option {
	return func(options *Options) {
		options.SendZC = ok
	}
}

// WithRingBufferConfig
// setup buffer and ring config
func WithRingBufferConfig(size uint16, count uint16, reference uint16, idleTimeout time.Duration) Option {
	return func(opts *Options) {
		opts.BufferAndRingConfig = BufferAndRingConfig{
			Size:        size,
			Count:       count,
			Reference:   reference,
			IdleTimeout: idleTimeout,
		}
	}
}

// WithKernelFlavorBlackList
// setup disable iouring direct alloc feat kernel flavor black list.
func WithKernelFlavorBlackList(list []string) Option {
	return func(opts *Options) {
		opts.KernelFlavorBlackList = list
	}
}

// WithProducer setup operation producer
func WithProducer(osThreadLock bool, batch uint32, batchTimeWindow time.Duration, batchIdleTimeout time.Duration) Option {
	return func(opts *Options) {
		opts.ProducerLockOSThread = osThreadLock
		opts.ProducerBatchSize = batch
		opts.ProducerBatchTimeWindow = batchTimeWindow
		opts.ProducerBatchIdleTime = batchIdleTimeout
	}
}

// WithConsumer setup operation consumer
func WithConsumer(curve Curve) Option {
	return func(opts *Options) {
		opts.ConsumeBatchTimeCurve = curve
	}
}

// WithRegisterFixedFiles
// setup register fixed fd of iouring.
func WithRegisterFixedFiles(files uint32) Option {
	return func(opts *Options) {
		opts.RegisterFixedFiles = files
	}
}

// WithHeartBeatTimeout
// setup heartbeat timeout.
func WithHeartBeatTimeout(d time.Duration) Option {
	return func(opts *Options) {
		opts.HeartbeatTimeout = d
	}
}
