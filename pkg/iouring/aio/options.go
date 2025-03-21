package aio

import (
	"strings"
	"time"
)

type Options struct {
	Entries                    uint32
	Flags                      uint32
	SQThreadCPU                uint32
	SQThreadIdle               uint32
	RegisterFixedBufferSize    uint32
	RegisterFixedBufferCount   uint32
	RegisterFixedFiles         uint32
	RegisterReservedFixedFiles uint32
	PrepSQEBatchSize           uint32
	PrepSQEBatchTimeWindow     time.Duration
	PrepSQEBatchIdleTime       time.Duration
	PrepSQEBatchAffCPU         int
	WaitCQEMode                string
	WaitCQEBatchSize           uint32
	WaitCQEBatchTimeCurve      Curve
	AttachRingFd               int
}

type Option func(*Options)

// WithAttach
// attach ring.
// see https://manpages.debian.org/unstable/liburing-dev/io_uring_setup.2.en.html#IORING_SETUP_ATTACH_WQ.
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

const (
	defaultSQThreadIdle = 10000
)

// WithSQThreadIdle
// setup iouring's sq thread idle, the unit is millisecond.
func WithSQThreadIdle(idle time.Duration) Option {
	return func(opts *Options) {
		if idle < time.Millisecond {
			idle = defaultSQThreadIdle * time.Millisecond
		}
		opts.SQThreadIdle = uint32(idle.Milliseconds())
	}
}

// WithPrepSQEBatchSize
// setup size of batch preparing sqe.
func WithPrepSQEBatchSize(size uint32) Option {
	return func(opts *Options) {
		opts.PrepSQEBatchSize = size
	}
}

const (
	WaitCQEEventMode = "EVENT"
	WaitCQEBatchMode = "BATCH"
)

// WithWaitCQEMode
// setup mode of wait cqe, default is [WaitCQEEventMode]
func WithWaitCQEMode(mode string) Option {
	return func(opts *Options) {
		mode = strings.ToUpper(strings.TrimSpace(mode))
		if mode == WaitCQEEventMode || mode == WaitCQEBatchMode {
			opts.WaitCQEMode = mode
		}
	}
}

const (
	defaultPrepSQEBatchTimeWindow = 100 * time.Microsecond
)

// WithPrepSQEBatchTimeWindow
// setup time window of batch preparing sqe.
func WithPrepSQEBatchTimeWindow(window time.Duration) Option {
	return func(opts *Options) {
		if window < 1 {
			window = defaultPrepSQEBatchTimeWindow
		}
		opts.PrepSQEBatchTimeWindow = window
	}
}

const (
	defaultPrepSQEBatchIdleTime = 30 * time.Second
)

// WithPrepSQEBatchIdleTime
// setup idle time of batch preparing sqe.
func WithPrepSQEBatchIdleTime(d time.Duration) Option {
	return func(opts *Options) {
		if d < 1 {
			d = defaultPrepSQEBatchIdleTime
		}
		opts.PrepSQEBatchIdleTime = d
	}
}

// WithPrepSQEBatchAFFCPU
// setup affinity cpu of preparing sqe.
func WithPrepSQEBatchAFFCPU(cpu int) Option {
	return func(opts *Options) {
		opts.PrepSQEBatchAffCPU = cpu
	}
}

// WithWaitCQEBatchSize
// setup size of batch waiting cqe.
func WithWaitCQEBatchSize(size uint32) Option {
	return func(opts *Options) {
		opts.WaitCQEBatchSize = size
	}
}

// WithWaitCQEBatchTimeCurve
// setup time curve of batch waiting cqe.
func WithWaitCQEBatchTimeCurve(curve Curve) Option {
	return func(opts *Options) {
		opts.WaitCQEBatchTimeCurve = curve
	}
}

// WithRegisterFixedBuffer
// setup register fixed buffer of iouring.
func WithRegisterFixedBuffer(size uint32, count uint32) Option {
	return func(opts *Options) {
		if size == 0 || count == 0 {
			return
		}
		opts.RegisterFixedBufferSize = size
		opts.RegisterFixedBufferCount = count
	}
}

// WithRegisterFixedFiles
// setup register fixed fd of iouring.
func WithRegisterFixedFiles(files uint32) Option {
	return func(opts *Options) {
		opts.RegisterFixedFiles = files
	}
}

// WithRegisterReservedFixedFiles
// setup  register reserved fixed fd of iouring.
func WithRegisterReservedFixedFiles(files uint32) Option {
	return func(opts *Options) {
		opts.RegisterReservedFixedFiles = files
	}
}
