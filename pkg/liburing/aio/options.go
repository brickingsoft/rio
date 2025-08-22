package aio

import (
	"errors"
	"math"
	"os"
	"time"

	"github.com/brickingsoft/rio/pkg/liburing"
)

var (
	presetOptions []Option
)

func Preset(options ...Option) {
	presetOptions = append(presetOptions, options...)
}

type BufferAndRingConfig struct {
	Size        int
	Count       int
	IdleTimeout time.Duration
}

const (
	maxBufferSize = int(^uint(0) >> 1)
)

func (config *BufferAndRingConfig) Validate() (err error) {
	size := config.Size
	if size < 1 {
		size = os.Getpagesize()
	}
	if size > math.MaxUint16 {
		err = errors.New("buffer size too big")
		return
	}
	config.Size = size

	count := config.Count
	if count == 0 {
		count = 16
	}
	count = int(liburing.RoundupPow2(uint32(count)))
	if count > 32768 {
		err = errors.New("count is too large for buffer and ring, max count is 32768")
		return
	}
	config.Count = count

	bLen := size * count
	if bLen > maxBufferSize {
		err = errors.New("size and count are too large for buffer and ring")
		return
	}

	if config.IdleTimeout < 1 {
		config.IdleTimeout = 15 * time.Second
	}
	return
}

type Options struct {
	Entries             uint32
	Flags               uint32
	SQThreadIdle        uint32
	SQThreadCPU         uint32
	SendZCEnabled       bool
	MultishotDisabled   bool
	NAPIBusyPollTimeout time.Duration
	BufferAndRingConfig BufferAndRingConfig
	WaitCQETimeoutCurve Curve
}

type Option func(*Options)

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

// WithSendZCEnabled
// setup to use send_zc and sendmsg_zc op insteadof send and sendmsg
func WithSendZCEnabled(enabled bool) Option {
	return func(options *Options) {
		options.SendZCEnabled = enabled
	}
}

// WithMultishotDisabled
// setup to disable multishot
func WithMultishotDisabled(disabled bool) Option {
	return func(options *Options) {
		options.MultishotDisabled = disabled
	}
}

// WithBufferAndRingConfig
// setup buffer and ring config
func WithBufferAndRingConfig(size int, count int, idleTimeout time.Duration) Option {
	return func(opts *Options) {
		if size < 0 {
			size = 0
		}
		opts.BufferAndRingConfig.Size = size
		if count < 0 {
			count = 0
		}
		opts.BufferAndRingConfig.Count = count
		if idleTimeout < 0 {
			idleTimeout = 0
		}
		opts.BufferAndRingConfig.IdleTimeout = idleTimeout
	}
}

// WithWaitCQETimeoutCurve
// setup wait cqe time curve
func WithWaitCQETimeoutCurve(curve Curve) Option {
	return func(opts *Options) {
		opts.WaitCQETimeoutCurve = curve
	}
}

// WithNAPIBusyPollTimeout
// setup napi busy poll timeout to register napi, effective in kernel versions higher than 6.8
func WithNAPIBusyPollTimeout(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.NAPIBusyPollTimeout = timeout
	}
}
