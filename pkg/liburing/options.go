//go:build linux

package liburing

import "errors"

type Options struct {
	Entries      uint32
	Flags        uint32
	SQThreadCPU  uint32
	SQThreadIdle uint32
	WQFd         uint32
	MemoryBuffer []byte
}

type Option func(*Options) error

const (
	MaxEntries     = 32768
	DefaultEntries = MaxEntries / 2
)

func WithEntries(entries uint32) Option {
	return func(o *Options) error {
		if entries > MaxEntries {
			return errors.New("entries too big")
		}
		if entries < 1 {
			entries = DefaultEntries
		}
		o.Entries = entries
		return nil
	}
}

// WithFlags
// see https://man.archlinux.org/listing/extra/liburing/
func WithFlags(flags uint32) Option {
	return func(o *Options) error {
		o.Flags |= flags
		return nil
	}
}

func WithSQThreadIdle(n uint32) Option {
	return func(o *Options) error {
		o.SQThreadIdle = n
		return nil
	}
}

func WithSQThreadCPU(cpuId uint32) Option {
	return func(o *Options) error {
		o.SQThreadCPU = cpuId
		return nil
	}
}

func WithAttachWQFd(fd uint32) Option {
	return func(o *Options) error {
		if fd == 0 {
			return errors.New("invalid wqfd")
		}
		o.WQFd = fd
		if o.Flags&IORING_SETUP_ATTACH_WQ == 0 {
			o.Flags |= IORING_SETUP_ATTACH_WQ
		}
		return nil
	}
}

func WithMemoryBuffer(memoryBuffer []byte) Option {
	return func(o *Options) error {
		o.MemoryBuffer = memoryBuffer
		return nil
	}
}
