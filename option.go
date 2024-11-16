package rio

import (
	"crypto/tls"
	"github.com/brickingsoft/rio/pkg/sockets"
	"github.com/brickingsoft/rxp"
	"github.com/brickingsoft/rxp/pkg/maxprocs"
	"net"
	"runtime"
	"time"
)

const (
	DefaultMaxConnections                   = int64(0)
	DefaultMaxConnectionsLimiterWaitTimeout = 500 * time.Millisecond
)

type Options struct {
	ExecutorsOptions                 rxp.Options
	ExtraExecutors                   rxp.Executors
	ParallelAcceptors                int
	MaxConnections                   int64
	MaxConnectionsLimiterWaitTimeout time.Duration
	TLSConfig                        *tls.Config
	MultipathTCP                     bool
	DialPacketConnLocalAddr          net.Addr
	UnixListenerUnlinkOnClose        bool
	DefaultStreamReadTimeout         time.Duration
	DefaultStreamWriteTimeout        time.Duration
}

func (options *Options) AsRxpOptions() []rxp.Option {
	opts := make([]rxp.Option, 0, 1)
	if n := options.ExecutorsOptions.MaxprocsOptions.MinGOMAXPROCS; n > 0 {
		opts = append(opts, rxp.MinGOMAXPROCS(n))
	}
	if fn := options.ExecutorsOptions.MaxprocsOptions.Procs; fn != nil {
		opts = append(opts, rxp.Procs(fn))
	}
	if fn := options.ExecutorsOptions.MaxprocsOptions.RoundQuotaFunc; fn != nil {
		opts = append(opts, rxp.RoundQuotaFunc(fn))
	}
	if n := options.ExecutorsOptions.MaxGoroutines; n > 0 {
		opts = append(opts, rxp.MaxGoroutines(n))
	}
	if n := options.ExecutorsOptions.MaxReadyGoroutinesIdleDuration; n > 0 {
		opts = append(opts, rxp.MaxReadyGoroutinesIdleDuration(n))
	}
	if n := options.ExecutorsOptions.CloseTimeout; n > 0 {
		opts = append(opts, rxp.WithCloseTimeout(n))
	}
	return opts
}

type Option func(options *Options) (err error)

// WithExtraExecutors
// 设置外部 rxp.Executors
func WithExtraExecutors(executor rxp.Executors) Option {
	return func(options *Options) (err error) {
		options.ExtraExecutors = executor
		return
	}
}

// WithParallelAcceptors
// 设置并行链接接受器数量。
//
// 默认值为 runtime.NumCPU() * 2。
// 注意：当值大于 Options.MaxConnections，即 WithMaxConnections 所设置的值。
// 则并行链接接受器数为最大链接数。
func WithParallelAcceptors(parallelAcceptors int) Option {
	return func(options *Options) (err error) {
		cpuNum := runtime.NumCPU() * 2
		if parallelAcceptors < 1 || cpuNum < parallelAcceptors {
			parallelAcceptors = cpuNum
		}
		options.ParallelAcceptors = parallelAcceptors
		return
	}
}

// WithMaxConnections
// 设置最大链接数。默认为0即无上限。
func WithMaxConnections(maxConnections int64) Option {
	return func(options *Options) (err error) {
		if maxConnections > 0 {
			options.MaxConnections = maxConnections
		}
		return
	}
}

// WithMaxConnectionsLimiterWaitTimeout
// 设置最大链接数限制器等待超时。默认为500毫秒。
//
// 当10次都没新链接，当前协程会被挂起。
func WithMaxConnectionsLimiterWaitTimeout(maxConnectionsLimiterWaitTimeout time.Duration) Option {
	return func(options *Options) (err error) {
		if maxConnectionsLimiterWaitTimeout > 0 {
			options.MaxConnectionsLimiterWaitTimeout = maxConnectionsLimiterWaitTimeout
		}
		return
	}
}

// WithTLSConfig
// 设置TLS
func WithTLSConfig(config *tls.Config) Option {
	return func(options *Options) (err error) {
		options.TLSConfig = config
		return
	}
}

// WithMultipathTCP
// 设置多路TCP
func WithMultipathTCP() Option {
	return func(options *Options) (err error) {
		options.MultipathTCP = true
		return
	}
}

// WithDialPacketConnLocalAddr
// 设置包链接拨号器的本地地址
func WithDialPacketConnLocalAddr(network string, addr string) Option {
	return func(options *Options) (err error) {
		options.DialPacketConnLocalAddr, _, _, err = sockets.GetAddrAndFamily(network, addr)
		return
	}
}

// WithMinGOMAXPROCS
// 最小 GOMAXPROCS 值，只在 linux 环境下有效。一般用于 docker 容器环境。
func WithMinGOMAXPROCS(n int) Option {
	return func(options *Options) error {
		return rxp.MinGOMAXPROCS(n)(&options.ExecutorsOptions)
	}
}

// WithProcsFunc
// 设置最大 GOMAXPROCS 构建函数。
func WithProcsFunc(fn maxprocs.ProcsFunc) Option {
	return func(options *Options) error {
		return rxp.Procs(fn)(&options.ExecutorsOptions)
	}
}

// WithRoundQuotaFunc
// 设置整数配额函数
func WithRoundQuotaFunc(fn maxprocs.RoundQuotaFunc) Option {
	return func(options *Options) error {
		return rxp.RoundQuotaFunc(fn)(&options.ExecutorsOptions)
	}
}

// WithMaxGoroutines
// 设置最大协程数
func WithMaxGoroutines(n int) Option {
	return func(options *Options) error {
		return rxp.MaxGoroutines(n)(&options.ExecutorsOptions)
	}
}

// WithMaxReadyGoroutinesIdleDuration
// 设置准备中协程最大闲置时长
func WithMaxReadyGoroutinesIdleDuration(d time.Duration) Option {
	return func(options *Options) error {
		return rxp.MaxReadyGoroutinesIdleDuration(d)(&options.ExecutorsOptions)
	}
}

// WithCloseTimeout
// 设置关闭超时时长
func WithCloseTimeout(timeout time.Duration) Option {
	return func(options *Options) error {
		return rxp.WithCloseTimeout(timeout)(&options.ExecutorsOptions)
	}
}

// WithUnixListenerUnlinkOnClose
// 设置unix监听器是否在关闭时取消地址链接。用于链接型地址。
func WithUnixListenerUnlinkOnClose() Option {
	return func(options *Options) (err error) {
		options.UnixListenerUnlinkOnClose = true
		return
	}
}

// WithDefaultStreamReadTimeout
// 设置默认流链接读超时。
func WithDefaultStreamReadTimeout(d time.Duration) Option {
	return func(options *Options) (err error) {
		if d > 0 {
			options.DefaultStreamReadTimeout = d
		}
		return
	}
}

// WithDefaultStreamWriteTimeout
// 设置默认流链接写超时。
func WithDefaultStreamWriteTimeout(d time.Duration) Option {
	return func(options *Options) (err error) {
		if d > 0 {
			options.DefaultStreamWriteTimeout = d
		}
		return
	}
}
