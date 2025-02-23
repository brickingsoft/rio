package rio

import (
	"github.com/brickingsoft/errors"
	"github.com/brickingsoft/rio/pkg/aio"
	"github.com/brickingsoft/rio/pkg/process"
	"github.com/brickingsoft/rxp"
	"github.com/brickingsoft/rxp/pkg/maxprocs"
	"runtime"
	"sync"
	"time"
)

var (
	startupOnce  = sync.Once{}
	shutdownOnce = sync.Once{}
)

// Startup
// 启动
//
// rio 是基于 rxp.Executors 与 aio.Engine 的异步编程模式。
// 提供默认值，如果需要定制化，则使用 Startup 完成。
//
// 注意：必须在程序起始位置调用，否则无效。
func Startup(options ...StartupOption) {
	startupOnce.Do(func() {
		opts := &StartupOptions{
			ProcessPriorityLevel: 0,
			AIOOptions: aio.Options{
				CylindersLoadBalance:  aio.RoundRobin,
				CylindersLockOSThread: true,
				Settings:              nil,
			},
			ExecutorsOptions: nil,
		}
		for _, option := range options {
			if err := option(opts); err != nil {
				panic(errors.New("startup failed", errors.WithMeta(errMetaPkgKey, errMetaPkgVal), errors.WithWrap(err)))
				return
			}
		}
		// process
		if opts.ProcessPriorityLevel != process.NORM {
			if err := process.SetCurrentProcessPriority(opts.ProcessPriorityLevel); err != nil {
				panic(errors.New("startup failed", errors.WithMeta(errMetaPkgKey, errMetaPkgVal), errors.WithWrap(err)))
				return
			}
		}
		// executors
		var err error
		executors, err = rxp.New(opts.ExecutorsOptions...)
		if err != nil {
			panic(errors.New("startup failed", errors.WithMeta(errMetaPkgKey, errMetaPkgVal), errors.WithWrap(err)))
			return
		}
		// aio.completions
		aio.Startup(opts.AIOOptions)
	})
	return
}

// Shutdown
// 优雅关闭。
//
// 会等待所有协程执行完毕。
func Shutdown() {
	shutdownOnce.Do(func() {
		exec := getExecutors()
		runtime.SetFinalizer(exec, nil)
		_ = exec.Close()
		aio.Shutdown()
	})
}

type StartupOptions struct {
	ProcessPriorityLevel process.PriorityLevel
	AIOOptions           aio.Options
	ExecutorsOptions     []rxp.Option
}

type StartupOption func(*StartupOptions) error

// WithProcessRealtimePriorityClass
// 设置进程优先级为实时，该程序需要对应的权限。
func WithProcessRealtimePriorityClass() StartupOption {
	return func(o *StartupOptions) error {
		o.ProcessPriorityLevel = process.REALTIME
		return nil
	}
}

// WithProcessHighPriorityClass
// 设置进程优先级为高，该程序需要对应的权限。
func WithProcessHighPriorityClass() StartupOption {
	return func(o *StartupOptions) error {
		o.ProcessPriorityLevel = process.HIGH
		return nil
	}
}

// WithProcessIdlePriorityClass
// 设置进程优先级为闲置，该程序需要对应的权限。
func WithProcessIdlePriorityClass() StartupOption {
	return func(o *StartupOptions) error {
		o.ProcessPriorityLevel = process.IDLE
		return nil
	}
}

// WithMinGOMAXPROCS
// 最小 GOMAXPROCS 值，只在 linux 环境下有效。一般用于 docker 容器环境。
func WithMinGOMAXPROCS(n int) StartupOption {
	return func(o *StartupOptions) error {
		o.ExecutorsOptions = append(o.ExecutorsOptions, rxp.WithMinGOMAXPROCS(n))
		return nil
	}
}

// WithProcs
// 设置最大 GOMAXPROCS 构建函数。
func WithProcs(fn maxprocs.ProcsFunc) StartupOption {
	return func(o *StartupOptions) error {
		o.ExecutorsOptions = append(o.ExecutorsOptions, rxp.WithProcs(fn))
		return nil
	}
}

// WithRoundQuotaFunc
// 设置整数配额函数
func WithRoundQuotaFunc(fn maxprocs.RoundQuotaFunc) StartupOption {
	return func(o *StartupOptions) error {
		o.ExecutorsOptions = append(o.ExecutorsOptions, rxp.WithRoundQuotaFunc(fn))
		return nil
	}
}

// WithMaxGoroutines
// 设置最大协程数
func WithMaxGoroutines(n int) StartupOption {
	return func(o *StartupOptions) error {
		o.ExecutorsOptions = append(o.ExecutorsOptions, rxp.WithMaxGoroutines(n))
		return nil
	}
}

// WithMaxReadyGoroutinesIdleDuration
// 设置准备中协程最大闲置时长
func WithMaxReadyGoroutinesIdleDuration(d time.Duration) StartupOption {
	return func(o *StartupOptions) error {
		o.ExecutorsOptions = append(o.ExecutorsOptions, rxp.WithMaxReadyGoroutinesIdleDuration(d))
		return nil
	}
}

// WithShutdownTimeout
// 设置关闭超时时长
func WithShutdownTimeout(d time.Duration) StartupOption {
	return func(o *StartupOptions) error {
		o.ExecutorsOptions = append(o.ExecutorsOptions, rxp.WithCloseTimeout(d))
		return nil
	}
}

// WithAIOEngineCylinders
// 设置 AIO LOOP 数。
func WithAIOEngineCylinders(n int) StartupOption {
	return func(o *StartupOptions) error {
		if n > 1 {
			o.AIOOptions.Cylinders = n
		}
		return nil
	}
}

// WithAIOEngineCylindersLockOSThread
// 设置 AIO LOOP 是否独占线程。默认为独占模式。
func WithAIOEngineCylindersLockOSThread(lockOSThread bool) StartupOption {
	return func(o *StartupOptions) error {
		o.AIOOptions.CylindersLockOSThread = lockOSThread
		return nil
	}
}

// WithAIOEngineCylindersLoadBalance
// 设置 AIO LOOP 组的负载均衡。默认为 aio.RoundRobin，aio.Least（windows不适用） 可选。
func WithAIOEngineCylindersLoadBalance(rb aio.LoadBalanceKind) StartupOption {
	return func(o *StartupOptions) error {
		o.AIOOptions.CylindersLoadBalance = rb
		return nil
	}
}
