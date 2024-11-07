package rio

import (
	"crypto/tls"
	"runtime"
	"time"
)

const (
	InfiniteConnections = int64(0)
)

type Options struct {
	minGOMAXPROCS           int
	parallelAcceptors       int
	maxConnections          int64
	maxExecutors            int
	maxExecutorIdleDuration time.Duration
	tlsConfig               *tls.Config
	multipathTCP            bool
	proto                   int
	pollers                 int
}

type Option func(options *Options) (err error)

func WithMinGOMAXPROCS(min int) Option {
	return func(options *Options) (err error) {
		if min > 2 {
			options.minGOMAXPROCS = min
		}
		return
	}
}

func WithParallelAcceptors(parallelAcceptors int) Option {
	return func(options *Options) (err error) {
		cpuNum := runtime.NumCPU() * 2
		if parallelAcceptors < 1 || cpuNum < parallelAcceptors {
			parallelAcceptors = cpuNum
		}
		options.parallelAcceptors = parallelAcceptors
		return
	}
}

func WithMaxConnections(maxConnections int64) Option {
	return func(options *Options) (err error) {
		if maxConnections > 0 {
			options.maxConnections = maxConnections
		}
		return
	}
}

func WithTLSConfig(config *tls.Config) Option {
	return func(options *Options) (err error) {
		options.tlsConfig = config
		return
	}
}
func WithMultipathTCP() Option {
	return func(options *Options) (err error) {
		options.multipathTCP = true
		return
	}
}

func WithProto(proto int) Option {
	return func(options *Options) (err error) {
		options.proto = proto
		return
	}
}

func WithPollers(pollers int) Option {
	return func(options *Options) (err error) {
		options.pollers = pollers
		return
	}
}

func WithMaxExecutors(maxExecutors int) Option {
	return func(options *Options) (err error) {
		options.maxExecutors = maxExecutors
		return
	}
}

func WithMaxExecutorIdleDuration(duration time.Duration) Option {
	return func(options *Options) (err error) {
		options.maxExecutorIdleDuration = duration
		return
	}
}
