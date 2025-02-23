package aio

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
)

type Options struct {
	// Cylinders
	// 引擎规模
	Cylinders int
	// CylindersLockOSThread
	// 是否独占线程
	CylindersLockOSThread bool
	// CylindersLoadBalance
	// 负载均衡器。 RoundRobin 和 Least。
	CylindersLoadBalance LoadBalanceKind
	// Settings
	// AIO配置设置
	Settings any
}

func ResolveSettings[T any](settings any) T {
	if settings == nil {
		return *new(T)
	}
	s, ok := settings.(T)
	if !ok {
		panic(fmt.Errorf("aio: cannot resolve %s settings from %s", reflect.TypeOf(*new(T)), reflect.TypeOf(settings)))
	}
	return s
}

type Cylinder interface {
	Fd() int
	Loop()
	Stop()
	Actives() int64
}

type LoadBalanceKind int

const (
	RoundRobin LoadBalanceKind = iota
	Least
)

func newEngine(options Options) *Engine {
	cylinders := options.Cylinders
	if cylinders < 1 {
		cylinders = runtime.NumCPU()
	}
	_engine = &Engine{
		fd:                    0,
		settings:              options.Settings,
		cylindersLoadBalancer: options.CylindersLoadBalance,
		cylindersLockOSThread: options.CylindersLockOSThread,
		cylindersIdx:          -1,
		cylindersNum:          int64(cylinders),
		cylinders:             make([]Cylinder, cylinders),
		wg:                    sync.WaitGroup{},
		lock:                  sync.Mutex{},
		running:               false,
	}
	return _engine
}

type Engine struct {
	fd                    int
	settings              any
	cylindersLoadBalancer LoadBalanceKind
	cylindersLockOSThread bool
	cylindersIdx          int64
	cylindersNum          int64
	cylinders             []Cylinder
	wg                    sync.WaitGroup
	lock                  sync.Mutex
	running               bool
	startupErr            error
}

func (engine *Engine) stopped() bool {
	engine.lock.Lock()
	defer engine.lock.Unlock()
	return !engine.running
}

func (engine *Engine) next() Cylinder {
	if !engine.running {
		err := errors.New("aio: engine not running")
		if engine.startupErr != nil {
			err = errors.Join(err, engine.startupErr)
		}
		panic(err)
		return nil
	}
	switch engine.cylindersLoadBalancer {
	case Least:
		idx := 0
		actives := int64(0)
		for i, c := range engine.cylinders {
			n := c.Actives()
			if n < 1 {
				idx = i
				break
			}
			if n < actives || actives == 0 {
				actives = n
				idx = i
			}
		}
		return engine.cylinders[idx]
	default:
		// RoundRobin
		idx := atomic.AddInt64(&engine.cylindersIdx, 1) % engine.cylindersNum
		return engine.cylinders[idx]
	}
}

var (
	_createEngineOnce         = sync.Once{}
	_engine           *Engine = nil
	_defaultOptions           = Options{
		Cylinders:             0,
		CylindersLoadBalance:  RoundRobin,
		CylindersLockOSThread: true,
		Settings:              nil,
	}
)

func Startup(options Options) {
	_createEngineOnce.Do(func() {
		_engine = newEngine(options)
		_engine.Start()
	})
}

func Shutdown() {
	if _engine != nil {
		_engine.Stop()
		runtime.KeepAlive(_engine)
	}
}

func engine() *Engine {
	_createEngineOnce.Do(func() {
		if _engine == nil {
			_engine = newEngine(_defaultOptions)
			_engine.Start()
			runtime.SetFinalizer(_engine, (*Engine).Stop)
		}
	})
	return _engine
}

func nextCylinder() Cylinder {
	return engine().next()
}
