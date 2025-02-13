//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package rio

import (
	"github.com/brickingsoft/rio/pkg/aio"
	"time"
)

type KqueueSettings struct {
	aio.KqueueSettings
}

// WithKqueueSettings
// 设置 Kqueue。
func WithKqueueSettings(settings KqueueSettings) StartupOption {
	return func(o *StartupOptions) error {
		o.AIOOptions.Settings = settings.KqueueSettings
		return nil
	}
}

// WithSampleKqueueSettings
// 简单设置 Kqueue。
//
// changeQueueSize 是 kqueue 的changes 的 buffer 大小，默认为 2^15。
func WithSampleKqueueSettings(changeQueueSize int) StartupOption {
	return func(o *StartupOptions) error {
		if changeQueueSize < 1 {
			changeQueueSize = 16384
		}
		o.AIOOptions.Settings = aio.KqueueSettings{
			ChangesQueueSize:     changeQueueSize,
			ChangesPeekBatchSize: changeQueueSize,
			EventsWaitBatchSize:  changeQueueSize,
			EventsWaitTimeout:    time.Millisecond,
		}
		return nil
	}
}
