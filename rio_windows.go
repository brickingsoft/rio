//go:build windows

package rio

import "github.com/brickingsoft/rio/pkg/aio"

type IOCPSettings struct {
	aio.IOCPSettings
}

// WithIOCPSettings
// 设置 IOCP
func WithIOCPSettings(settings IOCPSettings) StartupOption {
	return func(o *StartupOptions) error {
		o.AIOOptions.Settings = settings.IOCPSettings
		return nil
	}
}
