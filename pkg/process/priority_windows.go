//go:build windows

package process

import (
	"errors"

	"golang.org/x/sys/windows"
)

func SetCurrentProcessPriority(level PriorityLevel) (err error) {
	pid := windows.CurrentProcess()
	n := uint32(0)
	switch level {
	case REALTIME:
		n = windows.REALTIME_PRIORITY_CLASS
		break
	case HIGH:
		n = windows.HIGH_PRIORITY_CLASS
		break
	case NORM:
		n = windows.NORMAL_PRIORITY_CLASS
		break
	case IDLE:
		n = windows.IDLE_PRIORITY_CLASS
		break
	default:
		return errors.New("invalid priority level")
	}
	err = windows.SetPriorityClass(pid, n)
	return
}
