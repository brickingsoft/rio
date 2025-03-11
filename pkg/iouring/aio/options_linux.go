//go:build linux

package aio

import (
	"github.com/brickingsoft/rio/pkg/iouring"
)

func defaultIOURingSetupFlags() uint32 {
	return iouring.SetupSQAff
}

func performanceIOURingSetupFlags() uint32 {
	return iouring.SetupSQPoll | iouring.SetupSQAff
}
