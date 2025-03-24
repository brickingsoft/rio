//go:build linux

package process

import (
	"golang.org/x/sys/unix"
	"runtime"
)

// SetCPUAffinity 亲和CPU
func SetCPUAffinity(index int) error {
	var newMask unix.CPUSet

	newMask.Zero()

	cpuIndex := (index) % (runtime.NumCPU())
	newMask.Set(cpuIndex)
	pid := unix.Getpid()
	return unix.SchedSetaffinity(pid, &newMask)
}

// MaskCPU 屏蔽CPU
func MaskCPU(index int) error {
	var mask unix.CPUSet
	mask.Zero()
	for i := 0; i < runtime.NumCPU(); i++ {
		if i != index { // 允许所有 CPU，除了 index
			mask.Set(i)
		}
	}
	pid := unix.Getpid()
	return unix.SchedSetaffinity(pid, &mask)
}
