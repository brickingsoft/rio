//go:build linux

package sys

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// MaskCPU 屏蔽CPU
func MaskCPU(index int) error {
	var mask unix.CPUSet
	mask.Zero()
	cpuIndex := (index) % (runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		if i != cpuIndex { // 允许所有 CPU，除了 index
			mask.Set(i)
		}
	}
	pid := unix.Getpid()
	return unix.SchedSetaffinity(pid, &mask)
}

// AffCPU 亲和CPU
func AffCPU(index int) error {
	var newMask unix.CPUSet
	newMask.Zero()
	cpuIndex := (index) % (runtime.NumCPU())
	newMask.Set(cpuIndex)
	pid := unix.Getpid()
	return unix.SchedSetaffinity(pid, &newMask)
}
