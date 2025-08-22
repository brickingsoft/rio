//go:build linux

package sys

import (
	"os"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	skfAdOffPlusKSkfAdCPU = 4294963236
	cpuIdSize             = 4
)

func NewCBPFFilter(cpus uint32) CBPFFilter {
	return CBPFFilter{
		bpf.LoadAbsolute{Off: skfAdOffPlusKSkfAdCPU, Size: cpuIdSize},
		bpf.ALUOpConstant{Op: bpf.ALUOpMod, Val: cpus},
		bpf.RetA{},
	}
}

type CBPFFilter []bpf.Instruction

func (f CBPFFilter) Program() (program *unix.SockFprog, err error) {
	var (
		assembled []bpf.RawInstruction
	)

	if assembled, err = bpf.Assemble(f); err != nil {
		return
	}
	program = &unix.SockFprog{
		Len:    uint16(len(assembled)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&assembled[0])),
	}
	return
}

func (f CBPFFilter) ApplyTo(fd int) error {
	program, programErr := f.Program()
	if programErr != nil {
		return programErr
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_CBPF, program); err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}
