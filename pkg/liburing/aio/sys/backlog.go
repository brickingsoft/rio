//go:build linux

package sys

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/brickingsoft/rio/pkg/liburing"
)

var (
	somaxconn   = syscall.SOMAXCONN
	backlogOnce = sync.Once{}
)

func countAnyByte(s string, t string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(t, s[i]) >= 0 {
			n++
		}
	}
	return n
}

func splitAtBytes(s string, t string) []string {
	a := make([]string, 1+countAnyByte(s, t))
	n := 0
	last := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(t, s[i]) >= 0 {
			if last < i {
				a[n] = s[last:i]
				n++
			}
			last = i + 1
		}
	}
	if last < len(s) {
		a[n] = s[last:]
		n++
	}
	return a[0:n]
}

func getFields(s string) []string { return splitAtBytes(s, " \r\t\n") }

const big = 0xFFFFFF

func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

func MaxListenerBacklog() int {
	backlogOnce.Do(func() {
		fd, err := os.Open("/proc/sys/net/core/somaxconn")
		if err != nil {
			return
		}
		defer func() {
			_ = fd.Close()
		}()
		rd := bufio.NewReader(fd)

		l, readLineErr := rd.ReadString('\n')
		if readLineErr != nil {
			return
		}
		f := getFields(l)
		n, _, ok := dtoi(f[0])
		if n == 0 || !ok {
			return
		}

		if n > 1<<16-1 {
			somaxconn = maxAckBacklog(n)
			return
		}
	})
	return somaxconn
}

func maxAckBacklog(n int) int {
	size := 16
	if liburing.VersionEnable(4, 1, 0) {
		size = 32
	}
	var maxAck uint = 1<<size - 1
	if uint(n) > maxAck {
		n = int(maxAck)
	}
	return n
}
