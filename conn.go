package rio

import (
	"github.com/brickingsoft/rio/pkg/liburing/aio"
	"net"
)

// Conn is a generic stream-oriented network connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn interface {
	net.Conn
	// Fd export aio net fd.
	Fd() (*aio.NetFd, error)
	// SetSocketOptInt set socket option, the func is limited to SOL_SOCKET level.
	SetSocketOptInt(level int, optName int, optValue int) (err error)
	// GetSocketOptInt get socket option, the func is limited to SOL_SOCKET level.
	GetSocketOptInt(level int, optName int) (optValue int, err error)
}
