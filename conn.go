package rio

import (
	"net"
)

// Conn is a generic stream-oriented network connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn interface {
	net.Conn
	// SetSocketOptInt set socket option, the func is limited to SOL_SOCKET level.
	SetSocketOptInt(level int, optName int, optValue int) (err error)
	// GetSocketOptInt get socket option, the func is limited to SOL_SOCKET level.
	GetSocketOptInt(level int, optName int) (optValue int, err error)
}
