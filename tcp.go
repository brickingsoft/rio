package rio

import (
	"context"
	"github.com/brickingsoft/rio/pkg/aio"
	"time"
)

type KeepAliveConfig struct {
	Enable   bool
	Idle     time.Duration
	Interval time.Duration
	Count    int
}

type TCPConnection interface {
	Connection
	MultipathTCP() bool
	SetNoDelay(noDelay bool) (err error)
	SetLinger(sec int) (err error)
	SetKeepAlive(keepalive bool) (err error)
	SetKeepAlivePeriod(period time.Duration) (err error)
	SetKeepAliveConfig(config KeepAliveConfig) (err error)
}

func newTCPConnection(ctx context.Context, fd aio.NetFd) (conn TCPConnection) {
	c := newConnection(ctx, fd)
	conn = &tcpConnection{
		connection: *c,
	}
	return
}

type tcpConnection struct {
	connection
}

func (conn *tcpConnection) MultipathTCP() bool {
	return aio.IsUsingMultipathTCP(conn.fd)
}

func (conn *tcpConnection) SetNoDelay(noDelay bool) (err error) {
	err = aio.SetNoDelay(conn.fd, noDelay)
	return
}

func (conn *tcpConnection) SetLinger(sec int) (err error) {
	err = aio.SetLinger(conn.fd, sec)
	return
}

func (conn *tcpConnection) SetKeepAlive(keepalive bool) (err error) {
	err = aio.SetKeepAlive(conn.fd, keepalive)
	return
}

func (conn *tcpConnection) SetKeepAlivePeriod(period time.Duration) (err error) {
	err = aio.SetKeepAlivePeriod(conn.fd, period)
	return
}

func (conn *tcpConnection) SetKeepAliveConfig(config KeepAliveConfig) (err error) {
	err = aio.SetKeepAliveConfig(conn.fd, aio.KeepAliveConfig{
		Enable:   config.Enable,
		Idle:     config.Idle,
		Interval: config.Interval,
		Count:    config.Count,
	})
	return
}
