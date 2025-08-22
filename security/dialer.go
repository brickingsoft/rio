package security

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/brickingsoft/rio"
)

func DialWithDialer(dialer *rio.Dialer, network string, address string, config *tls.Config) (*tls.Conn, error) {
	return DialContextWithDialer(context.Background(), dialer, network, address, config)
}

func DialContextWithDialer(ctx context.Context, dialer *rio.Dialer, network string, address string, config *tls.Config) (*tls.Conn, error) {
	return dial(ctx, dialer, network, address, config)
}

func Dial(network string, address string, config *tls.Config) (*tls.Conn, error) {
	return DialContextWithDialer(context.Background(), &rio.DefaultDialer, network, address, config)
}

func DialContext(ctx context.Context, network string, address string, config *tls.Config) (net.Conn, error) {
	return DialContextWithDialer(ctx, &rio.DefaultDialer, network, address, config)
}

func DialTimeout(network string, address string, timeout time.Duration, config *tls.Config) (net.Conn, error) {
	dialer := rio.DefaultDialer
	dialer.Timeout = timeout
	return DialWithDialer(&dialer, network, address, config)
}

func DialContextTimeout(ctx context.Context, network string, address string, timeout time.Duration, config *tls.Config) (net.Conn, error) {
	dialer := rio.DefaultDialer
	dialer.Timeout = timeout
	return DialContextWithDialer(ctx, &dialer, network, address, config)
}

func dial(ctx context.Context, netDialer *rio.Dialer, network, address string, config *tls.Config) (*tls.Conn, error) {
	rawConn, err := netDialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(address, ":")
	if colonPos == -1 {
		colonPos = len(address)
	}
	hostname := address[:colonPos]

	if config == nil {
		config = &tls.Config{}
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}
	// conn
	conn := tls.Client(rawConn, config)
	// handshake
	var handshakeCtx context.Context
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}
	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}
	if handshakeErr := conn.HandshakeContext(handshakeCtx); handshakeErr != nil {
		_ = rawConn.Close()
		return nil, handshakeErr
	}
	return conn, nil
}
