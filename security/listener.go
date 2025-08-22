package security

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/brickingsoft/rio"
)

func NewListener(inner net.Listener, config *tls.Config) net.Listener {
	return tls.NewListener(inner, config)
}

func Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := rio.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}
