package security

import (
	"context"
	"crypto/tls"
	"github.com/brickingsoft/rio/pkg/aio"
)

func Server(ctx context.Context, fd aio.NetFd, config *tls.Config) (conn Connection, err error) {
	return
}
