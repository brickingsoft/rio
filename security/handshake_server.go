package security

import (
	"context"
	"crypto/tls"
	"github.com/brickingsoft/rio/transport"
	"github.com/brickingsoft/rxp/async"
)

func ServerHandshake(ctx context.Context, conn transport.Connection, config *tls.Config) (future async.Future[HandshakeResult]) {

	return
}
