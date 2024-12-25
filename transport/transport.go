package transport

import (
	"github.com/brickingsoft/rxp/async"
	"net"
	"time"
)

type Reader interface {
	Read() (future async.Future[Inbound])
}

type Writer interface {
	Write(b []byte) (future async.Future[int])
}

type Closer interface {
	Close() (future async.Future[async.Void])
}

type ReadWriter interface {
	Reader
	Writer
}

type Transport interface {
	Reader
	Writer
	Closer
}

type TimeoutReader interface {
	Reader
	SetReadTimeout(d time.Duration) (err error)
}

type TimeoutWriter interface {
	Reader
	SetWriteTimeout(d time.Duration) (err error)
}

type PacketReader interface {
	ReadFrom() (future async.Future[PacketInbound])
}

type PacketWriter interface {
	WriteTo(b []byte, addr net.Addr) (future async.Future[int])
}

type PacketReadWriter interface {
	PacketReader
	PacketWriter
}

type PacketTransport interface {
	PacketReader
	PacketWriter
	Closer
}
