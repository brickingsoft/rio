package codec

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/brickingsoft/rio/transport"
	"github.com/brickingsoft/rxp/async"
	"io"
)

func LengthFieldDecode(ctx context.Context, reader transport.Reader, lengthFieldSize int, options ...async.Option) (future async.Future[[]byte]) {
	decoder := NewLengthFieldEncoder(lengthFieldSize)
	future = Decode[[]byte](ctx, reader, decoder, options...)
	return
}

func LengthFieldEncode(ctx context.Context, writer transport.Writer, b []byte, lengthFieldSize int) (future async.Future[int]) {
	encoder := NewLengthFieldEncoder(lengthFieldSize)
	encoded, encodeErr := encoder.Encode(b)
	if encodeErr != nil {
		future = async.FailedImmediately[int](ctx, encodeErr)
		return
	}
	future = writer.Write(encoded)
	return
}

func NewLengthFieldEncoder(lengthFieldSize int) *LengthFieldEncoder {
	if lengthFieldSize <= 0 {
		panic("codec.NewLengthFieldEncoder: length field size must be > 0")
		return nil
	}
	return &LengthFieldEncoder{
		lengthFieldSize: lengthFieldSize,
	}
}

type LengthFieldEncoder struct {
	lengthFieldSize int
}

func (encoder *LengthFieldEncoder) Decode(reader transport.Inbound) (ok bool, message []byte, err error) {
	bufLen := reader.Len()
	if bufLen < encoder.lengthFieldSize {
		// not full
		return
	}

	lengthField := reader.Peek(encoder.lengthFieldSize)
	size := int(binary.BigEndian.Uint64(lengthField))
	if size == 0 {
		// decoded but content size is zero
		// so discard length field
		reader.Discard(encoder.lengthFieldSize)
		ok = true
		return
	}
	if bufLen-encoder.lengthFieldSize < size {
		// not full
		return
	}
	pLen := encoder.lengthFieldSize + size
	p := make([]byte, pLen)
	rn, readErr := reader.Read(p)
	if readErr != nil {
		err = readErr
		return
	}
	if rn != pLen {
		err = io.ErrShortBuffer
		return
	}
	message = p[encoder.lengthFieldSize:]
	ok = true
	return
}

func (encoder *LengthFieldEncoder) Encode(p []byte) (b []byte, err error) {
	pLen := len(p)
	if pLen == 0 {
		err = errors.New("codec.LengthFieldEncoder: empty packet")
		return
	}
	b = make([]byte, encoder.lengthFieldSize+pLen)
	binary.BigEndian.PutUint64(b, uint64(pLen))
	copy(b[encoder.lengthFieldSize:], p)
	return
}
