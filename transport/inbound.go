package transport

import (
	"errors"
	"github.com/brickingsoft/rio/pkg/bytebufferpool"
)

type InboundReader interface {
	Peek(n int) (p []byte)
	Next(n int) (p []byte, err error)
	Read(p []byte) (n int, err error)
	Discard(n int)
	Length() (n int)
}

type InboundBuffer interface {
	InboundReader
	Allocate(size int) (p []byte, err error)
	AllocatedWrote(n int)
	Write(p []byte) (n int, err error)
	Close()
}

func NewInboundBuffer() InboundBuffer {
	return new(inboundBuffer)
}

type inboundBuffer struct {
	b bytebufferpool.Buffer
}

func (buf *inboundBuffer) Allocate(size int) (p []byte, err error) {
	if buf.b == nil {
		buf.b = bytebufferpool.Get()
	}
	if buf.b.WritePending() {
		err = errors.New("transport: buffer already allocated a piece bytes")
		return
	}
	p = buf.b.Allocate(size)
	return
}

func (buf *inboundBuffer) AllocatedWrote(n int) {
	if buf.b != nil {
		buf.b.AllocatedWrote(n)
	}
}

func (buf *inboundBuffer) Write(p []byte) (n int, err error) {
	if buf.b == nil {
		buf.b = bytebufferpool.Get()
	}
	n, err = buf.b.Write(p)
	return
}

func (buf *inboundBuffer) Close() {
	if buf.b != nil {
		if buf.b.WritePending() {
			buf.b.AllocatedWrote(0)
		}
		bytebufferpool.Put(buf.b)
		buf.b = nil
	}
}

func (buf *inboundBuffer) Peek(n int) (p []byte) {
	if buf.b == nil {
		return
	}
	p = buf.b.Peek(n)
	return
}

func (buf *inboundBuffer) Next(n int) (p []byte, err error) {
	if buf.b == nil {
		return
	}
	p, err = buf.b.Next(n)
	if buf.b.Len() == 0 && !buf.b.WritePending() {
		bytebufferpool.Put(buf.b)
		buf.b = nil
	}
	return
}

func (buf *inboundBuffer) Read(p []byte) (n int, err error) {
	if buf.b == nil {
		return
	}
	n, err = buf.b.Read(p)
	if buf.b.Len() == 0 && !buf.b.WritePending() {
		bytebufferpool.Put(buf.b)
		buf.b = nil
	}
	return
}

func (buf *inboundBuffer) Discard(n int) {
	if buf.b == nil {
		return
	}
	buf.b.Discard(n)
	if buf.b.Len() == 0 {
		bytebufferpool.Put(buf.b)
		buf.b = nil
	}
	return
}

func (buf *inboundBuffer) Length() (n int) {
	if buf.b == nil {
		return
	}
	n = buf.b.Len()
	return
}
