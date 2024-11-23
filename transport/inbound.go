package transport

import (
	"errors"
	"github.com/brickingsoft/rio/pkg/bytebuffers"
	"io"
)

type InboundReader interface {
	Peek(n int) (p []byte)
	Next(n int) (p []byte, err error)
	Read(p []byte) (n int, err error)
	Discard(n int)
	Length() (n int)
	ReadBytes(delim byte) (line []byte, err error)
	Index(delim byte) (i int)
}

type InboundBuffer interface {
	InboundReader
	Allocate(size int) (p []byte, err error)
	AllocatedWrote(n int) (err error)
	Write(p []byte) (n int, err error)
	Close()
}

func NewInboundBuffer() InboundBuffer {
	return new(inboundBuffer)
}

func getBuffer() bytebuffers.Buffer {
	return bytebuffers.Get()
}

func putBuffer(buf bytebuffers.Buffer) {
	bytebuffers.Put(buf)
}

type inboundBuffer struct {
	b bytebuffers.Buffer
}

func (buf *inboundBuffer) ReadBytes(delim byte) (line []byte, err error) {
	if buf.b == nil {
		err = io.EOF
		return
	}
	line, err = buf.b.ReadBytes(delim)
	return
}

func (buf *inboundBuffer) Index(delim byte) (i int) {
	if buf.b == nil {
		i = -1
		return
	}
	i = buf.b.Index(delim)
	return
}

func (buf *inboundBuffer) Allocate(size int) (p []byte, err error) {
	if buf.b == nil {
		buf.b = getBuffer()
	}
	if buf.b.WritePending() {
		err = errors.New("transport: buffer already allocated a piece bytes")
		return
	}
	p, err = buf.b.Allocate(size)
	return
}

func (buf *inboundBuffer) AllocatedWrote(n int) (err error) {
	if buf.b != nil {
		err = buf.b.AllocatedWrote(n)
	}
	return
}

func (buf *inboundBuffer) Write(p []byte) (n int, err error) {
	if buf.b == nil {
		buf.b = getBuffer()
	}
	n, err = buf.b.Write(p)
	return
}

func (buf *inboundBuffer) Close() {
	if buf.b != nil {
		if buf.b.WritePending() {
			_ = buf.b.AllocatedWrote(0)
		}
		putBuffer(buf.b)
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
		putBuffer(buf.b)
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
		putBuffer(buf.b)
		buf.b = nil
	}
	return
}

func (buf *inboundBuffer) Discard(n int) {
	if buf.b == nil {
		return
	}
	_ = buf.b.Discard(n)
	if buf.b.Len() == 0 {
		putBuffer(buf.b)
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
