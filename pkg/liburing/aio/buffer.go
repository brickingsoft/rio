//go:build linux

package aio

import (
	"io"
	"time"
	"unsafe"

	"github.com/brickingsoft/rio/pkg/liburing"
)

type BufferAndRing struct {
	bgid        uint16
	mask        uint16
	count       uint16
	size        uint32
	lastUseTime time.Time
	value       *liburing.BufferAndRing
	buffer      []byte
}

func (br *BufferAndRing) Id() uint16 {
	return br.bgid
}

func (br *BufferAndRing) WriteTo(bid uint16, n int, writer io.Writer) {
	var (
		size = int(br.size)
		beg  = 0
		end  = 0
	)

	if n == 0 {
		beg = int(bid) * size
		end = beg + size
		b := br.buffer[beg:end]
		br.value.BufRingAdd(unsafe.Pointer(&b[0]), br.size, bid, br.mask, 0)
		br.value.BufRingAdvance(1)
		return
	}

	for n > 0 {
		beg = int(bid) * size
		if size > n {
			end = beg + n
			b := br.buffer[beg:end]
			_, _ = writer.Write(b)
			b = br.buffer[beg : beg+size]
			br.value.BufRingAdd(unsafe.Pointer(&b[0]), br.size, bid, br.mask, 0)
			br.value.BufRingAdvance(1)
			break
		}
		end = beg + size
		b := br.buffer[beg:end]
		_, _ = writer.Write(b)

		br.value.BufRingAdd(unsafe.Pointer(&b[0]), br.size, bid, br.mask, 0)
		br.value.BufRingAdvance(1)

		bid = (bid + 1) & br.mask
		n -= size
	}
	return
}

func (br *BufferAndRing) BufferOfBid(bid uint16) (b []byte) {
	var (
		bed = int(bid) * int(br.size)
		end = bed + int(br.size)
	)
	b = br.buffer[bed:end]
	return
}

func (br *BufferAndRing) Advance(bid uint16) {
	var (
		size = int(br.size)
		beg  = int(bid) * size
		end  = beg + size
	)
	b := br.buffer[beg:end]
	br.value.BufRingAdd(unsafe.Pointer(&b[0]), br.size, bid, br.mask, 0)
	br.value.BufRingAdvance(1)
}
