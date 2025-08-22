package rio_test

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/brickingsoft/rio"
)

func TestUDP(t *testing.T) {
	srv, srvErr := rio.ListenPacket("udp", ":9000")
	if srvErr != nil {
		t.Error(srvErr)
		return
	}

	wg := new(sync.WaitGroup)

	wg.Add(1)
	go func(conn net.PacketConn, wg *sync.WaitGroup) {
		defer wg.Done()
		t.Log("srv:", conn.LocalAddr())
		b := make([]byte, 1024)

		for {
			rn, addr, rErr := conn.ReadFrom(b)
			t.Log("srv read", rn, string(b[:rn]), addr)
			if rErr != nil {
				if !errors.Is(rErr, net.ErrClosed) {
					t.Error("srv read failed:", rErr)
				}
				break
			}
			wn, wErr := conn.WriteTo(b[:rn], addr)
			t.Log("srv write", wn)
			if wErr != nil {
				if !errors.Is(wErr, net.ErrClosed) {
					t.Error("srv write failed:", rErr)
				}
				break
			}
		}
		_ = conn.Close()
		t.Log("srv done")
		return
	}(srv, wg)

	cli, cliErr := rio.Dial("udp", "127.0.0.1:9000")
	if cliErr != nil {
		t.Error(cliErr)
		return
	}
	t.Log("cli:", cli.LocalAddr(), cli.RemoteAddr())

	for i := 0; i < 32; i++ {
		wn, wErr := cli.Write([]byte("hello world > " + strconv.Itoa(i)))
		if wErr != nil {
			cli.Close()
			t.Error(wErr)
			return
		}
		t.Log("cli write:", wn)

		b := make([]byte, 1024)
		rn, rErr := cli.Read(b)
		t.Log("cli read", rn, string(b[:rn]), rErr)
		if rErr != nil {
			cli.Close()
			t.Error(rErr)
			return
		}
	}

	cli.Close()
	t.Log("cli done")

	srv.Close()
	wg.Wait()
	t.Log("fin")
}

func TestUDPConn_ReadMsgUDP(t *testing.T) {
	srv, srvErr := rio.ListenPacket("udp", ":9000")
	if srvErr != nil {
		t.Error(srvErr)
		return
	}

	wg := new(sync.WaitGroup)

	wg.Add(1)
	go func(conn *rio.UDPConn, wg *sync.WaitGroup) {
		defer wg.Done()
		t.Log("srv:", conn.LocalAddr())
		b := make([]byte, 1024)
		oob := make([]byte, 128)
		for {
			rn, oobN, flags, addr, rErr := conn.ReadMsgUDP(b, oob)
			t.Log("srv read", rn, oobN, flags, string(b[:rn]), addr)
			if rErr != nil {
				if !errors.Is(rErr, net.ErrClosed) {
					t.Error("srv read failed:", rErr)
				}
				break
			}
			wn, wErr := conn.WriteTo(b[:rn], addr)
			t.Log("srv write", wn)
			if wErr != nil {
				if !errors.Is(wErr, net.ErrClosed) {
					t.Error("srv write failed:", rErr)
				}
				break
			}
		}
		_ = conn.Close()
		t.Log("srv done")
		return
	}(srv.(*rio.UDPConn), wg)

	cli, cliErr := rio.Dial("udp", "127.0.0.1:9000")
	if cliErr != nil {
		t.Error(cliErr)
		return
	}
	t.Log("cli:", cli.LocalAddr(), cli.RemoteAddr())

	for i := 0; i < 32; i++ {
		wn, wErr := cli.Write([]byte("hello world > " + strconv.Itoa(i)))
		if wErr != nil {
			cli.Close()
			t.Error(wErr)
			return
		}
		t.Log("cli write:", wn)

		b := make([]byte, 1024)
		rn, rErr := cli.Read(b)
		t.Log("cli read", rn, string(b[:rn]), rErr)
		if rErr != nil {
			cli.Close()
			t.Error(rErr)
			return
		}
	}

	cli.Close()
	t.Log("cli done")

	srv.Close()
	wg.Wait()
	t.Log("fin")

}
