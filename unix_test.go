package rio_test

import (
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/brickingsoft/rio"
)

func TestUnix(t *testing.T) {
	addr := fmt.Sprintf("%s/rio_unix_%d.sock", os.TempDir(), time.Now().Unix())
	t.Log("addr:", addr)
	defer func() {
		t.Log("rm addr:", os.Remove(addr))
	}()

	ln, lnErr := rio.Listen("unix", addr)
	if lnErr != nil {
		t.Error(lnErr)
		return
	}
	wg := new(sync.WaitGroup)
	defer wg.Wait()

	defer func() {
		err := ln.Close()
		if err != nil {
			t.Error(err)
		}
		return
	}()

	wg.Add(1)
	go func(ln net.Listener, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				t.Error("accept", err)
				return
			}
			t.Log("srv:", conn.LocalAddr(), conn.RemoteAddr())
			b := make([]byte, 1024)
			rn, rErr := conn.Read(b)
			t.Log("srv read", rn, string(b[:rn]), rErr)
			if rErr != nil {
				_ = conn.Close()
				return
			}
			wn, wErr := conn.Write(b[:rn])
			t.Log("srv write", wn, wErr)
			_ = conn.Close()
			return
		}
	}(ln, wg)

	conn, connErr := rio.Dial("unix", addr)
	if connErr != nil {
		t.Error(connErr)
		return
	}
	t.Log("cli:", conn.LocalAddr(), conn.RemoteAddr())
	defer conn.Close()

	wn, wErr := conn.Write([]byte("hello world"))
	if wErr != nil {
		t.Error(wErr)
		return
	}
	t.Log("cli write:", wn)

	b := make([]byte, 1024)
	rn, rErr := conn.Read(b)
	t.Log("cli read", rn, string(b[:rn]), rErr)
	if rErr != nil {
		t.Error(rErr)
		return
	}
}

func TestUnixgram(t *testing.T) {
	raddr := fmt.Sprintf("%s/rio_unixgram_r_%d.sock", os.TempDir(), time.Now().Unix())
	laddr := fmt.Sprintf("%s/rio_unixgram_l_%d.sock", os.TempDir(), time.Now().Unix())
	t.Log("srv addr:", raddr, "cli addr:", laddr)
	defer func() {
		t.Log("rm raddr:", os.Remove(raddr))
	}()
	defer func() {
		t.Log("rm laddr:", os.Remove(laddr))
	}()

	srv, srvErr := rio.ListenPacket("unixgram", raddr)
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
		rn, addr, rErr := srv.ReadFrom(b)
		t.Log("srv read", rn, string(b[:rn]), addr, rErr)
		if rErr != nil {
			_ = conn.Close()
			return
		}
		wn, wErr := conn.WriteTo(b[:rn], addr)
		t.Log("srv write", wn, wErr)
		_ = conn.Close()
		t.Log("srv done")
		return
	}(srv, wg)

	cua, _ := net.ResolveUnixAddr("unixgram", laddr)
	sua, _ := net.ResolveUnixAddr("unixgram", raddr)

	cli, cliErr := rio.DialUnix("unixgram", cua, sua)
	if cliErr != nil {
		t.Error(cliErr)
		return
	}
	t.Log("cli:", cli.LocalAddr(), cli.RemoteAddr())

	wn, wErr := cli.Write([]byte("hello world"))
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
	cli.Close()
	t.Log("cli done")
	wg.Wait()
	t.Log("fin")
}
