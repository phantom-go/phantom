package relay

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a, <-ch
}

// client <-> [x | Pipe | y] <-> server
func setup(t *testing.T, idle time.Duration) (client, server net.Conn, done chan [2]int64) {
	client, x := tcpPair(t)
	y, server := tcpPair(t)
	done = make(chan [2]int64, 1)
	go func() {
		a, b := Pipe(x, y, idle)
		x.Close()
		y.Close()
		done <- [2]int64{a, b}
	}()
	return client, server, done
}

func TestPipeBidirectionalIntegrity(t *testing.T) {
	client, server, done := setup(t, time.Minute)
	defer client.Close()
	defer server.Close()

	up := make([]byte, 3<<20)
	down := make([]byte, 5<<20)
	rand.Read(up)
	rand.Read(down)

	go func() {
		client.Write(up)
		client.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		server.Write(down)
		server.(*net.TCPConn).CloseWrite()
	}()

	var gotUp, gotDown []byte
	r := make(chan struct{})
	go func() { gotUp, _ = io.ReadAll(server); close(r) }()
	gotDown, _ = io.ReadAll(client)
	<-r

	if !bytes.Equal(gotUp, up) || !bytes.Equal(gotDown, down) {
		t.Fatalf("payload mismatch: up %d/%d down %d/%d", len(gotUp), len(up), len(gotDown), len(down))
	}
	n := <-done
	if n[0] != int64(len(up)) || n[1] != int64(len(down)) {
		t.Fatalf("byte counts %v", n)
	}
}

// A one-directional transfer that lasts far longer than the idle window
// must NOT be cut (the old absolute deadline killed it).
func TestPipeActiveTransferOutlivesIdleWindow(t *testing.T) {
	const idle = 200 * time.Millisecond
	client, server, done := setup(t, idle)
	defer client.Close()
	defer server.Close()

	go func() {
		for i := 0; i < 20; i++ { // ~1s total, 5x the idle window
			if _, err := server.Write([]byte("tick")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		server.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 80 {
		t.Fatalf("transfer cut short: got %d bytes, want 80", len(got))
	}
	client.(*net.TCPConn).CloseWrite()
	<-done
}

func TestPipeIdleConnectionIsReaped(t *testing.T) {
	client, server, done := setup(t, 150*time.Millisecond)
	defer client.Close()
	defer server.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("silent connection was not reaped by idle timeout")
	}
}

func BenchmarkPipe(b *testing.B) {
	benchCopy(b, func(x, y net.Conn) { Pipe(x, y, DefaultIdleTimeout) })
}

// BenchmarkIoCopyPair is the previous implementation, for comparison.
func BenchmarkIoCopyPair(b *testing.B) {
	benchCopy(b, func(x, y net.Conn) {
		d := make(chan struct{}, 2)
		go func() { io.Copy(y, onlyRW{x}); d <- struct{}{} }()
		go func() { io.Copy(x, onlyRW{y}); d <- struct{}{} }()
		<-d
	})
}

// onlyRW hides ReaderFrom/WriterTo exactly like the project's wrapper types.
type onlyRW struct{ io.ReadWriter }

func benchCopy(b *testing.B, pipe func(x, y net.Conn)) {
	payload := make([]byte, 256<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cx, x := net.Pipe()
		y, sy := net.Pipe()
		go func() { pipe(onlyConn{x}, onlyConn{y}); x.Close(); y.Close() }()
		go func() { io.Copy(io.Discard, sy) }()
		cx.Write(payload)
		cx.Close()
		sy.Close()
	}
}

type onlyConn struct{ net.Conn }
