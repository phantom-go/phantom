package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/phantom-go/phantom/internal/auth"
	"github.com/phantom-go/phantom/internal/logger"
	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/protocol"
	"github.com/phantom-go/phantom/internal/transport"
)

const testPassword = "correct horse battery staple"

type harness struct {
	addr     string
	echoPort uint16
	echo6    uint16
	fbHits   *countingListener
	tlsCli   *tls.Config
}

type countingListener struct {
	mu   sync.Mutex
	hits int
}

func echoServer(t *testing.T, network, addr string, prefix []byte) (net.Listener, uint16) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, 0
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if prefix != nil {
					c.Write(prefix)
				}
				io.Copy(c, c)
			}()
		}
	}()
	return ln, uint16(ln.Addr().(*net.TCPAddr).Port)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	log = logger.NewWithLevel("error")
	allowPrivateTargets = true
	handshakeTimeout = 300 * time.Millisecond
	probeIdleTimeout = 500 * time.Millisecond

	cert, err := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	if err != nil {
		t.Skip("server.crt/server.key not present at repo root")
	}
	h := &harness{tlsCli: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"phantom"}}}

	_, h.echoPort = echoServer(t, "tcp", "127.0.0.1:0", nil)
	_, h.echo6 = echoServer(t, "tcp6", "[::1]:0", nil)
	fbLn, _ := echoServer(t, "tcp", "127.0.0.1:0", []byte("FALLBACK"))
	fb := fbLn.Addr().String()
	fallbackAddr.Store(&fb)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"phantom"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h.addr = ln.Addr().String()

	a := auth.NewStaticAuth([]string{testPassword})
	lim := auth.NewRateLimiter(1000, time.Minute, time.Minute)
	t.Cleanup(lim.Close)
	m := metrics.New()
	var wg sync.WaitGroup
	go acceptLoop(ln, &wg, func(c net.Conn) { handleSession(c, a, lim, m) })
	return h
}

func header(pw, host string, port uint16) []byte {
	addr, _ := protocol.ResolveAddress(host, port)
	var b bytes.Buffer
	protocol.WriteHeader(&b, &protocol.Header{PasswordHash: protocol.HashPassword(pw), Request: protocol.Request{Command: protocol.CmdConnect, Address: addr}})
	return b.Bytes()
}

func roundTrip(t *testing.T, c io.ReadWriter, msg string) string {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

func TestE2EDirectTrojan(t *testing.T) {
	h := newHarness(t)
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(header(testPassword, "127.0.0.1", h.echoPort))
	if got := roundTrip(t, c, "ping"); got != "ping" {
		t.Fatalf("got %q", got)
	}
}

func TestE2EIPv6Target(t *testing.T) {
	h := newHarness(t)
	if h.echo6 == 0 {
		t.Skip("no IPv6 loopback")
	}
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(header(testPassword, "::1", h.echo6))
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if got := roundTrip(t, c, "v6"); got != "v6" {
		t.Fatalf("got %q", got)
	}
}

func TestE2ESmuxV1AndV2(t *testing.T) {
	h := newHarness(t)
	for _, v := range []int{1, 2} {
		t.Run("v"+strconv.Itoa(v), func(t *testing.T) {
			c, err := tls.Dial("tcp", h.addr, h.tlsCli)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := transport.NewMuxSessionVersion(c, v)
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					st, err := sess.OpenStream()
					if err != nil {
						t.Error(err)
						return
					}
					defer st.Close()
					st.Write(header(testPassword, "127.0.0.1", h.echoPort))
					msg := "stream-" + strconv.Itoa(i)
					if got := roundTrip(t, st, msg); got != msg {
						t.Errorf("got %q", got)
					}
				}(i)
			}
			wg.Wait()
		})
	}
}

func TestE2EWrongPasswordFallsBack(t *testing.T) {
	h := newHarness(t)
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(header("wrong", "127.0.0.1", h.echoPort))
	c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "FALLBACK" {
		t.Fatalf("expected fallback, got %q %v", buf, err)
	}
}

func TestE2EHTTPProbeFallsBack(t *testing.T) {
	h := newHarness(t)
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "FALLBACK" {
		t.Fatalf("expected fallback, got %q %v", buf, err)
	}
}

// A client that completes TLS and then goes silent must be disconnected
// (previously it was held open forever: slowloris).
func TestE2ESilentConnectionIsClosed(t *testing.T) {
	h := newHarness(t)
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected the server to close the connection")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server never closed the silent connection (waited %v)", time.Since(start))
	}
}
