package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/phantom-go/phantom/internal/config"
)

// A failed local SOCKS handshake must not open (and waste) a tunnel stream.
func TestV2FailedSOCKSHandshakeOpensNoStream(t *testing.T) {
	dial, dials, _, _ := dialerFactory(0)
	p := newSessionPool(1, 16, dial)
	defer p.Close()
	cfg := &config.Config{}

	for _, payload := range [][]byte{nil, {4, 1, 0, 80, 127, 0, 0, 1, 0}} { // connect+close, SOCKS4
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() { handleClientConn(b, p, cfg); b.Close(); close(done) }()
		go func() {
			if payload != nil {
				a.Write(payload) // may block until the handler stops reading
			}
			a.Close()
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("handler did not return")
		}
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("failed SOCKS handshakes opened %d tunnel sessions", n)
	}
}

func TestV2WebSocketALPNKeepsChromeFingerprint(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	if err != nil {
		t.Skip()
	}
	seen := make(chan string, 4)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			seen <- fmt.Sprintf("%v|%v", h.SupportedProtos, h.SupportedCurves)
			return nil, nil
		},
	})
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	c, err := dialUTLS(ln.Addr().String(), "HelloChrome_Auto", false, nil, []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	got := <-seen
	if got[:10] != "[http/1.1]" {
		t.Fatalf("ws ALPN = %s, want [http/1.1]", got)
	}
	if !contains(got, "X25519MLKEM768") {
		t.Fatalf("ALPN override dropped the Chrome key shares: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
