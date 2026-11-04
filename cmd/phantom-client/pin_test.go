package main

import (
	"crypto/sha256"
	"crypto/tls"
	"testing"
)

func pinServer(t *testing.T) (string, []byte) {
	cert, err := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	if err != nil {
		t.Skip("no test cert")
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	sum := sha256.Sum256(cert.Certificate[0])
	return ln.Addr().String(), sum[:]
}

func TestUTLSPinning(t *testing.T) {
	addr, good := pinServer(t)
	for _, fp := range []string{"HelloChrome_Auto", "HelloFirefox_Auto", "HelloRandomized"} {
		if c, err := dialUTLS(addr, fp, false, good); err != nil {
			t.Errorf("%s: correct pin rejected: %v", fp, err)
		} else {
			c.Close()
		}
		bad := make([]byte, 32)
		if c, err := dialUTLS(addr, fp, false, bad); err == nil {
			c.Close()
			t.Errorf("%s: WRONG pin accepted", fp)
		}
	}
}
