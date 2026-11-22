package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func FuzzParseUDPHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 'x'})
	f.Add([]byte{0, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80})
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseUDPHeader(data)
	})
}

type fakeConn struct {
	r io.Reader
	w bytes.Buffer
}

func (c *fakeConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzHandshake(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187})
	f.Add([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		Handshake(&fakeConn{r: bytes.NewReader(data)})
	})
}
