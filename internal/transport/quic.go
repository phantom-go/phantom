// Phantom — encrypted transport framework
// Copyright (C) 2026 The Phantom Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL <https://www.gnu.org/licenses/> for details.

package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ALPNH3 is the only ALPN Phantom's QUIC transport offers or accepts.
//
// Before 2.0 the QUIC handshake carried ALPN "phantom". QUIC Initial packets
// are encrypted with keys derived from public values, so any on-path observer
// can decrypt them and read the ALPN: QUIC mode was identifiable passively,
// and an active prober offering "phantom" got a definitive answer. Since 2.0
// every Phantom QUIC stream is an ordinary HTTP/3 CONNECT request; anything
// that is not an authenticated CONNECT is served as a normal website.
const ALPNH3 = http3.NextProtoH3

// ProxyAuthPrefix prefixes the password hash in the Proxy-Authorization
// header of a Phantom HTTP/3 CONNECT request. Proxy-Authorization is a
// hop-by-hop header, so it is never forwarded to the fallback web server.
const ProxyAuthPrefix = "Bearer "

// serverQUICConfig deliberately keeps quic-go's defaults for every value a
// peer can observe (stream limits, idle timeout), so the server's transport
// parameters match those of any other quic-go HTTP/3 server.
func serverQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		// Internal auto-tuning ceilings (not advertised): let one stream
		// fill a long fat pipe.
		MaxStreamReceiveWindow:     16 * 1024 * 1024,
		MaxConnectionReceiveWindow: 32 * 1024 * 1024,
	}
}

func clientQUICConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:            15 * time.Second,
		HandshakeIdleTimeout:       10 * time.Second,
		MaxStreamReceiveWindow:     16 * 1024 * 1024,
		MaxConnectionReceiveWindow: 32 * 1024 * 1024,
	}
}

// QUICListener accepts QUIC connections.
type QUICListener struct {
	ln *quic.Listener
}

// ListenQUIC starts a server-side QUIC listener. tlsCfg.NextProtos is forced
// to [h3].
func ListenQUIC(addr string, tlsCfg *tls.Config) (*QUICListener, error) {
	cfg := tlsCfg.Clone()
	cfg.NextProtos = []string{ALPNH3}
	cfg.MinVersion = tls.VersionTLS13
	ln, err := quic.ListenAddr(addr, cfg, serverQUICConfig())
	if err != nil {
		return nil, err
	}
	return &QUICListener{ln: ln}, nil
}

// Accept waits for the next connection. After Close it returns an error
// wrapping net.ErrClosed.
func (l *QUICListener) Accept(ctx context.Context) (*quic.Conn, error) { return l.ln.Accept(ctx) }

// Addr returns the listening address.
func (l *QUICListener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener.
func (l *QUICListener) Close() error { return l.ln.Close() }

// DialQUIC establishes a client-side QUIC connection with ALPN h3.
func DialQUIC(addr string, tlsCfg *tls.Config) (*quic.Conn, error) {
	cfg := tlsCfg.Clone()
	cfg.NextProtos = []string{ALPNH3}
	cfg.MinVersion = tls.VersionTLS13
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return quic.DialAddr(ctx, addr, cfg, clientQUICConfig())
}

// H3StreamConn adapts a hijacked server-side HTTP/3 stream to net.Conn.
// Reads and writes carry HTTP/3 DATA frames transparently.
type H3StreamConn struct {
	Str    *http3.Stream
	Local  net.Addr
	Remote net.Addr
}

func (c *H3StreamConn) Read(b []byte) (int, error)  { return c.Str.Read(b) }
func (c *H3StreamConn) Write(b []byte) (int, error) { return c.Str.Write(b) }

// Close releases both directions (QUIC Close only ends the send side).
func (c *H3StreamConn) Close() error {
	c.Str.CancelRead(0)
	return c.Str.Close()
}

// CloseWrite half-closes (FIN) while still allowing reads.
func (c *H3StreamConn) CloseWrite() error                  { return c.Str.Close() }
func (c *H3StreamConn) LocalAddr() net.Addr                { return c.Local }
func (c *H3StreamConn) RemoteAddr() net.Addr               { return c.Remote }
func (c *H3StreamConn) SetDeadline(t time.Time) error      { return c.Str.SetDeadline(t) }
func (c *H3StreamConn) SetReadDeadline(t time.Time) error  { return c.Str.SetReadDeadline(t) }
func (c *H3StreamConn) SetWriteDeadline(t time.Time) error { return c.Str.SetWriteDeadline(t) }

// H3ClientConn opens authenticated Phantom streams over an HTTP/3 connection.
type H3ClientConn struct {
	cc        *http3.ClientConn
	authority string
	auth      string
}

// NewH3ClientConn wraps an established QUIC connection (ALPN h3). authority
// is the server's host:port; passwordHash authenticates every stream.
func NewH3ClientConn(conn *quic.Conn, authority, passwordHash string) *H3ClientConn {
	tr := &http3.Transport{}
	return &H3ClientConn{
		cc:        tr.NewClientConn(conn),
		authority: authority,
		auth:      ProxyAuthPrefix + passwordHash,
	}
}

// OpenStream starts one CONNECT request and returns its stream. The request
// headers are sent immediately and the caller may write at once; the
// response is awaited lazily on the first Read, so opening a stream adds no
// round trip before the first payload byte is sent.
func (h *H3ClientConn) OpenStream(ctx context.Context) (*H3ClientStream, error) {
	rs, err := h.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		Host:   h.authority,
		URL:    &url.URL{Host: h.authority},
		Header: http.Header{"Proxy-Authorization": {h.auth}},
	}
	if err := rs.SendRequestHeader(req); err != nil {
		rs.CancelWrite(0)
		rs.CancelRead(0)
		return nil, err
	}
	return &H3ClientStream{rs: rs}, nil
}

// ErrStreamRejected means the server answered the CONNECT with a non-2xx
// status (wrong password, banned source, or not a Phantom server).
var ErrStreamRejected = errors.New("phantom: server rejected the stream")

// H3ClientStream is the client side of one Phantom HTTP/3 stream.
type H3ClientStream struct {
	rs      *http3.RequestStream
	once    sync.Once
	respErr error
}

func (s *H3ClientStream) awaitResponse() error {
	s.once.Do(func() {
		resp, err := s.rs.ReadResponse()
		if err != nil {
			s.respErr = err
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			s.respErr = ErrStreamRejected
		}
	})
	return s.respErr
}

func (s *H3ClientStream) Read(b []byte) (int, error) {
	if err := s.awaitResponse(); err != nil {
		return 0, err
	}
	return s.rs.Read(b)
}

func (s *H3ClientStream) Write(b []byte) (int, error) { return s.rs.Write(b) }

// Close releases both directions.
func (s *H3ClientStream) Close() error {
	s.rs.CancelRead(0)
	return s.rs.Close()
}

// CloseWrite half-closes (FIN) while still allowing reads.
func (s *H3ClientStream) CloseWrite() error                  { return s.rs.Close() }
func (s *H3ClientStream) SetDeadline(t time.Time) error      { return s.rs.SetDeadline(t) }
func (s *H3ClientStream) SetReadDeadline(t time.Time) error  { return s.rs.SetReadDeadline(t) }
func (s *H3ClientStream) SetWriteDeadline(t time.Time) error { return s.rs.SetWriteDeadline(t) }

// ParseProxyAuth extracts the password hash from a Proxy-Authorization value.
func ParseProxyAuth(v string) (string, bool) {
	if !strings.HasPrefix(v, ProxyAuthPrefix) {
		return "", false
	}
	return strings.TrimSpace(v[len(ProxyAuthPrefix):]), true
}

var _ io.ReadWriteCloser = (*H3ClientStream)(nil)
