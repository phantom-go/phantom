// Phantom — encrypted transport framework
// Copyright (C) 2026 The Phantom Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL <https://www.gnu.org/licenses/> for details.

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phantom-go/phantom/internal/config"
	"github.com/phantom-go/phantom/internal/logger"
	"github.com/phantom-go/phantom/internal/protocol"
	"github.com/phantom-go/phantom/internal/relay"
	"github.com/phantom-go/phantom/internal/socks5"
	"github.com/phantom-go/phantom/internal/transport"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

var log = logger.New()

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	socksTimeout     = 10 * time.Second
)

// passwordHash is computed once at startup instead of per connection.
var passwordHash string

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	useQUIC := flag.Bool("quic", false, "use QUIC transport")
	configPath := flag.String("config", "config.json", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", os.Getenv("PHANTOM_LOG_LEVEL"), "log level: debug, info, warn, error")
	flag.Parse()
	log = logger.NewWithLevel(*logLevel)

	if *showVersion {
		os.Stdout.WriteString("phantom-client " + version + "\n")
		return
	}

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	if config.InsecurePermissions(*configPath) {
		log.Warn("config file is readable by other users and contains the password; run: chmod 600 " + *configPath)
	}
	passwordHash = protocol.HashPassword(cfg.Client.Password)
	if !cfg.Client.VerifyEnabled() && cfg.Client.PinnedCertSHA256 == "" {
		log.Warn("verify=false without pinned_cert_sha256: the server is NOT authenticated and the tunnel is open to man-in-the-middle attacks")
	}
	switch cfg.Client.TLSFingerprint {
	case "HelloFirefox_Auto", "HelloEdge_Auto":
		// uTLS's newest Firefox parrot is Firefox 120 (2023) and its Edge
		// parrot is Edge 85 (2020): both stand out against real current
		// browsers and neither offers post-quantum key exchange.
		log.Warn("tls_fingerprint " + cfg.Client.TLSFingerprint + " imitates an outdated browser and has no post-quantum key exchange; HelloChrome_Auto (the default) is recommended")
	}

	// QUIC is enabled by either the --quic flag or transport="quic" in
	// config, so a phantom://...?type=quic URI translated into config
	// selects QUIC without needing the flag. The flag remains as a
	// convenient override.
	quicEnabled := *useQUIC || cfg.Client.Transport == "quic"

	if quicEnabled && cfg.Client.Transport == "ws" {
		log.Error("QUIC and transport=ws are mutually exclusive")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", cfg.Client.Socks5Addr)
	if err != nil {
		log.Error("listen socks5", "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	log.Info("socks5 listening", "addr", cfg.Client.Socks5Addr)

	if quicEnabled {
		runQUIC(cfg, ln)
	} else {
		runTCP(cfg, ln)
	}
}

// dialUTLS establishes a TLS connection mimicking a browser fingerprint based on configuration.
// When verify is false, certificate verification is skipped (matches the
// protocol-spec ?allowInsecure=1 use case for IP + self-signed deployments).
// When true, the server certificate is verified against the SNI host as
// usual — operators using a domain + CA cert should leave this enabled.
func dialUTLS(serverAddr string, fingerprint string, verify bool, pin []byte, alpn []string) (net.Conn, error) {
	// HelloRandomized occasionally generates a ClientHello that uTLS itself
	// cannot complete ("CurvePreferences includes unsupported curve"),
	// which surfaced as random connection failures. A fresh randomisation
	// almost always succeeds, so retry a few times.
	attempts := 1
	if fingerprint == "HelloRandomized" {
		attempts = 4
	}
	var err error
	for i := 0; i < attempts; i++ {
		var c net.Conn
		if c, err = dialUTLSOnce(serverAddr, fingerprint, verify, pin, alpn); err == nil {
			return c, nil
		}
		if errors.Is(err, errPinMismatch) {
			return nil, err
		}
	}
	return nil, err
}

// dialUTLSOnce performs one browser-fingerprinted TLS handshake. alpn, when
// non-nil, replaces the parrot's ALPN list (WebSocket mode uses
// ["http/1.1"], exactly what a browser offers for a WebSocket connection).
func dialUTLSOnce(serverAddr string, fingerprint string, verify bool, pin []byte, alpn []string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	d := &net.Dialer{Timeout: dialTimeout}
	tcpConn, err := d.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	uConfig := &utls.Config{
		ServerName:            host,
		InsecureSkipVerify:    !verify,
		VerifyPeerCertificate: pinVerifier(pin),
	}

	var clientHelloID utls.ClientHelloID
	switch fingerprint {
	case "HelloFirefox_Auto":
		clientHelloID = utls.HelloFirefox_Auto
	case "HelloEdge_Auto":
		clientHelloID = utls.HelloEdge_Auto
	case "HelloRandomized":
		clientHelloID = utls.HelloRandomized
	default:
		clientHelloID = utls.HelloChrome_Auto
	}

	uConn := utls.UClient(tcpConn, uConfig, clientHelloID)
	if len(alpn) > 0 {
		if spec, err := utls.UTLSIdToSpec(clientHelloID); err == nil {
			for _, ext := range spec.Extensions {
				if a, ok := ext.(*utls.ALPNExtension); ok {
					a.AlpnProtocols = alpn
				}
			}
			uConn = utls.UClient(tcpConn, uConfig, utls.HelloCustom)
			if err := uConn.ApplyPreset(&spec); err != nil {
				tcpConn.Close()
				return nil, err
			}
		}
	}
	// Bound the handshake: an unresponsive server (or a middlebox that
	// black-holes the ClientHello) previously hung the pool's dial forever.
	_ = tcpConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	_ = tcpConn.SetDeadline(time.Time{})
	return uConn, nil
}

var errPinMismatch = errors.New("server certificate does not match pinned_cert_sha256")

// pinVerifier returns a VerifyPeerCertificate hook that accepts only a leaf
// whose SHA-256 equals pin. It runs even when InsecureSkipVerify is set, which
// is exactly what makes pinning useful for self-signed deployments.
func pinVerifier(pin []byte) func([][]byte, [][]*x509.Certificate) error {
	if len(pin) == 0 {
		return nil
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errPinMismatch
		}
		sum := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
			return errPinMismatch
		}
		return nil
	}
}

// acceptLoop accepts SOCKS connections. A permanent Accept error (EMFILE)
// previously made the loop spin at 100% CPU logging an error per iteration.
func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			log.Error("accept", "err", err, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go handle(conn)
	}
}

func runTCP(cfg *config.Config, ln net.Listener) {
	pool := newSessionPool(
		cfg.Client.SessionPoolSize,
		cfg.Client.SessionGrowthThreshold,
		func() (pooledSession, error) { return dialSmuxSession(cfg) },
	).withIdleTimeout(cfg.Client.IdleTimeout())
	defer pool.Close()

	stop := make(chan struct{})
	defer close(stop)
	go pool.keepAlive(15*time.Second, stop)

	acceptLoop(ln, func(c net.Conn) {
		defer c.Close()
		handleClientConn(c, pool, cfg)
	})
}

// smuxSession adapts *smux.Session to the pooledSession interface.
type smuxSession struct {
	sess *smux.Session
	// underlying transport conn, closed alongside the session.
	conn    net.Conn
	streams atomic.Int64
}

func (s *smuxSession) OpenStream() (io.ReadWriteCloser, error) {
	st, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	s.streams.Add(1)
	return &countedSmuxStream{Stream: st, parent: s}, nil
}
func (s *smuxSession) Healthy() bool   { return s.sess != nil && !s.sess.IsClosed() }
func (s *smuxSession) NumStreams() int { return int(s.streams.Load()) }
func (s *smuxSession) Close() error {
	if s.sess != nil {
		s.sess.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

// countedSmuxStream decrements the parent's live-stream counter once on Close.
type countedSmuxStream struct {
	*smux.Stream
	parent *smuxSession
	once   sync.Once
}

func (c *countedSmuxStream) Close() error {
	c.once.Do(func() { c.parent.streams.Add(-1) })
	return c.Stream.Close()
}

// dialSmuxSession performs the full uTLS (+ optional WebSocket) + smux
// handshake. It is invoked by the pool with no lock held.
func dialSmuxSession(cfg *config.Config) (pooledSession, error) {
	// 1. Establish the underlying uTLS connection (obfuscates JA3/JA4).
	var alpn []string
	if cfg.Client.Transport == "ws" {
		alpn = []string{"http/1.1"}
	}
	conn, err := dialUTLS(cfg.Client.ServerAddr, cfg.Client.TLSFingerprint, cfg.Client.VerifyEnabled(), cfg.Client.PinnedCertBytes(), alpn)
	if err != nil {
		return nil, err
	}

	// 2. If WebSocket transport is enabled, layer it on top.
	if cfg.Client.Transport == "ws" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		wsConn, werr := transport.DialWS(ctx, conn, cfg.Client.ServerAddr, cfg.Client.WSPath)
		cancel()
		if werr != nil {
			conn.Close()
			return nil, werr
		}
		conn = wsConn
	}

	// 3. Bind the smux multiplexer onto the secure tunnel.
	sess, err := smux.Client(conn, transport.MuxConfig(transport.ClientMuxVersion))
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &smuxSession{sess: sess, conn: conn}, nil
}

func runQUIC(cfg *config.Config, ln net.Listener) {
	pool := newSessionPool(
		cfg.Client.SessionPoolSize,
		cfg.Client.SessionGrowthThreshold,
		func() (pooledSession, error) { return dialQUICSession(cfg) },
	).withIdleTimeout(cfg.Client.IdleTimeout())
	defer pool.Close()

	stop := make(chan struct{})
	defer close(stop)
	go pool.keepAlive(15*time.Second, stop)

	acceptLoop(ln, func(c net.Conn) {
		defer c.Close()
		handleClientConn(c, pool, cfg)
	})
}

// quicSession is one HTTP/3 connection to the server; every proxied
// connection is an authenticated CONNECT stream on it.
type quicSession struct {
	conn    *quic.Conn
	h3      *transport.H3ClientConn
	streams atomic.Int64
}

func (s *quicSession) OpenStream() (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	st, err := s.h3.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	s.streams.Add(1)
	return &countedH3Stream{H3ClientStream: st, parent: s}, nil
}
func (s *quicSession) Healthy() bool   { return s.conn != nil && s.conn.Context().Err() == nil }
func (s *quicSession) NumStreams() int { return int(s.streams.Load()) }
func (s *quicSession) Close() error {
	if s.conn != nil {
		return s.conn.CloseWithError(0, "")
	}
	return nil
}

// countedH3Stream decrements its parent session's stream counter exactly
// once, on first Close.
type countedH3Stream struct {
	*transport.H3ClientStream
	parent *quicSession
	once   sync.Once
}

func (c *countedH3Stream) Close() error {
	c.once.Do(func() { c.parent.streams.Add(-1) })
	return c.H3ClientStream.Close()
}

func dialQUICSession(cfg *config.Config) (pooledSession, error) {
	tlsCfg := &tls.Config{
		// Honour the per-client verify toggle. Same trade-off as dialUTLS:
		// for IP + self-signed deployments verify must be false; for
		// domain + CA cert deployments it should stay true.
		InsecureSkipVerify:    !cfg.Client.VerifyEnabled(),
		VerifyPeerCertificate: pinVerifier(cfg.Client.PinnedCertBytes()),
	}
	host, _, err := net.SplitHostPort(cfg.Client.ServerAddr)
	if err != nil {
		host = cfg.Client.ServerAddr
	}
	// Send SNI for host names like any HTTP/3 client (IPs never carry SNI).
	if net.ParseIP(host) == nil {
		tlsCfg.ServerName = host
	}
	qc, err := transport.DialQUIC(cfg.Client.ServerAddr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: qc, h3: transport.NewH3ClientConn(qc, cfg.Client.ServerAddr, passwordHash)}, nil
}

// handleClientConn services one accepted SOCKS5 connection.
//
// The tunnel stream is opened only AFTER the local SOCKS handshake succeeds.
// v1.x opened it first and closed it unused when the handshake failed; the
// server counted every such empty stream as a failed login, so 20 local port
// checks (many apps' proxy health checks) banned the user for 5 minutes.
func handleClientConn(conn net.Conn, pool *sessionPool, cfg *config.Config) {
	// A local client that connects and never completes the SOCKS
	// handshake must not pin a goroutine forever.
	conn.SetDeadline(time.Now().Add(socksTimeout))
	req, err := socks5.Handshake(conn)
	if err != nil {
		log.Debug("socks5 handshake", "err", err)
		return
	}
	conn.SetDeadline(time.Time{})

	stream, err := pool.OpenStream()
	if err != nil {
		log.Error("open stream", "err", err)
		return
	}
	defer stream.Close()

	cmdHost := req.Host
	cmdPort := req.Port
	cmd := byte(protocol.CmdConnect)
	if req.IsUDP {
		cmdHost = "0.0.0.0"
		cmdPort = 0
		cmd = protocol.CmdUDP
	}

	addr, err := protocol.ResolveAddress(cmdHost, cmdPort)
	if err != nil {
		log.Error("resolve target address", "err", err)
		return
	}

	header := &protocol.Header{
		PasswordHash: passwordHash,
		Request: protocol.Request{
			Command: cmd,
			Address: addr,
		},
	}

	if err := protocol.WriteHeader(stream, header); err != nil {
		log.Debug("write header", "err", err)
		return
	}

	if req.IsUDP {
		log.Debug("udp associate", "client", conn.RemoteAddr())
		handleUDP(conn, stream)
		return
	}

	log.Debug("relay", "host", req.Host, "port", req.Port)
	relay.Pipe(conn, stream, relay.DefaultIdleTimeout)
}

// handleUDP serves one SOCKS5 UDP ASSOCIATE.
//
// Security: the relay socket accepts datagrams only from the IP that opened
// the TCP control connection, and locks onto the first sender's port
// (RFC 1928 §7). Previously any local process could inject datagrams into —
// or hijack replies from — another user's association simply by sending to
// the 127.0.0.1 port, because the "client address" was overwritten by
// whoever sent last. The socket is also bound to the control connection's
// local IP, so UDP works when the SOCKS listener is on a LAN address
// (previously it always bound 127.0.0.1, unreachable from LAN clients).
func handleUDP(tcpConn net.Conn, stream io.ReadWriteCloser) {
	localIP := net.IPv4(127, 0, 0, 1)
	if la, ok := tcpConn.LocalAddr().(*net.TCPAddr); ok && la.IP != nil && !la.IP.IsUnspecified() {
		localIP = la.IP
	}
	var peerIP net.IP
	if ra, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
		peerIP = ra.IP
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		log.Error("listen local udp", "err", err)
		return
	}
	defer udpConn.Close()
	defer stream.Close()

	bound := udpConn.LocalAddr().(*net.UDPAddr)
	if err := socks5.SendReply(tcpConn, socks5.RepSuccess, bound.IP.String(), uint16(bound.Port)); err != nil {
		log.Error("send socks5 udp reply", "err", err)
		return
	}

	done := make(chan struct{}, 3)
	var clientUDPAddr atomic.Pointer[net.UDPAddr]

	go func() {
		defer func() { done <- struct{}{} }()
		big := make([]byte, 65535)
		for {
			n, addr, err := udpConn.ReadFromUDP(big)
			if err != nil {
				return
			}
			if peerIP != nil && !addr.IP.Equal(peerIP) {
				continue // not the owner of this association
			}
			if cur := clientUDPAddr.Load(); cur == nil {
				clientUDPAddr.Store(addr)
			} else if cur.Port != addr.Port {
				continue
			}
			socksReq, err := socks5.ParseUDPHeader(big[:n])
			if err != nil {
				continue
			}
			if len(socksReq.Payload) > protocol.MaxUDPPayloadLength {
				log.Debug("dropping oversized udp datagram", "size", len(socksReq.Payload), "max", protocol.MaxUDPPayloadLength)
				continue
			}
			if err := protocol.WriteUDPPacket(stream, socksReq.Host, socksReq.Port, socksReq.Payload); err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		br := bufio.NewReaderSize(stream, 16<<10)
		out := make([]byte, 0, 4+1+255+2+protocol.MaxUDPPayloadLength)
		for {
			pkt, err := protocol.ReadUDPPacket(br)
			if err != nil {
				return
			}
			cAddr := clientUDPAddr.Load()
			if cAddr == nil {
				continue
			}
			socksPacket, err := socks5.AppendUDPResponse(out[:0], pkt.Address.Host, pkt.Address.Port, pkt.Payload)
			if err != nil {
				continue
			}
			_, _ = udpConn.WriteToUDP(socksPacket, cAddr)
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		var discard [256]byte
		for {
			if _, err := tcpConn.Read(discard[:]); err != nil {
				return
			}
		}
	}()

	<-done
}
