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
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/phantom-go/phantom/internal/auth"
	"github.com/phantom-go/phantom/internal/config"
	"github.com/phantom-go/phantom/internal/logger"
	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/protocol"
	"github.com/phantom-go/phantom/internal/relay"
	"github.com/phantom-go/phantom/internal/transport"
)

var log *slog.Logger

// allowPrivateTargets mirrors cfg.Server.AllowPrivateTargets. Set once at
// startup; read by dispatchConn's SSRF guard.
var allowPrivateTargets bool

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	// handshakeTimeout bounds TLS handshake + phantom header parsing.
	handshakeTimeoutDefault = 10 * time.Second
	// probeIdleTimeout bounds how long a connection that has sent nothing
	// may stay open while we wait for its first byte. 60s mirrors nginx's
	// default client_header_timeout, so the timing is indistinguishable
	// from the fallback web server, and exceeds smux's 10s keep-alive so a
	// freshly dialled but idle client session is not mistaken for a probe.
	probeIdleTimeoutDefault = 60 * time.Second
	// fallbackIdleTimeout bounds silent fallback (probe) connections.
	fallbackIdleTimeout = 2 * time.Minute
	// maxPendingHandshakes caps concurrent not-yet-authenticated
	// connections process-wide; maxPendingPerSession caps concurrent
	// unauthenticated streams inside ONE smux/QUIC session. Without the
	// latter a single unauthenticated client could open thousands of
	// streams over one TLS connection, each costing a goroutine and a
	// 10-second parse window.
	maxPendingHandshakes = 4096
	maxPendingPerSession = 64
	// maxFallbackConns caps concurrent connections proxied to the
	// fallback web server so a probe flood cannot exhaust its sockets.
	maxFallbackConns = 2048
	// maxUDPTargetsPerStream caps outbound UDP sockets one UDP-associate
	// stream may open (each costs an fd and a goroutine).
	maxUDPTargetsPerStream = 256
	// shutdownGrace bounds how long shutdown waits for live sessions.
	shutdownGrace = 30 * time.Second
)

// Variables (not constants) so tests can shorten them.
var (
	handshakeTimeout = handshakeTimeoutDefault
	probeIdleTimeout = probeIdleTimeoutDefault
)

var (
	pendingSem  = make(chan struct{}, maxPendingHandshakes)
	fallbackSem = make(chan struct{}, maxFallbackConns)

	// fallbackAddr is swapped atomically on SIGHUP. The previous code
	// mutated cfg.Server.FallbackAddr from the signal goroutine while
	// connection goroutines read it — a data race.
	fallbackAddr atomic.Pointer[string]
)

func currentFallback() string {
	if p := fallbackAddr.Load(); p != nil {
		return *p
	}
	return ""
}

// trojanNotice is logged at startup and on the first trojan:// connection.
const trojanNotice = "trojan:// compatibility is temporary and provides basic proxying only; " +
	"it may be removed in a future release. Use phantom:// for full performance and security."

var trojanSeen sync.Once

// certStore serves the certificate through tls.Config.GetCertificate so it
// can be replaced on SIGHUP. Previously the cert was loaded once at start;
// after a Let's Encrypt renewal the server kept presenting the old
// certificate until someone restarted it, and clients failed hard once it
// expired.
type certStore struct {
	cert atomic.Pointer[tls.Certificate]
}

func (cs *certStore) load(certFile, keyFile string) error {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	cs.cert.Store(&c)
	return nil
}

func (cs *certStore) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cs.cert.Load(), nil
}

func main() {
	useQUIC := flag.Bool("quic", false, "use QUIC transport")
	configPath := flag.String("config", "config.json", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	logLevel := flag.String("log-level", os.Getenv("PHANTOM_LOG_LEVEL"), "log level: debug, info, warn, error")
	flag.Parse()

	if *showVersion {
		os.Stdout.WriteString("phantom-server " + version + "\n")
		return
	}

	log = logger.NewWithLevel(*logLevel)

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	if config.InsecurePermissions(*configPath) {
		log.Warn("config file is readable by other users and contains passwords; run: chmod 600 " + *configPath)
	}

	quicEnabled := *useQUIC || cfg.Server.Transport == "quic"
	if quicEnabled && cfg.Server.Transport == "ws" {
		log.Error("QUIC and transport=ws are mutually exclusive")
		os.Exit(1)
	}

	allowPrivateTargets = cfg.Server.AllowPrivateTargets
	if allowPrivateTargets {
		log.Warn("SSRF guard disabled (allow_private_targets=true): clients may reach loopback/private/metadata addresses")
	}
	fb := cfg.Server.FallbackAddr
	fallbackAddr.Store(&fb)

	certs := &certStore{}
	if err := certs.load(cfg.Server.CertFile, cfg.Server.KeyFile); err != nil {
		log.Error("load cert", "err", err)
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		GetCertificate: certs.get,
		NextProtos:     []string{"phantom", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	}

	var ln net.Listener
	if quicEnabled {
		ql, err := transport.ListenQUIC(cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen quic", "err", err)
			os.Exit(1)
		}
		ln = ql
		log.Info("listening on QUIC", "addr", cfg.Server.Listen, "version", version)
	} else {
		ln, err = tls.Listen("tcp", cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
		log.Info("listening on TCP", "addr", cfg.Server.Listen, "version", version)
	}
	log.Info("native protocol: phantom://. " + trojanNotice)

	authenticator := auth.NewStaticAuth(cfg.Server.Passwords)

	limiter := auth.NewRateLimiter(20, 5*time.Minute, 5*time.Minute)
	defer limiter.Close()

	m := metrics.New()

	var wg sync.WaitGroup
	var httpServer *http.Server
	var shuttingDown atomic.Bool

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for {
			s := <-sig
			switch s {
			case syscall.SIGHUP:
				log.Info("received SIGHUP, reloading configuration")
				newCfg, err := config.LoadFromFile(*configPath)
				if err != nil {
					log.Error("reload config failed", "err", err)
					continue
				}
				if newCfg.Server.Listen != cfg.Server.Listen {
					log.Warn("listen address change requires restart", "current", cfg.Server.Listen, "ignored", newCfg.Server.Listen)
				}
				nfb := newCfg.Server.FallbackAddr
				fallbackAddr.Store(&nfb)
				authenticator.Reload(newCfg.Server.Passwords)
				if err := certs.load(newCfg.Server.CertFile, newCfg.Server.KeyFile); err != nil {
					log.Error("reload cert failed; keeping previous certificate", "err", err)
				} else {
					log.Info("certificate reloaded")
				}
				logStats(m)
				log.Info("config reloaded")

			default:
				logStats(m)
				log.Info("shutting down")
				shuttingDown.Store(true)
				ln.Close()
				if httpServer != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = httpServer.Shutdown(ctx)
					cancel()
				}
				return
			}
		}
	}()

	if cfg.Server.Transport == "ws" {
		log.Info("starting WebSocket mode", "path", cfg.Server.WSPath)

		// The fallback proxy target is resolved per request so SIGHUP
		// changes to fallback_addr take effect in ws mode too.
		var proxyMu sync.Mutex
		var proxyFor string
		var proxy *httputil.ReverseProxy
		getProxy := func() *httputil.ReverseProxy {
			addr := currentFallback()
			if addr == "" {
				return nil
			}
			proxyMu.Lock()
			defer proxyMu.Unlock()
			if proxy != nil && proxyFor == addr {
				return proxy
			}
			raw := addr
			if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
				raw = "http://" + raw
			}
			u, err := url.Parse(raw)
			if err != nil {
				log.Error("parse fallback addr", "err", err)
				return nil
			}
			proxy = httputil.NewSingleHostReverseProxy(u)
			proxy.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
			proxyFor = addr
			return proxy
		}
		if getProxy() == nil && currentFallback() != "" {
			os.Exit(1)
		}

		mux := http.NewServeMux()
		mux.HandleFunc(cfg.Server.WSPath, func(w http.ResponseWriter, r *http.Request) {
			if limiter.IsBanned(transport.ClientAddr(r, cfg.Server.TrustProxyHeaders)) {
				if p := getProxy(); p != nil {
					p.ServeHTTP(w, r)
				} else {
					http.NotFound(w, r)
				}
				return
			}
			wsConn, err := transport.AcceptWS(w, r, cfg.Server.TrustProxyHeaders)
			if err != nil {
				log.Debug("websocket accept failed", "err", err)
				return
			}
			if shuttingDown.Load() {
				wsConn.Close()
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleSession(c, authenticator, limiter, m)
			}(wsConn)
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if p := getProxy(); p != nil {
				p.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		})

		httpServer = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: handshakeTimeout,
			IdleTimeout:       probeIdleTimeout,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		}
		_ = httpServer.Serve(ln)
	} else {
		acceptLoop(ln, &wg, func(c net.Conn) {
			handleSession(c, authenticator, limiter, m)
		})
	}

	waitTimeout(&wg, shutdownGrace)
	log.Info("shutdown complete")
}

// acceptLoop accepts until the listener is closed. Transient errors such as
// EMFILE/ENFILE back off and retry. The previous loop exited on ANY Accept
// error, so a burst of file-descriptor exhaustion made the process shut down
// cleanly with status 0 — which Restart=on-failure does not restart.
func acceptLoop(ln net.Listener, wg *sync.WaitGroup, handle func(net.Conn)) {
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
			log.Warn("accept error; retrying", "err", err, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handle(c)
		}(conn)
	}
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		log.Warn("shutdown grace period elapsed; closing remaining sessions")
	}
}

func logStats(m *metrics.Metrics) {
	for hash, stats := range m.Snapshot() {
		log.Info("user stats", "hash", hash[:8], "sent", stats[0], "recv", stats[1])
	}
}

// tryAcquire takes a slot from sem without blocking.
func tryAcquire(sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func handleSession(conn net.Conn, authenticator auth.Authenticator, limiter *auth.RateLimiter, m *metrics.Metrics) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()

	// QUIC connections carry multiple streams; fan each out to handleConn.
	if qconn, ok := conn.(*transport.QUICNetConn); ok {
		if limiter.IsBanned(remoteAddr) {
			log.Debug("banned IP attempted QUIC connection", "addr", remoteAddr)
			return
		}
		serveStreams(transport.AcceptQUICStreams(qconn.Conn), func() bool {
			return limiter.IsBanned(remoteAddr)
		}, authenticator, limiter, m)
		return
	}

	if limiter.IsBanned(remoteAddr) {
		log.Debug("banned IP attempted connection, falling back", "addr", remoteAddr)
		doFallback(conn, remoteAddr)
		return
	}

	if !tryAcquire(pendingSem) {
		// Overloaded with unauthenticated connections: shed load.
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			<-pendingSem
		}
	}
	defer release()

	rconn := transport.NewRewindConn(conn)
	rconn.SetDeadline(time.Now().Add(handshakeTimeout))

	header, err := protocol.ParseHeader(rconn)
	if err == nil {
		rconn.SetDeadline(time.Time{})
		if !authenticator.Verify(header.PasswordHash) {
			limiter.RecordFailure(remoteAddr)
			rconn.Rewind()
			release()
			doFallback(rconn, remoteAddr)
			return
		}
		limiter.RecordSuccess(remoteAddr)
		rconn.Commit()
		release()
		// A bare header on the TLS stream (no smux) is a Trojan client;
		// phantom-client always multiplexes.
		trojanSeen.Do(func() {
			log.Info("a client connected in trojan:// compatibility mode. " + trojanNotice)
		})
		dispatchConn(rconn, header, m)
		return
	}

	// Not a direct Trojan header. Decide between smux and fallback from the
	// first byte already captured by the rewind buffer.
	//
	// The previous code cleared the deadline and then blocked in
	// bufio.Peek with NO deadline: a client that completed TLS and then
	// went silent held a goroutine + fd forever (slowloris). Now an idle
	// connection gets a bounded probeIdleTimeout to produce its first byte.
	if len(rconn.Recorded()) == 0 {
		if !isTimeout(err) {
			return // TLS handshake failure or immediate EOF
		}
		rconn.SetDeadline(time.Now().Add(probeIdleTimeout))
		var one [1]byte
		if _, err := io.ReadFull(rconn, one[:]); err != nil {
			return
		}
	}
	first := rconn.Recorded()[0]
	rconn.Rewind()
	rconn.SetDeadline(time.Time{})
	release()

	session, err := transport.AcceptMuxSessionVersion(rconn, first)
	if err != nil {
		doFallback(rconn, remoteAddr)
		return
	}
	defer session.Close()

	streams := make(chan net.Conn)
	go func() {
		defer close(streams)
		for {
			st, err := session.AcceptStream()
			if err != nil {
				return
			}
			select {
			case streams <- st:
			case <-session.CloseChan():
				st.Close()
				return
			}
		}
	}()
	serveStreams(streams, func() bool { return limiter.IsBanned(remoteAddr) }, authenticator, limiter, m)
}

// serveStreams runs handleConn for each stream of one multiplexed session,
// with at most maxPendingPerSession streams in the unauthenticated phase at
// once (back-pressure on the session rather than unbounded goroutines). If
// the peer gets banned mid-session the whole session is dropped.
func serveStreams(streams <-chan net.Conn, banned func() bool, authenticator auth.Authenticator, limiter *auth.RateLimiter, m *metrics.Metrics) {
	sem := make(chan struct{}, maxPendingPerSession)
	for st := range streams {
		if banned() {
			st.Close()
			return
		}
		sem <- struct{}{}
		go handleConn(st, authenticator, limiter, m, func() { <-sem })
	}
}

func handleConn(conn net.Conn, authenticator auth.Authenticator, limiter *auth.RateLimiter, m *metrics.Metrics, release func()) {
	defer conn.Close()
	var once sync.Once
	done := func() { once.Do(release) }
	defer done()

	remoteAddr := conn.RemoteAddr()

	if limiter.IsBanned(remoteAddr) {
		return
	}

	rconn := transport.NewRewindConn(conn)
	rconn.SetDeadline(time.Now().Add(handshakeTimeout))

	header, err := protocol.ParseHeader(rconn)
	if err != nil || !authenticator.Verify(header.PasswordHash) {
		// Inside an established tunnel (smux / QUIC) there is no such
		// thing as an innocent prober: any malformed or unauthenticated
		// stream counts towards the ban, so an attacker cannot use one
		// tunnel to brute-force passwords without consequence.
		limiter.RecordFailure(remoteAddr)
		rconn.Rewind()
		rconn.SetDeadline(time.Time{})
		done()
		doFallback(rconn, remoteAddr)
		return
	}

	limiter.RecordSuccess(remoteAddr)
	rconn.Commit()
	rconn.SetDeadline(time.Time{})
	done()
	dispatchConn(rconn, header, m)
}

func dispatchConn(conn net.Conn, header *protocol.Header, m *metrics.Metrics) {
	stats := m.GetOrCreate(header.PasswordHash)
	user := header.PasswordHash[:8]

	if header.Request.Command == protocol.CmdUDP {
		log.Debug("udp relay", "user", user)
		handleUDPRelay(conn, stats)
		return
	}
	if header.Request.Command != protocol.CmdConnect {
		log.Debug("unsupported command", "cmd", header.Request.Command, "user", user)
		return
	}

	target := header.Request.Address.String()
	log.Debug("relay", "target", target, "user", user)

	remote, err := safeDialTCP(target, allowPrivateTargets, 10*time.Second)
	if err != nil {
		log.Debug("blocked or failed relay target", "err", err, "user", user)
		return
	}
	defer remote.Close()

	sent, recv := relay.Pipe(conn, remote, relay.DefaultIdleTimeout)
	stats.Sent.Add(uint64(sent))
	stats.Received.Add(uint64(recv))
}

func doFallback(conn net.Conn, remoteAddr net.Addr) {
	addr := currentFallback()
	if addr == "" {
		return
	}
	if !tryAcquire(fallbackSem) {
		return
	}
	defer func() { <-fallbackSem }()

	remote, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Error("fallback dial", "err", err)
		return
	}
	defer remote.Close()

	log.Debug("fallback connection", "from", remoteAddr)
	relay.Pipe(conn, remote, fallbackIdleTimeout)
}

func handleUDPRelay(stream net.Conn, stats *metrics.UserStats) {
	var (
		sessMu   sync.Mutex
		writeMu  sync.Mutex
		sessions = make(map[string]*net.UDPConn)
	)
	defer func() {
		sessMu.Lock()
		for _, conn := range sessions {
			conn.Close()
		}
		sessMu.Unlock()
	}()

	writePacket := func(host string, port uint16, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteUDPPacket(stream, host, port, payload)
	}

	// Buffered reader: ReadUDPPacket issues several small reads per
	// datagram; unbuffered, each one traversed rewind -> smux/QUIC locks.
	br := bufio.NewReaderSize(stream, 16<<10)

	for {
		stream.SetReadDeadline(time.Now().Add(relay.DefaultIdleTimeout))
		pkt, err := protocol.ReadUDPPacket(br)
		if err != nil {
			return
		}

		target := pkt.Address.String()
		sessMu.Lock()
		udpConn, exists := sessions[target]
		count := len(sessions)
		sessMu.Unlock()

		if !exists {
			if count >= maxUDPTargetsPerStream {
				log.Debug("udp target limit reached; dropping datagram", "limit", maxUDPTargetsPerStream)
				continue
			}
			udpAddr, err := safeResolveUDP(target, allowPrivateTargets)
			if err != nil {
				log.Debug("blocked or unresolvable udp relay target", "err", err)
				continue
			}
			udpConn, err = net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				log.Debug("dial udp target", "err", err)
				continue
			}
			sessMu.Lock()
			sessions[target] = udpConn
			sessMu.Unlock()

			go func(uConn *net.UDPConn, host string, port uint16, key string) {
				bp := relay.GetBuffer()
				defer relay.PutBuffer(bp)
				buf := *bp
				drop := func() {
					sessMu.Lock()
					if sessions[key] == uConn {
						delete(sessions, key)
					}
					sessMu.Unlock()
					uConn.Close()
				}
				for {
					uConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := uConn.Read(buf)
					if err != nil {
						drop()
						return
					}
					if n > protocol.MaxUDPPayloadLength {
						continue
					}
					if err := writePacket(host, port, buf[:n]); err != nil {
						drop()
						return
					}
					stats.Received.Add(uint64(n))
				}
			}(udpConn, pkt.Address.Host, pkt.Address.Port, target)
		}

		if _, err = udpConn.Write(pkt.Payload); err != nil {
			log.Debug("write to udp target", "err", err)
			sessMu.Lock()
			if sessions[target] == udpConn {
				delete(sessions, target)
			}
			sessMu.Unlock()
			udpConn.Close()
			continue
		}
		stats.Sent.Add(uint64(len(pkt.Payload)))
	}
}
