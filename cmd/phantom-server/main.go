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
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/phantom-go/phantom/internal/auth"
	"github.com/phantom-go/phantom/internal/config"
	"github.com/phantom-go/phantom/internal/logger"
	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/resolver"
	"github.com/phantom-go/phantom/internal/transport"
)

var log *slog.Logger

// allowPrivateTargets mirrors cfg.Server.AllowPrivateTargets. Set once at
// startup; read by the SSRF guard.
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
	// connections process-wide; maxPendingPerSource caps them per source
	// IP (IPv6: per /64) so one source cannot occupy every global slot;
	// maxPendingPerSession caps unauthenticated streams inside ONE smux
	// session.
	maxPendingHandshakes = 4096
	maxPendingPerSource  = 64
	maxPendingPerSession = 64
	// maxFallbackConns caps concurrent connections proxied to the
	// fallback web server so a probe flood cannot exhaust its sockets.
	maxFallbackConns = 2048
	// maxUDPTargetsPerStream caps distinct destinations per UDP association.
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
	pendingSem      = make(chan struct{}, maxPendingHandshakes)
	pendingBySource = auth.NewConcurrencyLimiter(maxPendingPerSource)
	fallbackSem     = make(chan struct{}, maxFallbackConns)
)

// trojanNotice is logged at startup and on the first trojan:// connection.
const trojanNotice = "trojan:// compatibility is temporary and provides basic proxying only; " +
	"it may be removed in a future release. Use phantom:// for full performance and security."

var trojanSeen sync.Once

// certStore serves the certificate through tls.Config.GetCertificate so it
// can be replaced on SIGHUP (e.g. after a Let's Encrypt renewal).
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

// newResolver builds the target resolver from config.
func newResolver(sc *config.ServerConfig) (resolver.Resolver, error) {
	if len(sc.DNSOverTLS) == 0 {
		return resolver.System{}, nil
	}
	return resolver.NewDoT(sc.DNSOverTLS, sc.DNSTLSName, resolver.System{}, log)
}

func main() {
	useQUIC := flag.Bool("quic", false, "use QUIC (HTTP/3) transport")
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
		log.Warn("config file is readable by other users and contains passwords; run: chmod 640 " + *configPath)
	}
	if os.Geteuid() == 0 {
		log.Warn("running as root; run phantom-server as an unprivileged user with CAP_NET_BIND_SERVICE (the installer does this)")
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
	setFallbacks(cfg.Server.FallbackAddr, cfg.Server.FallbackH2Addr)

	if targetResolver, err = newResolver(&cfg.Server); err != nil {
		log.Error("dns", "err", err)
		os.Exit(1)
	}
	if len(cfg.Server.DNSOverTLS) == 0 {
		log.Info("relay targets are resolved with the system resolver (plaintext); set dns_over_tls for private lookups")
	}

	certs := &certStore{}
	if err := certs.load(cfg.Server.CertFile, cfg.Server.KeyFile); err != nil {
		log.Error("load cert", "err", err)
		os.Exit(1)
	}

	// Advertise exactly what an ordinary modern HTTPS site does. phantom-
	// client sends the browser ALPN list, so no Phantom-specific value is
	// needed — and offering one let any prober confirm a Phantom server.
	tlsCfg := &tls.Config{
		GetCertificate: certs.get,
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	}

	authenticator := auth.NewStaticAuth(cfg.Server.Passwords)
	limiter := auth.NewRateLimiter(20, 5*time.Minute, 5*time.Minute)
	defer limiter.Close()
	m := metrics.New()
	webFallback := &httpFallback{}

	var wg sync.WaitGroup
	var shuttingDown atomic.Bool
	var closers []func()

	switch {
	case quicEnabled:
		ql, err := transport.ListenQUIC(cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen quic", "err", err)
			os.Exit(1)
		}
		closers = append(closers, func() { ql.Close() })
		log.Info("listening on QUIC (HTTP/3)", "addr", cfg.Server.Listen, "version", version)
		h := &h3Handler{auth: authenticator, limiter: limiter, metrics: m, fallback: webFallback, local: ql.Addr()}
		go handleSignals(*configPath, cfg, certs, authenticator, m, &shuttingDown, closers)
		serveQUIC(ql, &wg, h)

	case cfg.Server.Transport == "ws":
		ln, err := tls.Listen("tcp", cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
		log.Info("listening on TCP (WebSocket mode)", "addr", cfg.Server.Listen, "path", cfg.Server.WSPath, "version", version)
		mux := http.NewServeMux()
		mux.HandleFunc(cfg.Server.WSPath, func(w http.ResponseWriter, r *http.Request) {
			if limiter.IsBanned(transport.ClientAddr(r, cfg.Server.TrustProxyHeaders)) {
				webFallback.ServeHTTP(w, r)
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
		mux.Handle("/", webFallback)
		httpServer := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: handshakeTimeout,
			IdleTimeout:       probeIdleTimeout,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		}
		closers = append(closers, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = httpServer.Shutdown(ctx)
			cancel()
		})
		go handleSignals(*configPath, cfg, certs, authenticator, m, &shuttingDown, closers)
		_ = httpServer.Serve(ln)

	default:
		ln, err := tls.Listen("tcp", cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
		closers = append(closers, func() { ln.Close() })
		log.Info("listening on TCP", "addr", cfg.Server.Listen, "version", version)
		go handleSignals(*configPath, cfg, certs, authenticator, m, &shuttingDown, closers)
		acceptLoop(ln, &wg, func(c net.Conn) {
			handleSession(c, authenticator, limiter, m)
		})
	}

	waitTimeout(&wg, shutdownGrace)
	if d, ok := targetResolver.(*resolver.DoT); ok {
		d.Close()
	}
	log.Info("shutdown complete")
}

func handleSignals(configPath string, cfg *config.Config, certs *certStore, authenticator auth.Authenticator, m *metrics.Metrics, shuttingDown *atomic.Bool, closers []func()) {
	log.Info("native protocol: phantom://. " + trojanNotice)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s != syscall.SIGHUP {
			logStats(m)
			log.Info("shutting down")
			shuttingDown.Store(true)
			for _, c := range closers {
				c()
			}
			return
		}
		log.Info("received SIGHUP, reloading configuration")
		newCfg, err := config.LoadFromFile(configPath)
		if err != nil {
			log.Error("reload config failed", "err", err)
			continue
		}
		if newCfg.Server.Listen != cfg.Server.Listen {
			log.Warn("listen address change requires restart", "current", cfg.Server.Listen, "ignored", newCfg.Server.Listen)
		}
		setFallbacks(newCfg.Server.FallbackAddr, newCfg.Server.FallbackH2Addr)
		authenticator.Reload(newCfg.Server.Passwords)
		if err := certs.load(newCfg.Server.CertFile, newCfg.Server.KeyFile); err != nil {
			log.Error("reload cert failed; keeping previous certificate", "err", err)
		} else {
			log.Info("certificate reloaded")
		}
		logStats(m)
		log.Info("config reloaded")
	}
}

// acceptLoop accepts until the listener is closed. Transient errors such as
// EMFILE/ENFILE back off and retry instead of ending the process.
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
