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
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phantom-go/phantom/internal/relay"
)

// fallbackTargets is swapped atomically on SIGHUP.
type fallbackTargets struct {
	http1 string // plain HTTP/1.1 web server (fallback_addr)
	h2    string // HTTP/2 (prior-knowledge) web server (fallback_h2_addr)
}

var fallbacks atomic.Pointer[fallbackTargets]

func setFallbacks(http1, h2 string) { fallbacks.Store(&fallbackTargets{http1: http1, h2: h2}) }

// fallbackFor picks the backend that speaks the protocol the prober
// negotiated, so an h2 prober gets a genuine HTTP/2 response.
func fallbackFor(alpn string) string {
	t := fallbacks.Load()
	if t == nil {
		return ""
	}
	if alpn == "h2" && t.h2 != "" {
		return t.h2
	}
	return t.http1
}

// negotiatedALPN completes the TLS handshake if needed (bounded) and returns
// the negotiated protocol. Non-TLS conns report "".
func negotiatedALPN(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return ""
	}
	if !tc.ConnectionState().HandshakeComplete {
		_ = tc.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tc.Handshake(); err != nil {
			return ""
		}
		_ = tc.SetDeadline(time.Time{})
	}
	return tc.ConnectionState().NegotiatedProtocol
}

// doFallback replays conn to the web server matching alpn.
func doFallback(conn net.Conn, remoteAddr net.Addr, alpn string) {
	addr := fallbackFor(alpn)
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

	log.Debug("fallback connection", "from", remoteAddr, "alpn", alpn)
	relay.Pipe(conn, remote, fallbackIdleTimeout)
}

// httpFallback serves non-Phantom HTTP requests (WebSocket mode, HTTP/3)
// by reverse-proxying them to fallback_addr, so probers see the real site.
type httpFallback struct {
	mu    sync.Mutex
	addr  string
	proxy *httputil.ReverseProxy
}

func (h *httpFallback) current() *httputil.ReverseProxy {
	addr := fallbackFor("")
	if addr == "" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.proxy != nil && h.addr == addr {
		return h.proxy
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
	p := &httputil.ReverseProxy{
		// Rewrite (unlike the deprecated Director) never adds
		// X-Forwarded-* headers unless asked, so the fallback site does
		// not learn client addresses, and hop-by-hop headers — including
		// Proxy-Authorization, which carries Phantom credentials on
		// HTTP/3 — are already stripped from the outbound request.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = pr.In.Host // keep the Host the visitor asked for
		},
	}
	p.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	h.addr, h.proxy = addr, p
	return p
}

func (h *httpFallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p := h.current(); p != nil {
		p.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}
