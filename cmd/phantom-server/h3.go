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
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/phantom-go/phantom/internal/auth"
	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/transport"
)

// h3Handler implements Phantom over HTTP/3.
//
// A Phantom stream is an HTTP/3 CONNECT request carrying
// "Proxy-Authorization: Bearer <SHA-224 hex>". After a 200 response the
// request stream carries the ordinary Phantom request header and payload.
// Every other request — including a CONNECT with a wrong or missing
// password — is reverse-proxied to the fallback web server, so a prober sees
// an ordinary HTTP/3 website.
type h3Handler struct {
	auth     auth.Authenticator
	limiter  *auth.RateLimiter
	metrics  *metrics.Metrics
	fallback *httpFallback
	local    net.Addr
}

func (h *h3Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remote := udpAddrFromString(r.RemoteAddr)

	authz := r.Header.Get("Proxy-Authorization")
	if r.Method != http.MethodConnect || authz == "" {
		h.fallback.ServeHTTP(w, r)
		return
	}
	if h.limiter.IsBanned(remote) {
		h.fallback.ServeHTTP(w, r)
		return
	}
	hash, ok := transport.ParseProxyAuth(authz)
	if !ok || !h.auth.Verify(hash) {
		h.limiter.RecordFailure(remote)
		h.fallback.ServeHTTP(w, r)
		return
	}
	h.limiter.RecordSuccess(remote)

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	str, err := streamer.HTTPStream()
	if err != nil {
		return
	}
	conn := &transport.H3StreamConn{Str: str, Local: h.local, Remote: remote}
	// Same path as smux streams: parse the inner Phantom header and relay.
	handleConn(conn, h.auth, h.limiter, h.metrics, "h3", func() {})
}

func udpAddrFromString(s string) net.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return net.UDPAddrFromAddrPort(ap)
	}
	return &net.UDPAddr{}
}

// serveQUIC accepts QUIC connections and serves each as HTTP/3.
func serveQUIC(ln *transport.QUICListener, wg *sync.WaitGroup, h *h3Handler) {
	srv := &http3.Server{
		Handler:        h,
		MaxHeaderBytes: 16 << 10,
		Logger:         slog.New(log.Handler()).With("component", "http3"),
	}
	var backoff time.Duration
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				srv.Close()
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			log.Warn("quic accept error; retrying", "err", err, "backoff", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		// Banned sources are still served as a website (the handler only
		// refuses Phantom streams), exactly like the TCP path.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = srv.ServeQUICConn(conn)
		}()
	}
}
