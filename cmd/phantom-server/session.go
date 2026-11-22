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
	"io"
	"net"
	"sync"
	"time"

	"github.com/phantom-go/phantom/internal/auth"
	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/protocol"
	"github.com/phantom-go/phantom/internal/relay"
	"github.com/phantom-go/phantom/internal/transport"
)

// handleSession serves one TLS (or WebSocket) connection: a bare Trojan
// header, an smux session, or — for anything else — the fallback website.
func handleSession(conn net.Conn, authenticator auth.Authenticator, limiter *auth.RateLimiter, m *metrics.Metrics) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()

	if limiter.IsBanned(remoteAddr) {
		log.Debug("banned IP attempted connection, falling back", "addr", remoteAddr)
		doFallback(conn, remoteAddr, negotiatedALPN(conn))
		return
	}

	// Unauthenticated phase: bounded per source AND globally. Per-source
	// first, so a single source can never drain the global pool.
	releaseSource, ok := pendingBySource.Acquire(remoteAddr)
	if !ok {
		return
	}
	if !tryAcquire(pendingSem) {
		releaseSource()
		return // overloaded with unauthenticated connections: shed load
	}
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			<-pendingSem
			releaseSource()
		})
	}
	defer release()

	rconn := transport.NewRewindConn(conn)
	rconn.SetDeadline(time.Now().Add(handshakeTimeout))

	header, err := protocol.ParseHeader(rconn)
	alpn := negotiatedALPN(conn) // handshake has completed (or failed) by now
	if err == nil {
		rconn.SetDeadline(time.Time{})
		if !authenticator.Verify(header.PasswordHash) {
			limiter.RecordFailure(remoteAddr)
			rconn.Rewind()
			release()
			doFallback(rconn, remoteAddr, alpn)
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
	// first byte already captured by the rewind buffer. A silent connection
	// gets a bounded probeIdleTimeout to produce its first byte.
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
		doFallback(rconn, remoteAddr, alpn)
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
	serveStreams(streams, func() bool { return limiter.IsBanned(remoteAddr) }, authenticator, limiter, m, alpn)
}

// serveStreams runs handleConn for each stream of one smux session, with at
// most maxPendingPerSession streams in the unauthenticated phase at once. If
// the peer gets banned mid-session the whole session is dropped.
func serveStreams(streams <-chan net.Conn, banned func() bool, authenticator auth.Authenticator, limiter *auth.RateLimiter, m *metrics.Metrics, alpn string) {
	sem := make(chan struct{}, maxPendingPerSession)
	for st := range streams {
		if banned() {
			st.Close()
			return
		}
		sem <- struct{}{}
		go handleConn(st, authenticator, limiter, m, alpn, func() { <-sem })
	}
}

// handleConn serves one stream inside an authenticated-transport session
// (smux stream or HTTP/3 CONNECT stream).
func handleConn(conn net.Conn, authenticator auth.Authenticator, limiter *auth.RateLimiter, m *metrics.Metrics, alpn string, release func()) {
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
		done()
		if err != nil && len(rconn.Recorded()) == 0 {
			// The peer opened a stream and closed it (or let it idle)
			// without sending a single byte. That is not a login attempt
			// — v1.x counted it as one, so 20 local SOCKS port checks
			// could get a legitimate user banned for 5 minutes.
			return
		}
		// Malformed or wrong-password data inside a tunnel: no innocent
		// prober can produce this, so it counts towards the ban.
		limiter.RecordFailure(remoteAddr)
		if alpn == "h3" {
			return // HTTP/3 streams already passed outer auth; just close
		}
		rconn.Rewind()
		rconn.SetDeadline(time.Time{})
		doFallback(rconn, remoteAddr, alpn)
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
