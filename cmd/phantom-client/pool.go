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
	"errors"
	"io"
	"sync"
	"time"
)

// errPoolUnavailable is returned when the pool has no healthy session and a
// fresh dial also failed.
var errPoolUnavailable = errors.New("session pool: no healthy session available")

// pooledSession is the minimal behaviour the pool needs from an underlying
// transport session (smux over TLS/WS, or a QUIC connection). Both the
// smux-backed and QUIC-backed implementations live in main.go.
type pooledSession interface {
	// OpenStream opens a new multiplexed stream as a duplex byte pipe.
	OpenStream() (io.ReadWriteCloser, error)
	// Healthy reports whether the session is still usable.
	Healthy() bool
	// NumStreams returns the number of currently-open streams, used to
	// decide when on-demand growth is warranted.
	NumStreams() int
	// Close tears the session down.
	Close() error
}

// dialFn establishes one new underlying session. It is always called WITHOUT
// the pool lock held, so a slow TLS/QUIC handshake never blocks other
// goroutines acquiring an already-established session (this is the #5 fix).
type dialFn func() (pooledSession, error)

// sessionPool keeps up to maxSize underlying sessions to the server and hands
// out streams across them.
//
// Growth is on demand, never eager: the pool starts empty and opens its first
// session on the first request. A second (and further, up to maxSize) session
// is opened only when every existing healthy session is already carrying at
// least growthThreshold concurrent streams — so a pool configured with
// maxSize=4 still presents just one connection until real load justifies more,
// avoiding a burst of simultaneous handshakes at startup.
//
// When maxSize == 1 the pool degenerates to exactly the original
// single-session behaviour: one connection, reused, re-dialled on death.
type sessionPool struct {
	mu       sync.Mutex
	sessions []pooledSession
	rr       int // round-robin cursor

	maxSize         int
	growthThreshold int
	dial            dialFn

	// dialing guards against multiple goroutines dialling concurrently when
	// they all observe "needs growth" at once. Only one new dial is in
	// flight at a time; others reuse whatever is currently available.
	dialing bool
	// dialDone is closed when the in-flight dial finishes. Callers that
	// find the pool EMPTY while a dial is in flight wait on it instead of
	// starting their own dial. Previously "empty" bypassed the dialing
	// guard, so N concurrent requests at startup or after a disconnect
	// fired N simultaneous TLS handshakes (a loud fingerprint, wasted
	// RTTs) and appended all N sessions — ignoring maxSize entirely.
	dialDone chan struct{}

	// idleTimeout closes sessions that have carried no streams for this
	// long (0 = keep sessions forever and re-dial an empty pool, the
	// pre-2.0 always-on behaviour). idleSince records when each session
	// was first seen idle.
	idleTimeout time.Duration
	idleSince   map[pooledSession]time.Time
}

// withIdleTimeout enables closing idle sessions; it returns p for chaining.
func (p *sessionPool) withIdleTimeout(d time.Duration) *sessionPool {
	p.mu.Lock()
	p.idleTimeout = d
	p.mu.Unlock()
	return p
}

// newSessionPool builds a pool. maxSize < 1 is clamped to 1. growthThreshold
// is the per-session concurrent-stream count above which the pool will
// consider opening another session (ignored when maxSize == 1).
func newSessionPool(maxSize, growthThreshold int, dial dialFn) *sessionPool {
	if maxSize < 1 {
		maxSize = 1
	}
	if growthThreshold < 1 {
		growthThreshold = 1
	}
	return &sessionPool{
		maxSize:         maxSize,
		growthThreshold: growthThreshold,
		dial:            dial,
	}
}

// pruneLocked drops dead sessions. Caller holds p.mu.
func (p *sessionPool) pruneLocked() {
	live := p.sessions[:0]
	for _, s := range p.sessions {
		if s.Healthy() {
			live = append(live, s)
		} else {
			s.Close()
		}
	}
	p.sessions = live
	if len(p.sessions) == 0 {
		p.rr = 0
	} else if p.rr >= len(p.sessions) {
		p.rr = 0
	}
}

// pickLocked returns the next healthy session round-robin, or nil if the pool
// is empty. Caller holds p.mu.
func (p *sessionPool) pickLocked() pooledSession {
	if len(p.sessions) == 0 {
		return nil
	}
	s := p.sessions[p.rr%len(p.sessions)]
	p.rr++
	return s
}

// minLoadLocked reports the smallest NumStreams across healthy sessions.
// Caller holds p.mu. Returns 0 when there are no sessions.
func (p *sessionPool) minLoadLocked() int {
	if len(p.sessions) == 0 {
		return 0
	}
	min := -1
	for _, s := range p.sessions {
		n := s.NumStreams()
		if min < 0 || n < min {
			min = n
		}
	}
	if min < 0 {
		return 0
	}
	return min
}

// OpenStream acquires a stream from the pool, dialling a new session if needed.
// The dial happens with the lock released.
func (p *sessionPool) OpenStream() (io.ReadWriteCloser, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		p.mu.Lock()
		p.pruneLocked()

		empty := len(p.sessions) == 0
		if empty && p.dialing {
			// Someone is already establishing the first session: wait
			// for it rather than piling on another handshake.
			ch := p.dialDone
			p.mu.Unlock()
			<-ch
			continue
		}

		needDial := empty ||
			(len(p.sessions) < p.maxSize &&
				p.minLoadLocked() >= p.growthThreshold &&
				!p.dialing)

		if !needDial {
			s := p.pickLocked()
			p.mu.Unlock()
			if s == nil {
				continue
			}
			stream, err := s.OpenStream()
			if err != nil {
				lastErr = err
				continue
			}
			return stream, nil
		}

		sess, err := p.dialLocked()
		if err != nil {
			lastErr = err
			// Dial failed. Fall back to any usable session.
			p.mu.Lock()
			p.pruneLocked()
			s := p.pickLocked()
			p.mu.Unlock()
			if s != nil {
				if stream, oerr := s.OpenStream(); oerr == nil {
					return stream, nil
				}
			}
			return nil, err
		}

		stream, oerr := sess.OpenStream()
		if oerr != nil {
			lastErr = oerr
			continue
		}
		return stream, nil
	}

	p.mu.Lock()
	p.pruneLocked()
	s := p.pickLocked()
	p.mu.Unlock()
	if s != nil {
		return s.OpenStream()
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errPoolUnavailable
}

// dialLocked is entered with p.mu held and returns with it released. It marks
// a dial in flight, performs it unlocked, publishes the result, and wakes any
// waiters.
func (p *sessionPool) dialLocked() (pooledSession, error) {
	p.dialing = true
	done := make(chan struct{})
	p.dialDone = done
	p.mu.Unlock()

	sess, err := p.dial()

	p.mu.Lock()
	p.dialing = false
	p.dialDone = nil
	if err == nil {
		if len(p.sessions) < p.maxSize {
			p.sessions = append(p.sessions, sess)
		} else {
			// Defensive: never exceed maxSize.
			p.mu.Unlock()
			close(done)
			sess.Close()
			return nil, errPoolUnavailable
		}
	}
	p.mu.Unlock()
	close(done)
	return sess, err
}

// keepAlive runs in the background, periodically pruning dead sessions and
// ensuring at least one session exists so the first request after an idle gap
// doesn't pay the full reconnect latency. It never grows the pool beyond one
// session on its own — growth past one is strictly load-driven via OpenStream.
func (p *sessionPool) keepAlive(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			p.mu.Lock()
			p.pruneLocked()
			if p.idleTimeout > 0 {
				p.closeIdleLocked(time.Now())
				p.mu.Unlock()
				continue
			}
			// Always-on mode: keep one session up even with no traffic.
			if len(p.sessions) == 0 && !p.dialing {
				_, _ = p.dialLocked()
			} else {
				p.mu.Unlock()
			}
		}
	}
}

// closeIdleLocked closes sessions that have had no streams for idleTimeout.
// A closed session is simply re-dialled by the next OpenStream. Caller holds
// p.mu.
func (p *sessionPool) closeIdleLocked(now time.Time) {
	if p.idleSince == nil {
		p.idleSince = make(map[pooledSession]time.Time)
	}
	keep := p.sessions[:0]
	for _, s := range p.sessions {
		if s.NumStreams() > 0 {
			delete(p.idleSince, s)
			keep = append(keep, s)
			continue
		}
		since, seen := p.idleSince[s]
		if !seen {
			p.idleSince[s] = now
			keep = append(keep, s)
			continue
		}
		if now.Sub(since) >= p.idleTimeout {
			delete(p.idleSince, s)
			s.Close()
			continue
		}
		keep = append(keep, s)
	}
	p.sessions = keep
	if p.rr >= len(p.sessions) {
		p.rr = 0
	}
	// Forget sessions that pruneLocked already removed.
	for s := range p.idleSince {
		found := false
		for _, live := range p.sessions {
			if live == s {
				found = true
				break
			}
		}
		if !found {
			delete(p.idleSince, s)
		}
	}
}

// Close tears down every session in the pool.
func (p *sessionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		s.Close()
	}
	p.sessions = nil
}
