// Phantom — encrypted transport framework
// Copyright (C) 2026 The Phantom Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL <https://www.gnu.org/licenses/> for details.

package auth

import (
	"net"
	"sync"
)

// SourceKey returns the identity used for per-source accounting: the IPv4
// address, or the IPv6 /64 prefix (see extractIP).
func SourceKey(addr net.Addr) string { return extractIP(addr) }

// ConcurrencyLimiter caps how many operations one source (IPv4 address or
// IPv6 /64) may have in flight at once.
//
// It exists for the unauthenticated handshake phase. A process-wide cap alone
// is not enough: a single attacker could hold every global slot with idle TLS
// connections and lock all other users out (verified in the v1.3.1 audit:
// 4096 idle connections from one IP made the server refuse everyone). With a
// per-source cap, one source can only ever occupy its own share.
type ConcurrencyLimiter struct {
	mu    sync.Mutex
	limit int
	inUse map[string]int
}

// NewConcurrencyLimiter returns a limiter allowing limit concurrent
// operations per source.
func NewConcurrencyLimiter(limit int) *ConcurrencyLimiter {
	if limit < 1 {
		limit = 1
	}
	return &ConcurrencyLimiter{limit: limit, inUse: make(map[string]int)}
}

// Acquire reserves a slot for addr's source. It returns a release function
// (safe to call more than once) and true, or nil and false when the source is
// already at its limit.
func (l *ConcurrencyLimiter) Acquire(addr net.Addr) (func(), bool) {
	key := extractIP(addr)
	l.mu.Lock()
	if l.inUse[key] >= l.limit {
		l.mu.Unlock()
		return nil, false
	}
	l.inUse[key]++
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if n := l.inUse[key] - 1; n > 0 {
				l.inUse[key] = n
			} else {
				delete(l.inUse, key) // map never accumulates idle sources
			}
			l.mu.Unlock()
		})
	}, true
}

// InUse reports the number of slots currently held by addr's source.
func (l *ConcurrencyLimiter) InUse(addr net.Addr) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inUse[extractIP(addr)]
}
