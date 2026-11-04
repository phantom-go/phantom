package auth

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultMaxEntries bounds the number of per-IP failure records the limiter
// will hold. Without a cap, a flood of failures from many distinct (or
// spoofed) source IPs grows the map unbounded between the 5-minute cleanup
// passes, which is a memory-exhaustion vector. When the cap is reached,
// RecordFailure evicts the least-recently-seen NON-banned records to make
// room. Banned records are never evicted by this path, so an attacker cannot
// flush out a legitimate ban by spraying fresh IPs.
const DefaultMaxEntries = 100_000

// RateLimiter tracks authentication failures per IP and bans abusive sources.
type RateLimiter struct {
	mu          sync.Mutex
	failures    map[string]*failureRecord
	maxFailures int
	maxEntries  int
	window      time.Duration
	banDuration time.Duration
	stopChan    chan struct{}
}

type failureRecord struct {
	count      int
	firstSeen  time.Time
	lastSeen   time.Time
	bannedTill time.Time
}

// NewRateLimiter creates a rate limiter that bans an IP for banDuration
// after maxFailures failed attempts within window. The number of tracked
// records is capped at DefaultMaxEntries.
func NewRateLimiter(maxFailures int, window, banDuration time.Duration) *RateLimiter {
	return NewRateLimiterWithCap(maxFailures, window, banDuration, DefaultMaxEntries)
}

// NewRateLimiterWithCap is NewRateLimiter with an explicit record cap. A
// maxEntries <= 0 is treated as DefaultMaxEntries.
func NewRateLimiterWithCap(maxFailures int, window, banDuration time.Duration, maxEntries int) *RateLimiter {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	rl := &RateLimiter{
		failures:    make(map[string]*failureRecord),
		maxFailures: maxFailures,
		maxEntries:  maxEntries,
		window:      window,
		banDuration: banDuration,
		stopChan:    make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Close stops the background cleanup goroutine and releases resources.
func (rl *RateLimiter) Close() {
	close(rl.stopChan)
}

// IsBanned reports whether the given remote address is currently banned.
func (rl *RateLimiter) IsBanned(addr net.Addr) bool {
	ip := extractIP(addr)
	if ip == "" {
		return false
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rec, ok := rl.failures[ip]
	if !ok {
		return false
	}
	return time.Now().Before(rec.bannedTill)
}

// RecordFailure increments the failure count for an IP. If the count exceeds
// maxFailures within window, the IP is banned for banDuration.
func (rl *RateLimiter) RecordFailure(addr net.Addr) {
	ip := extractIP(addr)
	if ip == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rec, ok := rl.failures[ip]

	// Reset window if record does not exist, or window expired and IP is not currently banned
	if !ok || (now.Sub(rec.firstSeen) > rl.window && now.After(rec.bannedTill)) {
		// Bound memory: before inserting a brand-new key, make room if we
		// are at the cap. Updating an existing key never grows the map, so
		// eviction only gates genuine inserts.
		if !ok && len(rl.failures) >= rl.maxEntries {
			rl.evictOldestLocked(now)
		}
		rl.failures[ip] = &failureRecord{count: 1, firstSeen: now, lastSeen: now}
		return
	}

	rec.lastSeen = now

	// Already banned: do nothing, let the ban expire naturally
	if now.Before(rec.bannedTill) {
		return
	}

	rec.count++
	if rec.count >= rl.maxFailures {
		rec.bannedTill = now.Add(rl.banDuration)
	}
}

// evictOldestLocked makes room under the cap. Callers must hold rl.mu.
//
// The previous implementation scanned the WHOLE map to delete a single
// least-recently-seen entry on every insert once the cap was reached. Under
// exactly the attack the cap exists for (a spray of fresh source IPs), each
// failure did a 100k-entry scan while holding the global mutex that every
// new connection's IsBanned() also needs — an O(n) CPU amplification that
// stalled the accept path.
//
// Now one pass reclaims a batch (1/64 of the cap): expired records first,
// then arbitrary non-banned ones (Go map iteration order is randomised, so
// this is random eviction). The scan cost is amortised over the batch,
// giving O(64) work per insert.
//
// Banned records are deliberately exempt: evicting them would let an
// attacker flush an active ban by spamming fresh source IPs.
func (rl *RateLimiter) evictOldestLocked(now time.Time) {
	batch := rl.maxEntries / 64
	if batch < 1 {
		batch = 1
	}
	removed := 0
	for ip, rec := range rl.failures {
		if now.Sub(rec.firstSeen) > rl.window && now.After(rec.bannedTill) {
			delete(rl.failures, ip)
			removed++
		}
	}
	if removed >= batch {
		return
	}
	for ip, rec := range rl.failures {
		if removed >= batch {
			return
		}
		if now.Before(rec.bannedTill) {
			continue // never evict an active ban
		}
		delete(rl.failures, ip)
		removed++
	}
}

// RecordSuccess clears the failure record for an IP on successful auth.
func (rl *RateLimiter) RecordSuccess(addr net.Addr) {
	ip := extractIP(addr)
	if ip == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.failures, ip)
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, rec := range rl.failures {
				// Only cleanup if window expired and IP is not actively banned
				if now.Sub(rec.firstSeen) > rl.window && now.After(rec.bannedTill) {
					delete(rl.failures, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

// extractIP returns the rate-limit key for addr.
//
// IPv4 addresses are keyed individually. IPv6 addresses are keyed by their
// /64 prefix: a single customer/VM is routinely handed a whole /64 (2^64
// addresses), so per-/128 accounting let one attacker rotate source
// addresses indefinitely and never accumulate enough failures to be banned.
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	var ip netip.Addr
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return ""
		}
		ip, _ = netip.ParseAddr(host)
		if !ip.IsValid() {
			return host
		}
	}
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}
