// Phantom — encrypted transport framework
// Copyright (C) 2026 The Phantom Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL <https://www.gnu.org/licenses/> for details.

// Package resolver resolves relay targets for phantom-server.
//
// Go's built-in resolver sends every lookup in plaintext to the resolver in
// /etc/resolv.conf (normally the VPS provider's) and caches nothing. For a
// proxy that means the provider — and anyone on the path to its resolver —
// sees every domain every user visits, and each new proxied connection pays
// a DNS round trip.
//
// DoT fixes both: queries go over TLS (RFC 7858) on a small pool of
// persistent connections, are padded to a block size (RFC 8467) so their
// length does not reveal the domain length, answers are cached for their TTL,
// and identical concurrent lookups are coalesced.
package resolver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Resolver looks up the addresses of a host name.
type Resolver interface {
	LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// System is the operating system's resolver (the pre-2.0 behaviour).
type System struct{}

// LookupNetIP implements Resolver.
func (System) LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

const (
	minTTL       = 5 * time.Second
	maxTTL       = 30 * time.Minute
	negativeTTL  = 15 * time.Second
	maxCache     = 8192
	maxIdleConns = 4
	exchangeTO   = 5 * time.Second
	paddingBlock = 128 // RFC 8467 recommended query block size
)

// ErrNotFound reports that the name has no A/AAAA records.
var ErrNotFound = errors.New("resolver: no such host")

// DoT is a caching DNS-over-TLS resolver.
type DoT struct {
	servers  []string // "ip:port"
	tlsCfg   *tls.Config
	fallback Resolver // used when every DoT server is unreachable; nil = fail
	log      *slog.Logger

	idleMu sync.Mutex
	idle   []*tls.Conn

	cacheMu sync.Mutex
	cache   map[string]cacheEntry

	flightMu sync.Mutex
	flights  map[string]*flight

	lastWarn atomic.Int64
	dial     func(ctx context.Context, addr string) (net.Conn, error) // test hook
}

type cacheEntry struct {
	addrs   []netip.Addr
	err     error
	expires time.Time
}

type flight struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// NewDoT returns a DoT resolver. servers are "ip" or "ip:port" (port 853 by
// default); serverName is the name the resolver's certificate must match.
// fallback (may be nil) is consulted only when no DoT server can be reached.
func NewDoT(servers []string, serverName string, fallback Resolver, log *slog.Logger) (*DoT, error) {
	if len(servers) == 0 {
		return nil, errors.New("resolver: no DoT servers configured")
	}
	if serverName == "" {
		return nil, errors.New("resolver: dns_tls_name is required to authenticate the DoT server")
	}
	norm := make([]string, 0, len(servers))
	for _, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(strings.Trim(s, "[]"), "853")
		}
		host, _, _ := net.SplitHostPort(s)
		if _, err := netip.ParseAddr(host); err != nil {
			// An IP is required: resolving the resolver would leak the
			// first query in plaintext and create a bootstrap loop.
			return nil, fmt.Errorf("resolver: DoT server %q must be an IP address", s)
		}
		norm = append(norm, s)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	d := &DoT{
		servers: norm,
		tlsCfg: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
		fallback: fallback,
		log:      log,
		cache:    make(map[string]cacheEntry),
		flights:  make(map[string]*flight),
	}
	d.dial = d.dialTLS
	return d, nil
}

// LookupNetIP implements Resolver.
func (d *DoT) LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	// RFC 6761: "localhost" never goes to the network.
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if host == "" || len(host) > 253 {
		return nil, ErrNotFound
	}

	now := time.Now()
	d.cacheMu.Lock()
	if e, ok := d.cache[host]; ok && now.Before(e.expires) {
		d.cacheMu.Unlock()
		return e.addrs, e.err
	}
	d.cacheMu.Unlock()

	// Coalesce concurrent lookups of the same name.
	d.flightMu.Lock()
	if f, ok := d.flights[host]; ok {
		d.flightMu.Unlock()
		select {
		case <-f.done:
			return f.addrs, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	d.flights[host] = f
	d.flightMu.Unlock()

	f.addrs, f.err = d.resolve(host)

	d.flightMu.Lock()
	delete(d.flights, host)
	d.flightMu.Unlock()
	close(f.done)

	return f.addrs, f.err
}

// resolve queries A and AAAA in parallel and caches the result. It uses its
// own timeout rather than the caller's context so one impatient caller does
// not fail a lookup that other callers are waiting on.
func (d *DoT) resolve(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*exchangeTO)
	defer cancel()

	type res struct {
		addrs []netip.Addr
		ttl   time.Duration
		nx    bool
		err   error
	}
	ch := make(chan res, 2)
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA} {
		go func(qt dnsmessage.Type) {
			a, ttl, nx, err := d.query(ctx, host, qt)
			ch <- res{a, ttl, nx, err}
		}(qt)
	}
	var addrs []netip.Addr
	ttl := maxTTL
	var errs []error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		addrs = append(addrs, r.addrs...)
		if len(r.addrs) > 0 && r.ttl < ttl {
			ttl = r.ttl
		}
	}

	if len(addrs) == 0 && len(errs) > 0 {
		// Transport failure: no answer at all from any DoT server.
		if d.fallback != nil {
			d.warn("DoT resolver unreachable; falling back to the system resolver for this lookup", errors.Join(errs...))
			return d.fallback.LookupNetIP(ctx, host)
		}
		return nil, fmt.Errorf("resolver: %w", errors.Join(errs...))
	}

	var err error
	expires := time.Now().Add(clampTTL(ttl))
	if len(addrs) == 0 {
		err = ErrNotFound
		expires = time.Now().Add(negativeTTL)
	}
	d.store(host, cacheEntry{addrs: addrs, err: err, expires: expires})
	return addrs, err
}

func clampTTL(t time.Duration) time.Duration {
	if t < minTTL {
		return minTTL
	}
	if t > maxTTL {
		return maxTTL
	}
	return t
}

func (d *DoT) store(host string, e cacheEntry) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	if len(d.cache) >= maxCache {
		// Drop expired entries first, then arbitrary ones (map order is
		// random) — amortised O(1) per insert.
		now := time.Now()
		dropped := 0
		for k, v := range d.cache {
			if now.After(v.expires) || dropped < maxCache/16 {
				delete(d.cache, k)
				dropped++
			}
			if dropped >= maxCache/16 {
				break
			}
		}
	}
	d.cache[host] = e
}

func (d *DoT) warn(msg string, err error) {
	now := time.Now().Unix()
	if last := d.lastWarn.Load(); now-last >= 60 && d.lastWarn.CompareAndSwap(last, now) {
		d.log.Warn(msg, "err", err)
	}
}

// query performs one question, trying each server in turn.
func (d *DoT) query(ctx context.Context, host string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, bool, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, false, ErrNotFound
	}
	var lastErr error
	for _, server := range d.servers {
		for attempt := 0; attempt < 2; attempt++ {
			// attempt 0 may reuse a pooled connection the server has
			// already closed; attempt 1 always dials fresh.
			addrs, ttl, nx, err := d.exchange(ctx, server, name, qt, attempt == 0)
			if err == nil {
				return addrs, ttl, nx, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				return nil, 0, false, ctx.Err()
			}
		}
	}
	return nil, 0, false, lastErr
}

func (d *DoT) exchange(ctx context.Context, server string, name dnsmessage.Name, qt dnsmessage.Type, reuse bool) ([]netip.Addr, time.Duration, bool, error) {
	var conn *tls.Conn
	if reuse {
		conn = d.getIdle(server)
	}
	if conn == nil {
		c, err := d.dial(ctx, server)
		if err != nil {
			return nil, 0, false, err
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			c.Close()
			return nil, 0, false, errors.New("resolver: dial returned non-TLS conn")
		}
		conn = tc
	}

	id, query, err := buildQuery(name, qt)
	if err != nil {
		conn.Close()
		return nil, 0, false, err
	}
	deadline := time.Now().Add(exchangeTO)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(query); err != nil {
		conn.Close()
		return nil, 0, false, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		conn.Close()
		return nil, 0, false, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, 0, false, err
	}
	_ = conn.SetDeadline(time.Time{})

	addrs, ttl, nx, err := parseResponse(resp, id, name, qt)
	if err != nil {
		conn.Close()
		return nil, 0, false, err
	}
	d.putIdle(conn)
	return addrs, ttl, nx, nil
}

func (d *DoT) dialTLS(ctx context.Context, server string) (net.Conn, error) {
	dl := &net.Dialer{Timeout: exchangeTO}
	cfg := d.tlsCfg.Clone()
	return (&tls.Dialer{NetDialer: dl, Config: cfg}).DialContext(ctx, "tcp", server)
}

func (d *DoT) getIdle(server string) *tls.Conn {
	d.idleMu.Lock()
	defer d.idleMu.Unlock()
	for i := len(d.idle) - 1; i >= 0; i-- {
		c := d.idle[i]
		if c.RemoteAddr().String() == server {
			d.idle = append(d.idle[:i], d.idle[i+1:]...)
			return c
		}
	}
	return nil
}

func (d *DoT) putIdle(c *tls.Conn) {
	d.idleMu.Lock()
	defer d.idleMu.Unlock()
	if len(d.idle) >= maxIdleConns {
		c.Close()
		return
	}
	d.idle = append(d.idle, c)
}

// Close releases pooled connections.
func (d *DoT) Close() {
	d.idleMu.Lock()
	defer d.idleMu.Unlock()
	for _, c := range d.idle {
		c.Close()
	}
	d.idle = nil
}

// buildQuery returns a length-prefixed DNS query with EDNS(0) padding.
func buildQuery(name dnsmessage.Name, qt dnsmessage.Type) (uint16, []byte, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])

	build := func(pad int) ([]byte, error) {
		b := dnsmessage.NewBuilder(make([]byte, 2, 2+paddingBlock), dnsmessage.Header{ID: id, RecursionDesired: true})
		b.EnableCompression()
		if err := b.StartQuestions(); err != nil {
			return nil, err
		}
		if err := b.Question(dnsmessage.Question{Name: name, Type: qt, Class: dnsmessage.ClassINET}); err != nil {
			return nil, err
		}
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
			return nil, err
		}
		opts := []dnsmessage.Option{{Code: 12, Data: make([]byte, pad)}} // EDNS padding
		if err := b.OPTResource(rh, dnsmessage.OPTResource{Options: opts}); err != nil {
			return nil, err
		}
		return b.Finish()
	}

	// Measure, then pad the DNS message to a multiple of paddingBlock.
	msg, err := build(0)
	if err != nil {
		return 0, nil, err
	}
	size := len(msg) - 2
	pad := (paddingBlock - size%paddingBlock) % paddingBlock
	if pad != 0 {
		if msg, err = build(pad); err != nil {
			return 0, nil, err
		}
	}
	binary.BigEndian.PutUint16(msg[:2], uint16(len(msg)-2))
	return id, msg, nil
}

func parseResponse(resp []byte, id uint16, name dnsmessage.Name, qt dnsmessage.Type) ([]netip.Addr, time.Duration, bool, error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil, 0, false, err
	}
	if h.ID != id || !h.Response {
		return nil, 0, false, errors.New("resolver: mismatched DNS response")
	}
	q, err := p.Question()
	if err != nil || !strings.EqualFold(q.Name.String(), name.String()) || q.Type != qt {
		return nil, 0, false, errors.New("resolver: DNS response for a different question")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, false, err
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, negativeTTL, true, nil
	default:
		return nil, 0, false, fmt.Errorf("resolver: DNS server returned %v", h.RCode)
	}

	var addrs []netip.Addr
	ttl := maxTTL
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, false, err
		}
		if t := time.Duration(rh.TTL) * time.Second; t < ttl {
			ttl = t
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, 0, false, err
			}
			if qt == dnsmessage.TypeA {
				addrs = append(addrs, netip.AddrFrom4(r.A))
			}
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, 0, false, err
			}
			if qt == dnsmessage.TypeAAAA {
				addrs = append(addrs, netip.AddrFrom16(r.AAAA).Unmap())
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, false, err
			}
		}
	}
	return addrs, ttl, false, nil
}
