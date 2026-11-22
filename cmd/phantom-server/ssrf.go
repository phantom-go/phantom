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
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/phantom-go/phantom/internal/resolver"
)

// blockedPrefixes are ranges the SSRF guard refuses in addition to the
// stdlib loopback / private / link-local / multicast / unspecified checks.
var blockedPrefixes = func() []netip.Prefix {
	ps := []string{
		"0.0.0.0/8",     // "this network"; 0.x can reach local services on Linux
		"100.64.0.0/10", // CGNAT — also Alibaba Cloud metadata (100.100.100.200) & Tailscale
		"192.0.0.0/24",  // IETF protocol assignments
		"198.18.0.0/15", // benchmarking; used for internal fabrics
		"240.0.0.0/4",   // reserved, incl. 255.255.255.255 broadcast
		"100::/64",      // IPv6 discard
		"2001::/32",     // Teredo (tunnels to arbitrary IPv4)
		"2001:db8::/32", // documentation
		"fec0::/10",     // deprecated site-local
	}
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local  = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

// isDisallowedAddr reports whether a relayed connection must not reach ip when
// the SSRF guard is active: loopback, link-local (incl. the 169.254.169.254
// cloud-metadata endpoint), private (RFC 1918 / ULA, incl. AWS fd00:ec2::254),
// CGNAT, reserved, multicast, unspecified — and IPv6 transition addresses
// (NAT64, 6to4) whose embedded IPv4 is any of the above, which previously let
// "64:ff9b::7f00:1" reach 127.0.0.1 through a NAT64 gateway.
func isDisallowedAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsPrivate() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	if ip.Is6() {
		b := ip.As16()
		if nat64Prefix.Contains(ip) {
			return isDisallowedAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		}
		if nat64Local.Contains(ip) {
			return true
		}
		if sixToFour.Contains(ip) {
			return isDisallowedAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		}
	}
	return false
}

var errDisallowedTarget = errors.New("refusing to relay to disallowed address")

// ssrfControl runs after DNS resolution, immediately before connect(2), on
// the exact socket address the kernel is about to connect to. Checking here
// (rather than resolving, checking, then dialing the name again) closes the
// DNS-rebinding TOCTOU completely, and lets the stdlib dialer keep its
// Happy-Eyeballs behaviour: it can fall back from a broken IPv6 path to IPv4
// instead of the previous "pin to the first resolved IP" which failed outright
// on IPv4-only hosts whenever the name had an AAAA record listed first.
func ssrfControl(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparsable %q", errDisallowedTarget, address)
	}
	if isDisallowedAddr(ap.Addr()) {
		return fmt.Errorf("%w %s", errDisallowedTarget, ap.Addr())
	}
	return nil
}

func targetDialer(allowPrivate bool, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{
		Timeout: timeout,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     30 * time.Second,
			Interval: 15 * time.Second,
			Count:    4,
		},
	}
	if !allowPrivate {
		d.Control = ssrfControl
	}
	return d
}

// targetResolver resolves relay targets. Set at startup (system resolver or
// DNS-over-TLS); tests may replace it.
var targetResolver resolver.Resolver = resolver.System{}

// happyEyeballsDelay is how long the preferred address family gets before the
// other family is tried in parallel (RFC 8305 recommends 250 ms; Go uses 300).
const happyEyeballsDelay = 300 * time.Millisecond

// safeDialTCP dials target under the SSRF guard. Literal disallowed IPs are
// rejected before any syscall; for host names the resolved addresses are
// filtered, and every connect is re-checked on the exact socket address by
// ssrfControl, so DNS rebinding cannot slip through.
func safeDialTCP(target string, allowPrivate bool, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port in %q", target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := targetDialer(allowPrivate, timeout)

	if ip, err := netip.ParseAddr(host); err == nil {
		if !allowPrivate && isDisallowedAddr(ip) {
			return nil, fmt.Errorf("%w %s", errDisallowedTarget, ip)
		}
		return d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip.Unmap(), uint16(port)).String())
	}

	addrs, err := targetResolver.LookupNetIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if !allowPrivate {
		allowed := addrs[:0:0]
		for _, a := range addrs {
			if !isDisallowedAddr(a) {
				allowed = append(allowed, a)
			}
		}
		if len(allowed) == 0 {
			return nil, fmt.Errorf("%w: %q resolves only to disallowed addresses", errDisallowedTarget, host)
		}
		addrs = allowed
	}
	return dialHappyEyeballs(ctx, d, addrs, uint16(port))
}

// dialHappyEyeballs races IPv6 and IPv4 (RFC 8305, simplified): IPv6 starts
// first; IPv4 starts after happyEyeballsDelay or as soon as IPv6 fails. The
// first successful connection wins and any late one is closed.
func dialHappyEyeballs(ctx context.Context, d *net.Dialer, addrs []netip.Addr, port uint16) (net.Conn, error) {
	var v6, v4 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	primary, fallback := v6, v4
	if len(primary) == 0 {
		primary, fallback = v4, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, 2)
	dialSerial := func(list []netip.Addr) {
		var lastErr error
		for _, a := range list {
			c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, port).String())
			if err == nil {
				results <- result{c: c}
				return
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		results <- result{err: lastErr}
	}

	go dialSerial(primary)
	pending, fallbackStarted := 1, false
	startFallback := func() {
		if !fallbackStarted && len(fallback) > 0 {
			fallbackStarted = true
			pending++
			go dialSerial(fallback)
		}
	}
	timer := time.NewTimer(happyEyeballsDelay)
	defer timer.Stop()

	var firstErr error
	for {
		select {
		case <-timer.C:
			startFallback()
		case r := <-results:
			pending--
			if r.err == nil {
				if pending > 0 {
					go func(n int) { // close the loser(s)
						for i := 0; i < n; i++ {
							if lr := <-results; lr.c != nil {
								lr.c.Close()
							}
						}
					}(pending)
				}
				return r.c, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			startFallback()
			if pending == 0 {
				return nil, firstErr
			}
		}
	}
}

// resolveAllowedIP resolves target once and returns "ip:port" for the first
// allowed address. It is used for UDP, where there is no connect-time hook
// on the per-packet path, so the verified IP is pinned instead. A name that
// resolves to ANY disallowed address is rejected outright.
func resolveAllowedIP(ctx context.Context, target string, allowPrivate bool) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: %w", target, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !allowPrivate && isDisallowedAddr(ip) {
			return "", fmt.Errorf("%w %s", errDisallowedTarget, ip)
		}
		return net.JoinHostPort(ip.Unmap().String(), port), nil
	}
	ips, err := targetResolver.LookupNetIP(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve target %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve target %q: no addresses", host)
	}
	pick := netip.Addr{}
	for _, ip := range ips {
		if !allowPrivate && isDisallowedAddr(ip) {
			return "", fmt.Errorf("refusing to relay to %q (resolves to disallowed address %s)", host, ip)
		}
		// Prefer IPv4 for UDP: far more servers have working v4 egress.
		if !pick.IsValid() || (ip.Unmap().Is4() && !pick.Is4()) {
			pick = ip.Unmap()
		}
	}
	return net.JoinHostPort(pick.String(), port), nil
}

// safeResolveUDP resolves+verifies target under the SSRF guard and returns the
// pinned address to send to.
func safeResolveUDP(target string, allowPrivate bool) (netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ipPort, err := resolveAllowedIP(ctx, target, allowPrivate)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.ParseAddrPort(ipPort)
}
