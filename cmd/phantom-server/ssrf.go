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
	"syscall"
	"time"
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

// isDisallowedTargetIP is the net.IP form of isDisallowedAddr.
func isDisallowedTargetIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return isDisallowedAddr(a)
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

// safeDialTCP dials target under the SSRF guard. Literal disallowed IPs are
// rejected before any syscall; for hostnames every candidate address is
// checked at connect time by ssrfControl.
func safeDialTCP(target string, allowPrivate bool, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if !allowPrivate {
		if ip, err := netip.ParseAddr(host); err == nil && isDisallowedAddr(ip) {
			return nil, fmt.Errorf("%w %s", errDisallowedTarget, ip)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return targetDialer(allowPrivate, timeout).DialContext(ctx, "tcp", target)
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
	if allowPrivate {
		return target, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if isDisallowedAddr(ip) {
			return "", fmt.Errorf("%w %s", errDisallowedTarget, ip)
		}
		return net.JoinHostPort(ip.Unmap().String(), port), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("resolve target %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve target %q: no addresses", host)
	}
	pick := netip.Addr{}
	for _, ip := range ips {
		if isDisallowedAddr(ip) {
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
// pinned *net.UDPAddr to dial.
func safeResolveUDP(target string, allowPrivate bool) (*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ipPort, err := resolveAllowedIP(ctx, target, allowPrivate)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", ipPort)
}
