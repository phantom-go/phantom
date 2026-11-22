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
	"bufio"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/protocol"
	"github.com/phantom-go/phantom/internal/relay"
)

// handleUDPRelay serves one UDP association (CMD 0x03).
//
// Since 2.0 an association uses ONE unconnected UDP socket for all its
// destinations (previously one connected socket + goroutine per destination,
// up to 256). This gives:
//
//   - endpoint-independent mapping: every destination sees the same source
//     port, the NAT behaviour games, WebRTC and other P2P traffic need;
//   - address-and-port-dependent filtering: inbound datagrams are accepted
//     only from address:port pairs the client has sent to, so the socket is
//     never an open inbound port;
//   - one fd and one reader goroutine per association instead of up to 256.
func handleUDPRelay(stream net.Conn, stats *metrics.UserStats) {
	sock, err := net.ListenUDP("udp", nil) // dual-stack, ephemeral port
	if err != nil {
		log.Debug("udp listen", "err", err)
		return
	}
	defer sock.Close()

	var (
		mu sync.Mutex
		// destination as the client named it -> resolved, SSRF-checked address
		resolved = make(map[string]netip.AddrPort)
		// addresses we have sent to (inbound filter) -> name to report back
		// (the domain the client used, so replies match what it expects)
		peers   = make(map[netip.AddrPort]protocol.Address)
		writeMu sync.Mutex
	)

	// Inbound: target -> client.
	go func() {
		bp := relay.GetBuffer()
		defer relay.PutBuffer(bp)
		buf := *bp
		for {
			n, from, err := sock.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			mu.Lock()
			name, ok := peers[from]
			mu.Unlock()
			if !ok || n > protocol.MaxUDPPayloadLength {
				continue // unsolicited or oversized: drop
			}
			writeMu.Lock()
			err = protocol.WriteUDPPacket(stream, name.Host, name.Port, buf[:n])
			writeMu.Unlock()
			if err != nil {
				stream.Close()
				return
			}
			stats.Received.Add(uint64(n))
		}
	}()

	// Outbound: client -> targets.
	br := bufio.NewReaderSize(stream, 16<<10)
	for {
		stream.SetReadDeadline(time.Now().Add(relay.DefaultIdleTimeout))
		pkt, err := protocol.ReadUDPPacket(br)
		if err != nil {
			return
		}
		key := pkt.Address.String()

		mu.Lock()
		dst, ok := resolved[key]
		n := len(resolved)
		mu.Unlock()
		if !ok {
			if n >= maxUDPTargetsPerStream {
				log.Debug("udp destination limit reached; dropping datagram", "limit", maxUDPTargetsPerStream)
				continue
			}
			dst, err = safeResolveUDP(key, allowPrivateTargets)
			if err != nil {
				log.Debug("blocked or unresolvable udp target", "err", err)
				continue
			}
			mu.Lock()
			resolved[key] = dst
			peers[dst] = pkt.Address
			mu.Unlock()
		}

		if _, err := sock.WriteToUDPAddrPort(pkt.Payload, dst); err != nil {
			log.Debug("udp send", "err", err)
			continue
		}
		stats.Sent.Add(uint64(len(pkt.Payload)))
	}
}
