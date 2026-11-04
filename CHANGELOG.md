# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.3.0] - 2026-11-03

Security and performance overhaul.

### Changed
- **phantom-client now always uses smux v2** (per-stream flow control), so
  it needs a v1.3.0+ server. The server still accepts v1 and v2.
- **Clearer guidance to use `phantom://`.** The README, installer output and
  server log now note that `trojan://` is a temporary compatibility option
  (basic proxying only, may be removed in a future release).
- README simplified.

### Security
- **Slowloris fix (server).** A client that completed TLS and then sent
  nothing was held open forever (the first-byte peek had no deadline).
  Silent connections are now closed after 60 s, matching nginx's default
  `client_header_timeout` so timing does not distinguish the server from
  the fallback.
- **Unauthenticated stream flood (server).** One unauthenticated smux/QUIC
  session could open thousands of streams, each costing a goroutine and a
  10 s parse window. Now at most 64 pending handshakes per session and 4096
  process-wide; malformed streams inside a tunnel count towards the IP ban,
  and a session is dropped once its peer is banned.
- **X-Forwarded-For spoofing behind a proxy.** With `trust_proxy_headers`
  the *left-most* XFF entry (client-controlled) was trusted, letting anyone
  pick their rate-limit identity or get innocent IPs banned. Now
  `X-Real-IP`, else the right-most XFF entry. Header values are parsed,
  never DNS-resolved (previously a hostname in the header triggered a
  server-side DNS lookup).
- **SSRF guard hardened.** The address check now runs at connect time on
  the exact socket address (closing DNS rebinding completely) and also
  blocks CGNAT `100.64/10` (incl. Alibaba Cloud metadata `100.100.100.200`),
  `0/8`, `198.18/15`, `240/4`, Teredo, and NAT64 / 6to4 addresses that embed
  a private IPv4 (e.g. `64:ff9b::7f00:1` → 127.0.0.1).
- **Rate limiter.** IPv6 is keyed by /64 (a single host could previously
  rotate through 2^64 addresses and never be banned). Eviction at the
  100 k-entry cap was an O(n) scan per failure under the global lock
  (≈ 8.5 ms each); now amortised (≈ 14 µs).
- **Certificate pinning (client).** New `pinned_cert_sha256` gives MITM
  protection to self-signed deployments, which previously had none.
- **TLS certificate hot reload** on SIGHUP, plus a certbot deploy hook in
  the installer. Previously a renewed Let's Encrypt cert was never loaded
  and clients broke when the old one expired.
- **SOCKS5 UDP hijack (client).** Any local process could inject into, or
  steal replies from, another user's UDP association. The relay socket now
  only accepts the control connection's IP and locks to the first port;
  fragmented datagrams are rejected.
- **Server exited on transient Accept errors** (e.g. EMFILE) with status 0,
  which `Restart=on-failure` does not restart. It now backs off and retries.
- **Data race** on `fallback_addr` during SIGHUP reload removed.
- **Privacy:** every relayed destination was logged at INFO (users'
  browsing history in journald by default). Now DEBUG only.
- **Deployment:** systemd units sandboxed (capabilities reduced to
  `CAP_NET_BIND_SERVICE`, read-only filesystem, syscall filter, …) with
  `ExecReload`; installer uses a private `mktemp` dir (was predictable
  `/tmp` paths run as root) and verifies the release `SHA256SUMS`; config and
  key are created mode 0600 with no world-readable window; self-signed certs
  are ECDSA P-256. CI now runs gofmt, vet, `go test -race` and govulncheck
  before any release, builds with `-trimpath CGO_ENABLED=0`, and publishes
  `SHA256SUMS`.
- Config validation: transport names, `ws_path`, empty/duplicate passwords,
  `server_addr`; warning when the config file is readable by other users.

### Fixed
- **IPv6 targets never worked**: `Address.String()` produced `::1:443`
  instead of `[::1]:443`, which every dial rejected.
- **Long connections cut at exactly 5 minutes**: the server set an absolute
  deadline. Replaced by a 5-minute *idle* timeout shared by both directions.
- **Client pool thundering herd**: N concurrent requests on an empty pool
  opened N TLS sessions at once (64 requests → 64 handshakes) and exceeded
  `session_pool_size`. Now exactly one dial; others wait for it.
- Client: dial/handshake timeouts (a black-holed server hung the pool
  forever), SOCKS handshake deadline, accept-error backoff instead of a
  100 %-CPU log loop, UDP works when the SOCKS listener is on a LAN address.
- Half-close propagated through the rewind wrapper and QUIC streams;
  QUIC stream Close now releases the receive side.

### Performance
- Trojan header and UDP frames written in **one** write instead of five
  (each was a separate smux frame / TLS record): header encode 188 → 41 ns,
  0 allocations; UDP frame encode 0 allocations.
- Header parse 490 → 320 ns, 12 → 4 allocations.
- Relay uses pooled 32 KiB buffers: per-connection garbage 68 KB → 4 KB,
  ~20 % higher pump throughput.
- Rewind buffer released after authentication (−4 KiB per live connection,
  no extra copy of the first 4 KiB).
- smux v2 with 1 MiB per-stream windows removes head-of-line blocking: one
  stalled download no longer freezes every other connection in the session.
  Trade-off: v2 sends one extra flow-control frame when a stream is first
  read, adding roughly 15 µs per new stream on loopback (not a network round
  trip). The smux micro-benchmarks are therefore ~8–20 % below v1.2, in
  exchange for no head-of-line blocking.
- QUIC: larger flow-control windows, idle/handshake timeouts, unidirectional
  streams disabled. Dialer TCP keep-alive tuned.

### Dependencies
- **Go toolchain 1.26.6 → 1.26.10 and golang.org/x/net 0.59.0 → 0.62.0**
  (x/crypto 0.58.0, x/sys 0.49.0). Clears 10 vulnerabilities govulncheck
  found reachable from this project, all in the Go standard library:
  GO-2026-6809 (crypto/x509: distrust compromised intermediates),
  GO-2026-6617, -6613, -6612, -6611, -6610, -6605, -6603 (net/http, HTTP/1
  and HTTP/2 server/transport flaws), GO-2026-6608 (MIME header memory limit
  bypass) and GO-2026-6607 (crypto/tls ECH). CI now tracks the latest 1.26.x
  patch release automatically.
- quic-go 0.59.1 → 0.65.0, smux 1.5.57 → 1.5.58, coder/websocket
  1.8.14 → 1.8.15, klauspost/compress 1.17.4 → 1.20.3, brotli 1.0.6 → 1.2.7.

## [1.2.1] - 2026-06-08

### Security
- **Upgraded the Go toolchain to 1.26.6+ to clear 8 standard-library
  vulnerabilities.** A `govulncheck` scan on the previous toolchain (go1.26.3)
  flagged 8 issues reachable from this project's call paths — all in the Go
  standard library, none in project code or third-party dependencies:
  GO-2026-6218 (`net/url` quadratic `resolvePath`), GO-2026-6090 (`crypto/tls`
  post-handshake message flood), GO-2026-6089 (`net/http` H2C
  `ReadHeaderTimeout`), GO-2026-5972 (`encoding/asn1` recursion depth),
  GO-2026-5856 (`crypto/tls` ECH privacy leak), GO-2026-5039 (`net/textproto`
  unescaped error input), GO-2026-5037 (`crypto/x509` hostname parsing), and
  GO-2026-5026 (`net/http` IDNA Punycode). Rebuilding on the current toolchain
  resolves all of them; `govulncheck ./...` now reports zero affecting the
  project. No code or dependency changes were required.

### Changed
- **CI Go version bumped `1.25` → `1.26`** (`check-latest: true` keeps it on the
  newest 1.26 patch) so release builds match the toolchain the module now
  requires.

## [1.2.0] - 2026-06-08

### Added
- **Configurable client session pool.** New `session_pool_size` (default `1`).
  At `1` the client keeps exactly one session, so the TLS fingerprint appears
  once and there is no multi-connection signature — identical to previous
  behaviour. At `N > 1` the client round-robins new streams across up to `N`
  sessions for higher aggregate throughput and resilience: a single session
  dropping no longer stalls everything.
- **On-demand pool growth.** Sessions are never pre-opened. The pool starts
  empty, opens its first session on the first request, and only opens further
  sessions (up to `session_pool_size`) once the busiest existing session is
  carrying at least `session_growth_threshold` concurrent streams — avoiding
  the signature of `N` simultaneous handshakes at startup.
- **`session_growth_threshold` (default `16`).** The stealth/throughput dial:
  larger packs more streams onto each connection (fewer connections, stealthier);
  smaller opens new sessions sooner (more parallelism). Ignored when
  `session_pool_size == 1`.
- **QUIC keep-alive.** The QUIC dialer and listener now set a keep-alive period
  so an idle tunnel is not silently dropped by NAT/firewall middleboxes between
  requests.

### Fixed
- **Client TLS handshake moved out of the pool lock.** The (possibly slow)
  uTLS/QUIC handshake now runs with the lock released, so re-dialling a dead
  session no longer freezes every other in-flight request behind it.
- **Automatic session recovery.** A background keep-alive loop prunes dead
  sessions and re-establishes one after an idle gap, so the first request after
  a drop does not pay the full reconnect penalty mid-request.
- **`QUICNetConn` now honours the `io.Reader` contract.** Its placeholder
  `Read`/`Write` returned `(0, nil)`, which makes `io.Copy`/`io.ReadFull` spin
  at 100% CPU. They now return an explicit error, turning any accidental
  stream-level misuse into a loud failure instead of a busy-loop.
- **Oversized UDP datagrams no longer tear down the relay.** A datagram whose
  payload exceeds `MaxUDPPayloadLength` is now dropped individually (with a
  warning) instead of returning a fatal error that killed the entire UDP
  session in that direction. Applied on both the client and server relay paths.

### Security
- **Root-caused the SSRF TOCTOU / DNS-rebinding bypass.** The relay previously
  resolved-and-checked the target, then dialled the hostname again, allowing a
  hostile resolver to return a public IP for the check and an internal IP
  (e.g. `169.254.169.254`) for the connection. The target is now resolved
  exactly once, every returned address is verified against the guard, and the
  dial is pinned to the verified IP — the name is never handed to `Dial` a
  second time. Applied to both the TCP and UDP relay paths.
- **Rate-limiter memory bound.** The per-IP failure table now has a hard cap
  (`DefaultMaxEntries`). When full, the least-recently-seen *non-banned* record
  is evicted to make room; active bans are never evicted, so an attacker cannot
  flush a legitimate ban by spraying fresh source IPs. This closes a
  memory-exhaustion vector under a high-cardinality failure flood.

## [1.1.0] - 2026-06-02

### Added
- **TCP + QUIC dual-stack deployment.** `install.sh` now installs two
  independent systemd units, `phantom-server-tcp` (TCP/TLS on 443) and
  `phantom-server-quic` (QUIC on UDP/443), sharing a single config. Previously
  only TCP was served despite QUIC being advertised.
- **QUIC selectable via config.** `transport: "quic"` now enables the QUIC
  transport on both client and server, equivalent to the `--quic` flag, so a
  `phantom://...?type=quic` URI maps onto config without the flag.
- **SSRF guard.** The server refuses by default to relay (TCP or UDP) to
  loopback, link-local, private (RFC 1918 / ULA) and cloud-metadata
  (169.254.169.254) addresses, resolving hostnames first so a domain pointing
  at an internal IP is also blocked. Opt out with `allow_private_targets: true`.
- `--version` flag on both `phantom-server` and `phantom-client`. The version
  string is injected at build time via `-ldflags "-X main.version=..."` and
  wired into the release workflow.
- QUIC client URI shown by the installer alongside the TCP URI.

### Fixed
- `protocol.writeAddress` now returns an error for unknown address types and
  rejects empty domain names, instead of silently emitting a malformed packet.
- SOCKS5 handshake now verifies the client actually offered the no-auth method
  (0x00) and replies with 0xFF ("no acceptable methods") otherwise, per RFC 1928.
- Client UDP relay (`handleUDP`) now closes the tunnel stream on exit so the
  inbound read goroutine cannot linger.
- `install.sh` download now uses `curl -fsSL` and validates the archive and the
  extracted binary, instead of silently saving an HTTP error page.
- The legacy single-mode `phantom-server.service` unit is removed on
  (re)install and uninstall so it cannot double-bind port 443.
- `auth.Verify` now compares the credential hash against every configured
  password hash in constant time (crypto/subtle, no short-circuit) instead of a
  timing-variable map lookup.
- Removed an unused `QUICConnToNet` helper and a no-op `http2 on;` directive
  from the Nginx fallback block.
- `go.mod` toolchain directive aligned to Go 1.25 (1.24 reached EOL), matching CI.

## [1.0.0]
- Initial release: Trojan-compatible encrypted proxy with TCP/TLS and QUIC
  transports, WebSocket option, SOCKS5 front end, UDP relay, multi-user auth,
  rate limiting, hot config reload, and metrics.
