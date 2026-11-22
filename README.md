# Phantom

![Version](https://img.shields.io/badge/version-v2.0.0-blue) ![License](https://img.shields.io/badge/license-AGPL--3.0-orange) ![Go](https://img.shields.io/badge/go-1.26.11%2B-00ADD8)

**A next-generation encrypted transport, built from the ground up for speed,
stealth and security — with its own native `phantom://` protocol.**

One connection carries every request. QUIC that is indistinguishable from
ordinary HTTP/3. A TLS handshake that looks like a real browser's, with
post-quantum key exchange. A server that looks like an ordinary website to
anyone who probes it — over HTTP/1.1, HTTP/2 or HTTP/3. And a codebase small
enough to audit in an afternoon.

> [!NOTE]
> Use **`phantom://`** links for the full feature set. `trojan://` links are a
> temporary compatibility option for apps that don't support Phantom yet —
> basic proxying only, and may be removed in a future release.

---

## Why Phantom

### ⚡ Built for speed
- **Native QUIC transport over real HTTP/3** — no TCP head-of-line blocking
  and faster loss recovery, ideal for mobile and long-distance links.
- **True stream multiplexing with per-stream flow control** — one TLS session
  carries every connection, so a new request costs no handshake; and a stalled
  download never freezes your other tabs.
- **Zero-waste hot path** — handshake and UDP frames go out in a single write
  with zero heap allocations; relay buffers are pooled and grow only for bulk
  transfers, so an idle connection costs the server 28 KiB.
- **Adaptive session pool** — opened on demand, grown only under load, and
  closed after 5 idle minutes: no around-the-clock heartbeat.
- **Full-cone-friendly UDP** — one socket per association with the same
  source port for every destination, so games, WebRTC and P2P work.

### 🛡 Built for stealth
- **Browser-grade TLS fingerprints** — current Chrome ClientHello via uTLS,
  including its post-quantum X25519MLKEM768 key share.
- **Nothing says "Phantom"** — standard ALPN (`h2`, `http/1.1`, `h3`), a
  neutral certificate, and QUIC streams that are ordinary HTTP/3 `CONNECT`
  requests.
- **Active-probe defense** — anything that is not a valid Phantom client is
  handed to a real web server over the protocol it asked for (HTTP/1.1,
  HTTP/2 or HTTP/3). Scanners see a normal website, with normal timing.
- **CDN-ready WebSocket mode** on an innocuous API path.

### 🔒 Built for security
- **Certificate pinning** — real man-in-the-middle protection even on
  IP-only, self-signed servers.
- **Private DNS** — the server resolves destinations over DNS-over-TLS with
  padded queries, so the hosting provider cannot log which sites users visit.
- **Brute-force protection** — automatic bans, IPv6-aware (per /64), with
  per-source limits so one attacker cannot lock other users out.
- **SSRF guard** — clients cannot reach the server's private network or cloud
  metadata, checked on the exact address at connect time.
- **Least privilege** — runs as an unprivileged user in a sandboxed systemd
  service; releases carry signed build provenance and are checksum-verified
  on install.

### 🧰 Built for operators
- **One-line install** with automatic TLS, firewall and QR codes.
- **Hot reload** of users *and* certificates — no dropped connections,
  automatic after Let's Encrypt renewal.
- **Per-user identities and traffic metrics** — revoke one stolen device
  without touching anyone else.

---

## Performance

| Benchmark | Result |
|:---|:---|
| Single-stream relay throughput | **257 MB/s** (≈ 2 Gbps on one stream) |
| Concurrent streams (open → 1 KB echo → close, in parallel) | **~24,000 streams/s** |
| Stream round-trip latency (open → 1 B echo → close) | **~83 µs** |

> AMD Ryzen 7 PRO 6850U, 4-vCPU KVM virtual machine (Proxmox), Go 1.26.6,
> TLS + smux over loopback (this path is unchanged in 2.0). Results vary with
> hardware.
> Reproduce with `go test -run xxx -bench . -benchmem ./internal/benchmark/`
> (needs `server.crt` / `server.key` in the repo root).

**Resource gains** (each pair measured on the same machine with the same
toolchain):

| Measure | Before | Now |
|:---|:---|:---|
| Server memory per idle proxied connection | 87.5 KiB (v1.3.1) | **27.9 KiB** (v2.0) |
| Server cost of an idle, connected client | forever (v1.3.1) | **released after 5 min** (v2.0) |
| UDP sockets per association | 1 per destination (v1.3.1) | **1** (v2.0) |
| Relay throughput | 3,438 MB/s (v1.3.1) | 3,410 MB/s (v2.0, within noise) |
| Handshake header encode | 188 ns · 8 allocs · 5 writes (v1.2) | **41 ns · 0 allocs · 1 write** |
| Handshake header parse | 490 ns · 12 allocs (v1.2) | **320 ns · 4 allocs** |
| Memory garbage per relayed connection | 68 KB (v1.2) | **4 KB** |
| Concurrent connects on a cold client | 64 TLS handshakes (v1.2) | **1 handshake** |
| One stalled stream blocks the session | yes (v1.2) | **no** |

---

## `phantom://` vs. `trojan://` compatibility mode

| | `phantom://` | `trojan://` (temporary) |
|:---|:---:|:---:|
| TCP & UDP proxying | ✅ | ✅ |
| Native QUIC transport (as standard HTTP/3) | ✅ | — |
| Multiplexed streams (no handshake per request) | ✅ | — |
| Per-stream flow control (no head-of-line blocking) | ✅ | — |
| Adaptive multi-session pool | ✅ | — |
| Future protocol features | ✅ | — |

---

## Install

```bash
bash <(curl -sL https://raw.githubusercontent.com/phantom-go/phantom/main/docs/install.sh)
```

Debian / Ubuntu / CentOS, as root. The installer sets up Nginx (fallback site),
a TLS certificate (Let's Encrypt with a domain, otherwise self-signed), a random
password, the firewall and systemd services, then prints your connection link
and QR code.

Run it again to manage the server:

```
[1] Install Phantom
[2] Upgrade Phantom (keeps users & certificates)
[3] Uninstall Phantom
[4] Show users (URI + QR code)
[5] Add user
[6] Remove user
[7] Exit
```

**Upgrading?** Choose `[2]`: it installs the latest release and keeps every
user, password and certificate, so existing links keep working. From 1.x it
also moves the service to the unprivileged `phantom` user and enables
DNS-over-TLS. QUIC users need phantom-client 2.0 (QUIC now runs over HTTP/3).

Each password is a separate user with its own traffic metrics. Adding or
removing one takes effect instantly, without disconnecting anyone else.

---

## Configuration

### Server

```json
{
  "server": {
    "listen": ":443",
    "passwords": ["your-password"],
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem",
    "fallback_addr": "127.0.0.1:8080",
    "fallback_h2_addr": "127.0.0.1:8081",
    "dns_over_tls": ["9.9.9.9", "149.112.112.112"],
    "dns_tls_name": "dns.quad9.net",
    "transport": "tcp"
  }
}
```

### Client

```json
{
  "client": {
    "server_addr": "your-server.com:443",
    "password": "your-password",
    "socks5_addr": "127.0.0.1:1080",
    "transport": "tcp"
  }
}
```

Using an **IP address with a self-signed certificate**? Add these two lines —
the installer prints the fingerprint:

```json
    "verify": false,
    "pinned_cert_sha256": "AB:CD:…:EF"
```

Without the pin, `verify: false` does not check who you are talking to.

<details>
<summary>All options</summary>

| Option | Side | Default | Meaning |
|:---|:---|:---|:---|
| `transport` | both | `tcp` | `tcp`, `ws` (WebSocket, for CDNs) or `quic` |
| `ws_path` | both | `/api/v1/stream` | WebSocket path |
| `tls_fingerprint` | client | `HelloChrome_Auto` | also `HelloRandomized`; `HelloFirefox_Auto` / `HelloEdge_Auto` imitate outdated browsers and are not recommended |
| `verify` | client | `true` | verify the server certificate against a CA |
| `pinned_cert_sha256` | client | — | accept only this exact certificate |
| `session_pool_size` | client | `1` | max connections to the server (more = faster, less stealthy) |
| `session_growth_threshold` | client | `16` | streams per connection before opening another |
| `session_idle_timeout` | client | `300` | seconds without traffic before the connection to the server is closed (`-1` = always on) |
| `allow_lan_socks5` | client | `false` | allow SOCKS5 on a non-loopback address (it has no password!) |
| `trust_proxy_headers` | server | `false` | trust `X-Real-IP` / `X-Forwarded-For` — only behind your own reverse proxy |
| `allow_private_targets` | server | `false` | let clients reach private / internal addresses |
| `fallback_h2_addr` | server | — | HTTP/2 (prior-knowledge) web server for probers that negotiate `h2`; empty = `fallback_addr` |
| `dns_over_tls` | server | — | DoT resolver IPs (port 853 default); empty = system resolver (plaintext) |
| `dns_tls_name` | server | — | certificate name of the DoT resolvers, e.g. `dns.quad9.net` |

Log level: `--log-level` or `PHANTOM_LOG_LEVEL` (`debug`, `info`, `warn`, `error`).

</details>

---

## Manual setup

```bash
tar -xzf phantom-<version>-linux-amd64.tar.gz

IP=203.0.113.10   # your server's public IP
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 3650 -nodes \
  -subj "/CN=$IP" -addext "subjectAltName=IP:$IP"

./phantom-server --config config.json          # add --quic for QUIC (HTTP/3)
./phantom-client --config config.json          # SOCKS5 on socks5_addr

kill -HUP $(pgrep phantom-server)              # reload users + certificate
```

---

## Clients

| Client | Platform | `phantom://` | `trojan://` (temporary) |
|:---|:---|:---|:---|
| phantom-client | All | ✅ | — |
| Shadowrocket | iOS | Pending | ✅ basic |
| NekoBox | Android | Pending | ✅ basic |
| v2rayN | Windows | Pending | ✅ basic |
| Clash Meta / Mihomo | All | Pending | ✅ basic |
| sing-box | All | Pending | ✅ basic |

### Bring `phantom://` to your client

Phantom's wire format is small, documented and stable, with a complete
reference implementation in Go (`internal/protocol`, `internal/transport`).
Adding native support gives your users QUIC (as standard HTTP/3), true
multiplexing and Phantom's full performance — far beyond what the
compatibility mode can offer.

Start with the [Protocol Specification](docs/protocol-spec.md); issues and
pull requests from client developers are very welcome.

---

## Docs

[Design](docs/design.md) · [Protocol](docs/protocol-spec.md) · [Philosophy](docs/philosophy.md) · [Changelog](CHANGELOG.md)

## License

[AGPL-3.0](LICENSE). If you run a modified version as a network service, you
must make its source available to its users.
