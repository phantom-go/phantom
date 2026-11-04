# Phantom Protocol Specification

**Version**: 0.2
**Status**: Draft
**Last Updated**: 2026-11-04

---

## URI Format

```
phantom://password@host:port?params
```

### Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `type` | `tcp`, `ws`, `quic` | Transport layer mode (see [Transport Layers](#transport-layers)) |
| `path` | string | WebSocket path for `type=ws` (default `/api/v1/stream`) |
| `security` | `tls` | Transport security (always enabled) |
| `sni` | string | TLS SNI (Server Name Indication) hostname |
| `allowInsecure` | `0`, `1` | Skip TLS certificate verification (`1` = skip) |
| `fp` | `chrome`, `firefox`, `random` | TLS Client Hello fingerprint mimicking |

### Examples

**TCP mode with domain name:**
```
phantom://mypassword@example.com:443?type=tcp&security=tls&sni=example.com
```

**QUIC mode with domain name:**
```
phantom://mypassword@example.com:443?type=quic&security=tls&sni=example.com
```

**TCP mode with direct IP (self-signed certificate):**
```
phantom://mypassword@1.2.3.4:443?type=tcp&security=tls&allowInsecure=1
```

---

## Transport Layers

A native Phantom client carries every proxied connection as a **stream** inside
one long-lived session. This is what distinguishes `phantom://` from the
`trojan://` compatibility mode (one TLS connection per proxied connection).

| `type` | Session | One proxied connection = |
|:---|:---|:---|
| `tcp` | TLS over TCP, carrying an smux session | one smux stream |
| `ws` | TLS → HTTP/1.1 WebSocket upgrade on `path`; binary messages carry the smux byte stream | one smux stream |
| `quic` | QUIC v1 (TLS 1.3) | one bidirectional QUIC stream |

**TLS.** TLS 1.2+ (QUIC: 1.3). Clients offer ALPN `phantom`. Clients should
send a mainstream browser ClientHello (uTLS) for `tcp` / `ws`.

**smux (`tcp`, `ws`).** The session uses the
[smux](https://github.com/xtaci/smux) framing, **protocol version 2**
(per-stream flow control). Recommended settings: 1 MiB per-stream window,
4 MiB session buffer, keep-alive every 10 s with a 30 s timeout. The server
identifies a session by the first byte of the TLS stream: `0x02` (smux v2) or
`0x01` (smux v1, accepted for robustness). Anything else is parsed as a bare
Request Header (Trojan compatibility).

**QUIC (`quic`).** No smux layer: QUIC already multiplexes. Each
bidirectional stream carries exactly one proxied connection; unidirectional
streams are not used and are refused by the server.

**Per stream**, the client first writes the [Request Header](#tcp-request-header),
then relays payload in both directions. A client may send the header and the
first payload bytes in one write. Closing the write side (smux FIN / QUIC
stream FIN) signals end of data in that direction.

---

## Wire Format

### TCP Request Header

The first bytes of every stream (or, in Trojan compatibility mode, of the TLS
connection). The hash is the lowercase hex encoding of SHA-224(password).

```
[56 bytes SHA224(password) hex] CRLF
[CMD 1 byte] [ATYP 1 byte] [DST.ADDR] [DST.PORT 2 bytes] CRLF
[Payload...]
```

### CMD Values

| Value | Description |
|-------|-------------|
| `0x01` | `CONNECT` — TCP tunnel relay |
| `0x03` | `UDP ASSOCIATE` — UDP packet tunneling |

### ATYP Values

| Value | Description |
|-------|-------------|
| `0x01` | IPv4 address (4 bytes raw) |
| `0x03` | Domain name (1 byte length prefix + N bytes string) |
| `0x04` | IPv6 address (16 bytes raw) |

### UDP Packet Format

For `UDP ASSOCIATE` the header's address is ignored (clients send
`0.0.0.0:0`); every datagram that follows on the same stream, in either
direction, is framed as:

```
[ATYP 1 byte] [DST.ADDR] [DST.PORT 2 bytes]
[Length 2 bytes, big-endian] CRLF [Payload: Length bytes]
```

Each frame should be written in a single write. In server → client frames
the address is the datagram's source.

> **Security Note**: The `Length` field is a 16-bit unsigned integer (Big-Endian).
> The protocol's hard upper bound is therefore 65535, but a reference
> implementation should reject packets above a conservative limit
> (Phantom uses 9000 bytes, slightly above standard jumbo frame size)
> to prevent per-packet memory amplification.

---

## Anti-Probe Behavior

An invalid password hash or malformed handshake header triggers an immediate backend
redirection. The incoming connection **MUST NOT** be abruptly reset. Instead, all
subsequent raw bytes are replayed transparently to a preconfigured fallback backend
(e.g., a legitimate web server) to mitigate active-probing detection.

A connection that completes TLS but sends nothing is closed after 60 seconds,
the same as nginx's default `client_header_timeout`. Inside an established
session, malformed or unauthenticated streams count towards the source IP's
ban.

---

## Ecosystem Integration Drafts

> These are draft configuration examples intended to assist third-party tool maintainers
> in implementing Phantom protocol support. They are not yet officially supported.

### sing-box

```json
{
 "type": "phantom",
 "server": "example.com",
 "server_port": 443,
 "password": "yourpassword",
 "tls": {
   "enabled": true,
   "server_name": "example.com"
 },
 "transport": {
   "type": "tcp"
 }
}
```

### Xray

```json
{
 "protocol": "phantom",
 "settings": {
   "servers": [
     {
       "address": "example.com",
       "port": 443,
       "password": "yourpassword"
     }
   ]
 },
 "streamSettings": {
   "network": "tcp",
   "security": "tls"
 }
}
```
