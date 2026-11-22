# Phantom Protocol Specification

**Version**: 0.3 (Phantom 2.0)
**Status**: Draft
**Last Updated**: 2026-11-22

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
| `quic` | QUIC v1 (TLS 1.3) carrying HTTP/3 | one HTTP/3 `CONNECT` request stream |

**TLS.** TLS 1.2+ (QUIC: 1.3). No Phantom-specific value may appear in the
handshake. For `tcp`, clients send a mainstream browser ClientHello (uTLS)
with that browser's own ALPN list (`h2`, `http/1.1`); for `ws`, the same
ClientHello with ALPN `http/1.1` only (what browsers offer for WebSockets);
for `quic`, ALPN `h3`. Servers advertise `h2`, `http/1.1` on TCP and `h3`
on QUIC. The negotiated ALPN carries no meaning for the Phantom protocol.

**smux (`tcp`, `ws`).** The session uses the
[smux](https://github.com/xtaci/smux) framing, **protocol version 2**
(per-stream flow control). Recommended settings: 1 MiB per-stream window,
4 MiB session buffer, keep-alive every 10 s with a 30 s timeout. The server
identifies a session by the first byte of the TLS stream: `0x02` (smux v2) or
`0x01` (smux v1, accepted for robustness). Anything else is parsed as a bare
Request Header (Trojan compatibility).

**QUIC (`quic`).** No smux layer: QUIC already multiplexes, and the
connection is a regular HTTP/3 connection (RFC 9114) — both sides open their
control streams as usual. Each proxied connection is one HTTP/3 request:

```
:method               = CONNECT
:authority            = <server host:port>
proxy-authorization   = Bearer <56-char lowercase hex SHA-224(password)>
```

The server answers `200` and the request stream then carries the Phantom
request header and payload inside HTTP/3 DATA frames, exactly as on an smux
stream. Clients may send DATA immediately after the request headers, without
waiting for the response. Any other request — including a `CONNECT` with a
missing or wrong `proxy-authorization` — is served by the fallback website
(and a wrong password counts towards the source's ban). `proxy-authorization`
is a hop-by-hop field and must never be forwarded to the fallback.

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
session, streams carrying malformed data or a wrong password count towards the
source's ban; a stream closed without sending any data does not (clients
should open a stream only once they have a request to send).

The fallback is chosen by the negotiated ALPN: `h2` connections go to an
HTTP/2 backend, others to HTTP/1.1, and HTTP/3 requests are reverse-proxied —
so a prober receives a genuine response in whatever protocol it chose.

Servers limit unauthenticated connections per source (IPv4 address or IPv6
/64) as well as globally, so one source cannot exhaust the server.

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
