package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// MaxRewindBuffer caps the per-connection rewind buffer to prevent an
// attacker from holding the server in pre-Rewind state while streaming
// arbitrary data into memory. The Trojan handshake header (56-byte hash
// + CRLF + tiny request struct + CRLF) is well under 300 bytes, so
// 4096 leaves substantial headroom for protocol evolution while still
// being a cheap fixed cost.
//
// Reads beyond this threshold continue to succeed (silently dropping
// out of the buffer) — failing the Read instead would create an
// observable behavioural difference that an active prober could use
// to fingerprint phantom-server.
const MaxRewindBuffer = 4096

// RewindConn wraps a net.Conn and allows unreading or rewinding cached data
// back into the stream for subsequent protocol parsers.
type RewindConn struct {
	net.Conn
	buf      bytes.Buffer
	readLeft io.Reader
	rewinded bool
	bufFull  bool // true once we've stopped recording into buf
}

// NewRewindConn creates a new instance of RewindConn.
func NewRewindConn(c net.Conn) *RewindConn {
	return &RewindConn{
		Conn: c,
	}
}

// Read reads data from the connection or the rewind buffer if it has been rewound.
//
// While not rewound and the buffer is below MaxRewindBuffer, reads are
// mirrored into the buffer so a subsequent Rewind() can replay them.
// Once the buffer reaches MaxRewindBuffer, further reads continue
// transparently but are NOT recorded — a later Rewind() will only
// replay what was captured before the cap. In practice this is
// invisible because Rewind is only called after a handshake parse
// failure, which happens within the first few hundred bytes.
func (c *RewindConn) Read(b []byte) (int, error) {
	if !c.rewinded {
		n, err := c.Conn.Read(b)
		if n > 0 && !c.bufFull {
			remaining := MaxRewindBuffer - c.buf.Len()
			if remaining <= 0 {
				c.bufFull = true
			} else if n <= remaining {
				c.buf.Write(b[:n])
			} else {
				c.buf.Write(b[:remaining])
				c.bufFull = true
			}
		}
		return n, err
	}
	return c.readLeft.Read(b)
}

// Recorded returns the bytes captured so far (before Rewind). The slice
// aliases internal storage and is only valid until the next Read.
func (c *RewindConn) Recorded() []byte { return c.buf.Bytes() }

// Commit stops recording and releases the rewind buffer. Call it once the
// handshake has been accepted and the connection will never be rewound: it
// frees up to MaxRewindBuffer bytes per live connection and removes the
// extra memcpy that recording imposed on the first 4 KiB of relayed data.
func (c *RewindConn) Commit() {
	if c.rewinded {
		return
	}
	c.bufFull = true
	c.buf = bytes.Buffer{}
}

var errCloseWriteUnsupported = errors.New("rewind: underlying conn does not support CloseWrite")

// CloseWrite half-closes the underlying connection when it supports it
// (TCP, smux, QUIC streams). Without this passthrough the wrapper hid the
// method and the relay could never propagate a half-close.
func (c *RewindConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errCloseWriteUnsupported
}

// Rewind marks the connection as rewound and prefixes the read stream with cached data.
func (c *RewindConn) Rewind() {
	if c.rewinded {
		return
	}
	c.rewinded = true
	c.readLeft = io.MultiReader(&c.buf, c.Conn)
}
