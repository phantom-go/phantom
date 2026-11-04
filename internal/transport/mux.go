package transport

import (
	"errors"
	"net"
	"time"

	"github.com/xtaci/smux"
)

// ClientMuxVersion is the smux protocol version phantom-client speaks.
const ClientMuxVersion = 2

// MuxConfig returns the smux configuration shared by client and server.
//
// version 1 is the original protocol (session-wide flow control only): a
// single slow consumer can fill the 4 MiB session buffer and stall every
// other stream on the connection (head-of-line blocking). version 2 adds
// per-stream flow control. The per-stream window is raised from smux's
// 64 KiB default to 1 MiB: with v2 a 64 KiB window caps one stream at
// 64 KiB per RTT (~320 KiB/s at 200 ms), which is far below what a
// typical long-haul link can carry.
func MuxConfig(version int) *smux.Config {
	cfg := smux.DefaultConfig()
	if version == 2 {
		cfg.Version = 2
	}
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	cfg.MaxReceiveBuffer = 4 * 1024 * 1024
	cfg.MaxStreamBuffer = 1024 * 1024
	return cfg
}

// NewMuxSession initializes a client-side smux multiplexing session over a connection.
func NewMuxSession(conn net.Conn) (*smux.Session, error) {
	return smux.Client(conn, MuxConfig(ClientMuxVersion))
}

// NewMuxSessionVersion is NewMuxSession with an explicit smux protocol version.
func NewMuxSessionVersion(conn net.Conn, version int) (*smux.Session, error) {
	return smux.Client(conn, MuxConfig(version))
}

// ErrUnknownMuxVersion is returned when the first byte is not a smux version.
var ErrUnknownMuxVersion = errors.New("transport: not a supported smux version")

// AcceptMuxSession initializes a server-side smux multiplexing session over a connection.
// It speaks the same version as NewMuxSession so the pair always matches.
func AcceptMuxSession(conn net.Conn) (*smux.Session, error) {
	return smux.Server(conn, MuxConfig(ClientMuxVersion))
}

// AcceptMuxSessionVersion starts a server-side session for the smux protocol
// version announced by the peer's first frame byte (1 or 2). Detecting it
// per connection keeps the server tolerant of v1 peers at no cost.
func AcceptMuxSessionVersion(conn net.Conn, firstByte byte) (*smux.Session, error) {
	switch firstByte {
	case 1, 2:
		return smux.Server(conn, MuxConfig(int(firstByte)))
	default:
		return nil, ErrUnknownMuxVersion
	}
}
