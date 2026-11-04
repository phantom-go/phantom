package transport

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/coder/websocket"
)

// wsConnWrapper overwrites the RemoteAddr method to preserve the original client's IP address.
type wsConnWrapper struct {
	net.Conn
	remoteAddr net.Addr
}

func (w *wsConnWrapper) RemoteAddr() net.Addr {
	return w.remoteAddr
}

// DialWS establishes a WebSocket connection over a pre-established net.Conn (e.g., uTLS connection)
// and wraps it into a net.Conn compatible object.
func DialWS(ctx context.Context, rawConn net.Conn, serverAddr, wsPath string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	// Crucial Fix: Use "ws" instead of "wss" because the underlying rawConn
	// is already an established uTLS encrypted channel. Setting it to "wss"
	// would trigger an erroneous double-TLS handshake.
	u := url.URL{
		Scheme: "ws",
		Host:   host,
		Path:   wsPath,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return rawConn, nil
			},
		},
		// Do not follow redirects off the authenticated tunnel.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	options := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, u.String(), options)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
}

// AcceptWS upgrades an incoming HTTP request into a WebSocket session and
// wraps it as a net.Conn.
//
// When trustProxyHeaders is true, X-Forwarded-For / X-Real-IP from the
// request are honoured to determine the real client address (use this
// only behind a trusted reverse proxy that overwrites/strips client-set
// XFF — Nginx, Caddy, Cloudflare). When false (default), the proxy
// headers are ignored entirely and r.RemoteAddr is used: this prevents
// an attacker reaching phantom-server directly from spoofing a source
// IP to evade rate limiting or get innocent IPs banned.
func AcceptWS(w http.ResponseWriter, r *http.Request, trustProxyHeaders bool) (net.Conn, error) {
	options := &websocket.AcceptOptions{
		// InsecureSkipVerify here disables the websocket Origin check,
		// NOT TLS verification. Phantom uses its own auth, so origin
		// filtering would only block legitimate clients.
		InsecureSkipVerify: true,
	}

	wsConn, err := websocket.Accept(w, r, options)
	if err != nil {
		return nil, err
	}

	nc := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)

	return &wsConnWrapper{Conn: nc, remoteAddr: ClientAddr(r, trustProxyHeaders)}, nil
}

// ClientAddr determines the address used for rate limiting.
//
// Security notes:
//   - Only when trustProxyHeaders is set are proxy headers consulted.
//   - X-Real-IP is preferred: Nginx/Caddy set it to the socket peer and it
//     cannot carry client-supplied history.
//   - For X-Forwarded-For the RIGHT-most entry is used. Proxies APPEND the
//     peer they saw (nginx $proxy_add_x_forwarded_for), so the left-most
//     entry is whatever the client sent — trusting it (as the previous code
//     did) let any client choose its own rate-limit identity and frame
//     innocent IPs for bans even behind a correctly configured proxy.
//   - Header values are parsed with netip (pure parsing). The old code used
//     net.ResolveTCPAddr, which performs a DNS lookup for a hostname — a
//     client-controlled header could make the server issue arbitrary DNS
//     queries and block the handler on resolution.
func ClientAddr(r *http.Request, trustProxyHeaders bool) net.Addr {
	if trustProxyHeaders {
		if ap, ok := parseHeaderIP(r.Header.Get("X-Real-IP")); ok {
			return net.TCPAddrFromAddrPort(ap)
		}
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			last := xff[len(xff)-1]
			if idx := strings.LastIndexByte(last, ','); idx != -1 {
				last = last[idx+1:]
			}
			if ap, ok := parseHeaderIP(last); ok {
				return net.TCPAddrFromAddrPort(ap)
			}
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return net.TCPAddrFromAddrPort(ap)
	}
	if ap, ok := parseHeaderIP(r.RemoteAddr); ok {
		return net.TCPAddrFromAddrPort(ap)
	}
	return &net.TCPAddr{}
}

func parseHeaderIP(v string) (netip.AddrPort, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.AddrPort{}, false
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
	v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	if a, err := netip.ParseAddr(v); err == nil {
		return netip.AddrPortFrom(a.Unmap(), 0), true
	}
	return netip.AddrPort{}, false
}
