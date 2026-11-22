package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/phantom-go/phantom/internal/auth"
	"github.com/phantom-go/phantom/internal/metrics"
	"github.com/phantom-go/phantom/internal/protocol"
	"github.com/phantom-go/phantom/internal/transport"
)

// v1.3.1 bug: streams opened and closed without a byte counted as failed
// logins; 20 of them banned the user.
func TestV2EmptyStreamsDoNotBan(t *testing.T) {
	h := startServer(t, 20)
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := transport.NewMuxSession(c)
	defer sess.Close()
	for i := 0; i < 40; i++ {
		st, err := sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		st.Close()
	}
	time.Sleep(300 * time.Millisecond)
	if h.lim.IsBanned(c.RemoteAddr()) {
		t.Fatal("empty streams got the user banned")
	}
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	st.SetDeadline(time.Now().Add(3 * time.Second))
	st.Write(append(header(testPassword, "127.0.0.1", h.echoPort), "ok"...))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("legitimate request failed after empty streams: %q %v", buf, err)
	}
}

// Wrong passwords inside a tunnel still count.
func TestV2WrongPasswordStreamsStillBan(t *testing.T) {
	h := startServer(t, 20)
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := transport.NewMuxSession(c)
	defer sess.Close()
	for i := 0; i < 20; i++ {
		st, err := sess.OpenStream()
		if err != nil {
			break
		}
		st.Write(header("wrong", "127.0.0.1", h.echoPort))
		st.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		st.Read(make([]byte, 1))
		st.Close()
	}
	time.Sleep(200 * time.Millisecond)
	if !h.lim.IsBanned(c.RemoteAddr()) {
		t.Fatal("password guessing inside a tunnel was not banned")
	}
}

// v1.3.1 bug: idle connections from ONE source filled every global slot.
func TestV2PerSourceHandshakeLimit(t *testing.T) {
	h := startServer(t, 1000)
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < maxPendingPerSource; i++ {
		c, err := tls.Dial("tcp", h.addr, h.tlsCli)
		if err != nil {
			t.Fatalf("attacker conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)

	// The same source is now at its limit...
	if c, err := tls.Dial("tcp", h.addr, h.tlsCli); err == nil {
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, rerr := c.Read(make([]byte, 1))
		c.Close()
		if rerr == nil || isTimeout(rerr) {
			t.Fatal("source above its limit was still served")
		}
	}
	// ...but another source is unaffected.
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	c, err := tls.DialWithDialer(d, "tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatalf("other source refused: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(append(header(testPassword, "127.0.0.1", h.echoPort), "ok"...))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("other source could not use the server: %v", err)
	}
}

// Active probing: no Phantom-specific ALPN; h2 probers reach an h2 backend.
func TestV2ALPNProbes(t *testing.T) {
	h := startServer(t, 1000)
	if c, err := tls.Dial("tcp", h.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"phantom"}}); err == nil {
		c.Close()
		t.Fatal(`server accepted ALPN "phantom"`)
	}
	for _, tc := range []struct {
		protos []string
		want   string
	}{
		{[]string{"h2"}, "FALLBACK-H2"},
		{[]string{"h2", "http/1.1"}, "FALLBACK-H2"},
		{[]string{"http/1.1"}, "FALLBACK"},
		{nil, "FALLBACK"},
	} {
		c, err := tls.Dial("tcp", h.addr, &tls.Config{InsecureSkipVerify: true, NextProtos: tc.protos})
		if err != nil {
			t.Fatalf("%v: handshake failed: %v", tc.protos, err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + strings.Repeat("x", 64)))
		buf := make([]byte, len(tc.want))
		_, err = io.ReadFull(c, buf)
		c.Close()
		if err != nil || string(buf) != tc.want {
			t.Fatalf("%v: got %q (%v), want %q", tc.protos, buf, err, tc.want)
		}
	}
}

// UDP: one socket per association (same source port for every destination)
// and unsolicited inbound datagrams are dropped.
func TestV2UDPEndpointIndependentMappingAndFiltering(t *testing.T) {
	h := startServer(t, 1000)
	echo := func() (*net.UDPConn, uint16) {
		pc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				_, from, err := pc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				pc.WriteToUDP([]byte(fmt.Sprintf("port:%d", from.Port)), from)
			}
		}()
		return pc, uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	}
	_, p1 := echo()
	_, p2 := echo()

	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	hdr := []byte(protocol.HashPassword(testPassword) + "\r\n")
	hdr = append(hdr, protocol.CmdUDP, protocol.AtypIPv4, 0, 0, 0, 0, 0, 0, '\r', '\n')
	c.Write(hdr)

	seen := map[uint16]string{}
	for _, p := range []uint16{p1, p2} {
		protocol.WriteUDPPacket(c, "127.0.0.1", p, []byte("q"))
		pkt, err := protocol.ReadUDPPacket(c)
		if err != nil {
			t.Fatal(err)
		}
		seen[pkt.Address.Port] = string(pkt.Payload)
	}
	if seen[p1] == "" || seen[p1] != seen[p2] {
		t.Fatalf("destinations saw different source ports (symmetric NAT): %v", seen)
	}

	// An unrelated host sends to the relay's port: must not reach the client.
	var relayPort int
	fmt.Sscanf(seen[p1], "port:%d", &relayPort)
	stranger, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relayPort})
	stranger.Write([]byte("unsolicited"))
	stranger.Close()
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if pkt, err := protocol.ReadUDPPacket(c); err == nil {
		t.Fatalf("unsolicited datagram delivered: %q", pkt.Payload)
	}
}

type fakeResolver struct{ m map[string]netip.Addr }

func (f fakeResolver) LookupNetIP(_ context.Context, host string) ([]netip.Addr, error) {
	if a, ok := f.m[host]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, fmt.Errorf("nx")
}

func TestV2TargetsUseConfiguredResolver(t *testing.T) {
	h := startServer(t, 1000)
	old := targetResolver
	targetResolver = fakeResolver{m: map[string]netip.Addr{"only-in-fake.test": netip.MustParseAddr("127.0.0.1")}}
	defer func() { targetResolver = old }()
	c, err := tls.Dial("tcp", h.addr, h.tlsCli)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(append(header(testPassword, "only-in-fake.test", h.echoPort), "ok"...))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("target not resolved via configured resolver: %v", err)
	}
}

func TestV2HappyEyeballsFallsBackToIPv4(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	// ::1 has nothing listening on that port -> v6 fails fast -> v4 wins.
	addrs := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	start := time.Now()
	c, err := dialHappyEyeballs(context.Background(), &net.Dialer{}, addrs, port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if time.Since(start) > 2*time.Second {
		t.Fatal("fallback was not prompt")
	}
}

// ---------------------------------------------------------------- HTTP/3 --

type h3Harness struct {
	addr     string
	echoPort uint16
	lim      *auth.RateLimiter
}

func startH3(t *testing.T) *h3Harness {
	h := startServer(t, 20) // reuses TCP echo + timeouts
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		io.WriteString(w, "real website")
	}))
	t.Cleanup(web.Close)
	setFallbacks(strings.TrimPrefix(web.URL, "http://"), "")

	cert, _ := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	ql, err := transport.ListenQUIC("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ql.Close() })
	lim := auth.NewRateLimiter(20, time.Minute, time.Minute)
	t.Cleanup(lim.Close)
	hh := &h3Handler{auth: auth.NewStaticAuth([]string{testPassword}), limiter: lim, metrics: metrics.New(), fallback: &httpFallback{}, local: ql.Addr()}
	var wg sync.WaitGroup
	go serveQUIC(ql, &wg, hh)
	return &h3Harness{addr: ql.Addr().String(), echoPort: h.echoPort, lim: lim}
}

func h3Dial(t *testing.T, addr string) *quic.Conn {
	qc, err := transport.DialQUIC(addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { qc.CloseWithError(0, "") })
	return qc
}

func TestV2HTTP3PhantomStreams(t *testing.T) {
	h := startH3(t)
	qc := h3Dial(t, h.addr)
	if got := qc.ConnectionState().TLS.NegotiatedProtocol; got != "h3" {
		t.Fatalf("ALPN %q, want h3", got)
	}
	cc := transport.NewH3ClientConn(qc, h.addr, protocol.HashPassword(testPassword))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := cc.OpenStream(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			defer st.Close()
			st.SetDeadline(time.Now().Add(5 * time.Second))
			msg := fmt.Sprintf("h3-stream-%d-%s", i, strings.Repeat("z", 40000))
			st.Write(append(header(testPassword, "127.0.0.1", h.echoPort), msg...))
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, []byte(msg)) {
				t.Errorf("stream %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}

func TestV2HTTP3ProbersSeeAWebsite(t *testing.T) {
	h := startH3(t)
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.Close()
	resp, err := (&http.Client{Transport: tr}).Get("https://" + h.addr + "/")
	if err != nil {
		t.Fatalf("plain HTTP/3 GET failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "real website" || resp.Header.Get("Server") != "nginx" {
		t.Fatalf("prober got %d %q %v", resp.StatusCode, body, resp.Header)
	}

	// CONNECT with a wrong password: rejected like any website would, and
	// counted towards the ban.
	qc := h3Dial(t, h.addr)
	cc := transport.NewH3ClientConn(qc, h.addr, protocol.HashPassword("wrong"))
	st, err := cc.OpenStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := st.Read(make([]byte, 1)); err != transport.ErrStreamRejected {
		t.Fatalf("wrong password: got %v, want ErrStreamRejected", err)
	}
	st.Close()
}

// The fallback must never leak Phantom credentials or client addresses.
func TestV2FallbackStripsCredentialsAndXFF(t *testing.T) {
	startServer(t, 1000) // initialises shared test globals (logger)
	got := make(chan http.Header, 2)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		got <- http.Header{"Host": {r.Host}}
	}))
	defer web.Close()
	setFallbacks(strings.TrimPrefix(web.URL, "http://"), "")
	req := httptest.NewRequest(http.MethodGet, "https://site.example/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer secret-hash")
	req.Header.Set("Connection", "Proxy-Authorization")
	(&httpFallback{}).ServeHTTP(httptest.NewRecorder(), req)
	h := <-got
	host := (<-got).Get("Host")
	if h.Get("Proxy-Authorization") != "" || h.Get("X-Forwarded-For") != "" || h.Get("X-Forwarded-Host") != "" {
		t.Fatalf("fallback leaked headers: %v", h)
	}
	if host != "site.example" {
		t.Fatalf("Host not preserved: %q", host)
	}
}
