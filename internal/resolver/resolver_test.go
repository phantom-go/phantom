package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type testDoT struct {
	addr       string
	pool       *x509.CertPool
	handshakes atomic.Int32
	queries    atomic.Int32
	badLen     atomic.Int32
}

func startDoT(t *testing.T) *testDoT {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dns.test"},
		DNSNames: []string{"dns.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	ts := &testDoT{pool: pool}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ts.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			ts.handshakes.Add(1)
			go ts.serve(c)
		}
	}()
	return ts
}

func (ts *testDoT) serve(c net.Conn) {
	defer c.Close()
	for {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		ts.queries.Add(1)
		if len(q)%paddingBlock != 0 {
			ts.badLen.Add(1)
		}
		var p dnsmessage.Parser
		h, _ := p.Start(q)
		qq, _ := p.Question()
		b := dnsmessage.NewBuilder(make([]byte, 2, 512), dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeSuccess})
		b.StartQuestions()
		b.Question(qq)
		b.StartAnswers()
		switch {
		case qq.Name.String() == "missing.test.":
			// fallthrough to empty NXDOMAIN-like answer below
		case qq.Type == dnsmessage.TypeA:
			b.AResource(dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}})
		case qq.Type == dnsmessage.TypeAAAA:
			b.AAAAResource(dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}})
		}
		msg, _ := b.Finish()
		binary.BigEndian.PutUint16(msg[:2], uint16(len(msg)-2))
		c.Write(msg)
	}
}

func newTestResolver(t *testing.T, ts *testDoT, fallback Resolver) *DoT {
	d, err := NewDoT([]string{ts.addr}, "dns.test", fallback, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.tlsCfg.RootCAs = ts.pool
	t.Cleanup(d.Close)
	return d
}

func TestDoTResolveCacheReusePadding(t *testing.T) {
	ts := startDoT(t)
	d := newTestResolver(t, ts, nil)
	ctx := context.Background()

	addrs, err := d.LookupNetIP(ctx, "Example.TEST.")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("lookup: %v %v", addrs, err)
	}
	for i := 0; i < 50; i++ { // served from cache
		d.LookupNetIP(ctx, "example.test")
	}
	if q := ts.queries.Load(); q != 2 {
		t.Fatalf("expected 2 queries (A+AAAA) thanks to the cache, got %d", q)
	}
	d.cacheMu.Lock()
	d.cache = map[string]cacheEntry{}
	d.cacheMu.Unlock()
	d.LookupNetIP(ctx, "example.test")
	if h := ts.handshakes.Load(); h > 2 {
		t.Fatalf("connections not reused: %d TLS handshakes for 2 rounds", h)
	}
	if ts.badLen.Load() != 0 {
		t.Fatal("queries are not padded to the block size")
	}
	if _, err := d.LookupNetIP(ctx, "missing.test"); err != ErrNotFound {
		t.Fatalf("missing name: %v", err)
	}
}

func TestDoTCoalescesConcurrentLookups(t *testing.T) {
	ts := startDoT(t)
	d := newTestResolver(t, ts, nil)
	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func() { d.LookupNetIP(context.Background(), "burst.test"); done <- struct{}{} }()
	}
	for i := 0; i < 32; i++ {
		<-done
	}
	if q := ts.queries.Load(); q != 2 {
		t.Fatalf("32 concurrent lookups should cost 2 queries, got %d", q)
	}
}

type fakeSys struct{ called atomic.Int32 }

func (f *fakeSys) LookupNetIP(context.Context, string) ([]netip.Addr, error) {
	f.called.Add(1)
	return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
}

func TestDoTFallbackWhenUnreachable(t *testing.T) {
	ts := startDoT(t)
	fb := &fakeSys{}
	d := newTestResolver(t, ts, fb)
	d.servers = []string{"127.0.0.1:1"} // nothing listens
	addrs, err := d.LookupNetIP(context.Background(), "x.test")
	if err != nil || len(addrs) != 1 || fb.called.Load() == 0 {
		t.Fatalf("expected fallback: %v %v", addrs, err)
	}
}

func TestDoTRejectsWrongCertificateName(t *testing.T) {
	ts := startDoT(t)
	d, _ := NewDoT([]string{ts.addr}, "other.name", nil, nil)
	d.tlsCfg.RootCAs = ts.pool
	if _, err := d.LookupNetIP(context.Background(), "x.test"); err == nil {
		t.Fatal("resolver accepted a certificate for the wrong name")
	}
}

func TestNewDoTRequiresIPServers(t *testing.T) {
	if _, err := NewDoT([]string{"dns.quad9.net"}, "dns.quad9.net", nil, nil); err == nil {
		t.Fatal("hostname DoT server should be rejected (bootstrap leak)")
	}
	if d, err := NewDoT([]string{"9.9.9.9"}, "dns.quad9.net", nil, nil); err != nil || d.servers[0] != "9.9.9.9:853" {
		t.Fatalf("default port: %v %v", d, err)
	}
}

func TestLocalhostNeverQueried(t *testing.T) {
	ts := startDoT(t)
	d := newTestResolver(t, ts, nil)
	d.LookupNetIP(context.Background(), "localhost")
	if ts.queries.Load() != 0 {
		t.Fatal("localhost must not be sent to the network")
	}
}
