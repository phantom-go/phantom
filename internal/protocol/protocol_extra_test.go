package protocol

import (
	"bytes"
	"net"
	"testing"
)

type countingWriter struct {
	bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) { w.writes++; return w.Buffer.Write(p) }

func TestAddressStringIPv6IsDialable(t *testing.T) {
	a := Address{Type: AtypIPv6, Host: "2001:db8::1", Port: 443}
	if got := a.String(); got != "[2001:db8::1]:443" {
		t.Fatalf("got %q", got)
	}
	if _, _, err := net.SplitHostPort(a.String()); err != nil {
		t.Fatalf("not splittable: %v", err)
	}
}

func TestWriteHeaderIsOneWrite(t *testing.T) {
	addr, _ := ResolveAddress("example.com", 443)
	h := &Header{PasswordHash: HashPassword("pw"), Request: Request{Command: CmdConnect, Address: addr}}
	var w countingWriter
	if err := WriteHeader(&w, h); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("expected 1 write, got %d", w.writes)
	}
	got, err := ParseHeader(&w.Buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != h.PasswordHash || got.Request.Address != addr {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestWriteUDPPacketIsOneWrite(t *testing.T) {
	var w countingWriter
	if err := WriteUDPPacket(&w, "::1", 53, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("expected 1 write, got %d", w.writes)
	}
	pkt, err := ReadUDPPacket(&w.Buffer)
	if err != nil || string(pkt.Payload) != "hello" || pkt.Address.Host != "::1" {
		t.Fatalf("round trip: %+v %v", pkt, err)
	}
}

func TestWriteUDPPacketRejectsOversize(t *testing.T) {
	if err := WriteUDPPacket(&bytes.Buffer{}, "1.2.3.4", 1, make([]byte, MaxUDPPayloadLength+1)); err == nil {
		t.Fatal("expected error")
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkWriteHeader(b *testing.B) {
	addr, _ := ResolveAddress("www.example.com", 443)
	h := &Header{PasswordHash: HashPassword("pw"), Request: Request{Command: CmdConnect, Address: addr}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = WriteHeader(discardWriter{}, h)
	}
}

func BenchmarkWriteUDPPacket(b *testing.B) {
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = WriteUDPPacket(discardWriter{}, "8.8.8.8", 53, payload)
	}
}

func BenchmarkParseHeader(b *testing.B) {
	addr, _ := ResolveAddress("www.example.com", 443)
	var buf bytes.Buffer
	_ = WriteHeader(&buf, &Header{PasswordHash: HashPassword("pw"), Request: Request{Command: CmdConnect, Address: addr}})
	raw := buf.Bytes()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseHeader(bytes.NewReader(raw))
	}
}
