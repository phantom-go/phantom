package protocol

import (
	"bytes"
	"testing"
)

func FuzzParseHeader(f *testing.F) {
	addr, _ := ResolveAddress("example.com", 443)
	var b bytes.Buffer
	WriteHeader(&b, &Header{PasswordHash: HashPassword("x"), Request: Request{Command: CmdConnect, Address: addr}})
	f.Add(b.Bytes())
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseHeader(bytes.NewReader(data))
		if err != nil {
			return
		}
		// Round trip must be stable.
		var out bytes.Buffer
		if err := WriteHeader(&out, h); err != nil {
			return
		}
		h2, err := ParseHeader(&out)
		if err != nil || h2.PasswordHash != h.PasswordHash || h2.Request != h.Request {
			t.Fatalf("round trip mismatch: %+v vs %+v (%v)", h, h2, err)
		}
	})
}

func FuzzReadUDPPacket(f *testing.F) {
	var b bytes.Buffer
	WriteUDPPacket(&b, "8.8.8.8", 53, []byte("q"))
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		for i := 0; i < 8; i++ {
			p, err := ReadUDPPacket(r)
			if err != nil {
				return
			}
			if len(p.Payload) > MaxUDPPayloadLength {
				t.Fatalf("oversized payload accepted: %d", len(p.Payload))
			}
		}
	})
}
