package protocol

import (
	"bytes"
	"testing"
)

// Trojan standard UDP frame (trojan-gfw spec):
//
//	ATYP | DST.ADDR | DST.PORT | Length | CRLF | Payload
//
// Built byte-by-byte here, independent of our encoder, so the test pins
// interoperability with real Trojan clients.
func trojanUDPFrame(payload []byte) []byte {
	b := []byte{AtypIPv4, 8, 8, 8, 8, 0, 53, byte(len(payload) >> 8), byte(len(payload)), '\r', '\n'}
	return append(b, payload...)
}

func TestReadUDPPacketTrojanStandardFraming(t *testing.T) {
	var stream bytes.Buffer
	stream.Write(trojanUDPFrame([]byte("dns-query-1")))
	stream.Write(trojanUDPFrame([]byte("q2")))
	for _, want := range []string{"dns-query-1", "q2"} {
		pkt, err := ReadUDPPacket(&stream)
		if err != nil {
			t.Fatalf("reading standard Trojan UDP frame: %v", err)
		}
		if string(pkt.Payload) != want || pkt.Address.Host != "8.8.8.8" || pkt.Address.Port != 53 {
			t.Fatalf("got %+v", pkt)
		}
	}
}

func TestWriteUDPPacketTrojanStandardFraming(t *testing.T) {
	var got bytes.Buffer
	if err := WriteUDPPacket(&got, "8.8.8.8", 53, []byte("answer")); err != nil {
		t.Fatal(err)
	}
	if want := trojanUDPFrame([]byte("answer")); !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("not Trojan-standard framing:\n got  %q\n want %q", got.Bytes(), want)
	}
}
