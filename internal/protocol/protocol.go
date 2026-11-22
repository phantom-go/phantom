package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	CmdConnect = 0x01
	CmdUDP     = 0x03

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

type Address struct {
	Type byte
	Host string
	Port uint16
}

// String returns "host:port". IPv6 literals are bracketed ("[::1]:443") so
// the result can be fed straight back into net.SplitHostPort / net.Dial.
// The previous fmt.Sprintf("%s:%d") form produced "::1:443", which
// SplitHostPort rejects — every IPv6 relay target silently failed.
func (a *Address) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

type Request struct {
	Command byte
	Address Address
}

type Header struct {
	PasswordHash string
	Request      Request
}

type UDPPacket struct {
	Address Address
	Payload []byte
}

// HashPassword computes the SHA-224 hash of the password and returns its hex string representation.
func HashPassword(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ResolveAddress exposes the address resolution logic to determine IPv4, IPv6, or Domain type.
func ResolveAddress(host string, port uint16) (Address, error) {
	return resolveAddress(host, port)
}

// HashLength is the length of the hex-encoded SHA-224 password hash.
const HashLength = 56

var crlf = [2]byte{'\r', '\n'}

var errInvalidCRLF = errors.New("invalid CRLF")

// ParseHeader parses the incoming Trojan handshake header from the client (Server side).
//
// The fixed-size prefix (hash + CRLF + command) is read with a single
// ReadFull into a stack buffer, cutting the number of Read calls (each of
// which goes through the TLS/smux/rewind layers) and heap allocations.
func ParseHeader(r io.Reader) (*Header, error) {
	sp := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sp)
	fixed := sp[:HashLength+2+1]
	if _, err := io.ReadFull(r, fixed); err != nil {
		return nil, err
	}
	if fixed[HashLength] != '\r' || fixed[HashLength+1] != '\n' {
		return nil, errInvalidCRLF
	}
	h := &Header{PasswordHash: string(fixed[:HashLength])}
	h.Request.Command = fixed[HashLength+2]

	addr, err := readAddressScratch(r, sp)
	if err != nil {
		return nil, err
	}
	h.Request.Address = addr

	if err := readCRLFScratch(r, sp); err != nil {
		return nil, err
	}
	return h, nil
}

// scratch is a reusable read buffer large enough for any address
// (1 + 1 + 255 + 2) or the fixed header prefix. Pooling it keeps the
// per-handshake reads off the heap (stack arrays escape through io.Reader).
type scratch [512]byte

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

// AppendHeader appends the wire encoding of h to buf.
func AppendHeader(buf []byte, h *Header) ([]byte, error) {
	buf = append(buf, h.PasswordHash...)
	buf = append(buf, crlf[:]...)
	buf = append(buf, h.Request.Command)
	buf, err := appendAddress(buf, h.Request.Address)
	if err != nil {
		return nil, err
	}
	return append(buf, crlf[:]...), nil
}

// WriteHeader writes the Trojan handshake header to the server (Client side).
//
// The header is encoded into one buffer and emitted with a single Write.
// Previously it was five separate Writes; over smux each Write becomes its
// own frame (8-byte header + scheduling) and over raw TLS its own record,
// so the handshake cost 5 frames/records instead of 1 — and the
// distinctive burst of tiny records was also a traffic-analysis signal.
func WriteHeader(w io.Writer, h *Header) error {
	sp := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sp)
	buf, err := AppendHeader(sp[:0], h)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// MaxUDPPayloadLength caps individual UDP packet payloads to bound the
// per-packet allocation in ReadUDPPacket. A 16-bit length field can encode
// up to 65535, but a maximally-sized payload is implausible for legitimate
// traffic (Ethernet jumbo frames stop around 9000 bytes; over QUIC/TCP
// transport the encapsulated packet is rarely above 1500). The previous
// "length > 65535" check was a no-op because the length field is uint16.
//
// This bound is conservative enough to never reject real traffic while
// preventing an attacker from amplifying a small Trojan-format stream
// into 64 KB-per-packet allocations.
const MaxUDPPayloadLength = 9000

// ReadUDPPacket parses one UDP frame:
//
//	ATYP | DST.ADDR | DST.PORT | Length (2, big-endian) | CRLF | Payload
//
// This is the Trojan-standard layout. Earlier versions put the CRLF AFTER
// the payload, which no real Trojan client does — so UDP (DNS, QUIC, games)
// through trojan:// compatibility mode never worked.
func ReadUDPPacket(r io.Reader) (*UDPPacket, error) {
	sp := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sp)

	addr, err := readAddressScratch(r, sp)
	if err != nil {
		return nil, err
	}

	// Length + CRLF in one read.
	lc := sp[:4]
	if _, err := io.ReadFull(r, lc); err != nil {
		return nil, err
	}
	if lc[2] != '\r' || lc[3] != '\n' {
		return nil, errInvalidCRLF
	}
	length := binary.BigEndian.Uint16(lc[:2])

	// Reject implausibly large payloads (see MaxUDPPayloadLength).
	if length > MaxUDPPayloadLength {
		return nil, fmt.Errorf("udp packet length too large: %d (max %d)", length, MaxUDPPayloadLength)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &UDPPacket{
		Address: addr,
		Payload: payload,
	}, nil
}

// udpBufPool recycles encode buffers for WriteUDPPacket. Sized for the
// largest frame: atyp + len + 255-byte domain + port + length + payload + CRLF.
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1+1+255+2+2+MaxUDPPayloadLength+2)
		return &b
	},
}

// WriteUDPPacket encapsulates and writes data into the Trojan UDP format.
//
// The whole frame is assembled in a pooled buffer and written once, so each
// datagram costs exactly one smux frame / TLS record / QUIC STREAM write
// instead of five, and no per-packet allocation.
func WriteUDPPacket(w io.Writer, host string, port uint16, payload []byte) error {
	if len(payload) > MaxUDPPayloadLength {
		return fmt.Errorf("udp payload too large: %d (max %d)", len(payload), MaxUDPPayloadLength)
	}
	addr, err := resolveAddress(host, port)
	if err != nil {
		return err
	}

	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)

	buf, err := appendAddress((*bp)[:0], addr)
	if err != nil {
		return err
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload)))
	buf = append(buf, crlf[:]...)
	buf = append(buf, payload...)
	*bp = buf[:0]

	_, err = w.Write(buf)
	return err
}

func readCRLFScratch(r io.Reader, sp *scratch) error {
	if _, err := io.ReadFull(r, sp[:2]); err != nil {
		return err
	}
	if sp[0] != '\r' || sp[1] != '\n' {
		return errInvalidCRLF
	}
	return nil
}

func readAddressScratch(r io.Reader, sp *scratch) (Address, error) {
	head := sp[:2]
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		return Address{}, err
	}

	addr := Address{Type: head[0]}

	switch head[0] {
	case AtypIPv4:
		b := sp[2 : 2+4+2]
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, err
		}
		addr.Host = net.IP(b[:4]).String()
		addr.Port = binary.BigEndian.Uint16(b[4:])

	case AtypIPv6:
		b := sp[2 : 2+16+2]
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, err
		}
		addr.Host = net.IP(b[:16]).String()
		addr.Port = binary.BigEndian.Uint16(b[16:])

	case AtypDomain:
		if _, err := io.ReadFull(r, head[1:2]); err != nil {
			return Address{}, err
		}
		n := int(head[1])
		if n == 0 {
			return Address{}, fmt.Errorf("empty domain name")
		}
		b := sp[2 : 2+n+2]
		if _, err := io.ReadFull(r, b); err != nil {
			return Address{}, err
		}
		addr.Host = string(b[:n])
		addr.Port = binary.BigEndian.Uint16(b[n : n+2])

	default:
		return Address{}, fmt.Errorf("unsupported address type: %d", head[0])
	}

	return addr, nil
}

func appendAddress(buf []byte, addr Address) ([]byte, error) {
	buf = append(buf, addr.Type)

	switch addr.Type {
	case AtypIPv4:
		ip := net.ParseIP(addr.Host).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid ipv4 address")
		}
		buf = append(buf, ip...)
	case AtypIPv6:
		ip := net.ParseIP(addr.Host).To16()
		if ip == nil {
			return nil, fmt.Errorf("invalid ipv6 address")
		}
		buf = append(buf, ip...)
	case AtypDomain:
		if len(addr.Host) == 0 {
			return nil, fmt.Errorf("empty domain name")
		}
		if len(addr.Host) > 255 {
			return nil, fmt.Errorf("domain name too long")
		}
		buf = append(buf, byte(len(addr.Host)))
		buf = append(buf, addr.Host...)
	default:
		return nil, fmt.Errorf("unsupported address type: %d", addr.Type)
	}

	return binary.BigEndian.AppendUint16(buf, addr.Port), nil
}

func resolveAddress(host string, port uint16) (Address, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return Address{Type: AtypIPv4, Host: host, Port: port}, nil
		}
		return Address{Type: AtypIPv6, Host: host, Port: port}, nil
	}
	return Address{Type: AtypDomain, Host: host, Port: port}, nil
}
