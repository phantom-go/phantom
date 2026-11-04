package auth

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// addr returns a net.Addr whose String() yields "host:port", matching
// what extractIP() expects.
type addr struct{ s string }

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return a.s }

func TestRateLimiterBansAfterMaxFailures(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute, time.Minute)
	defer rl.Close()

	a := addr{"1.2.3.4:5000"}
	if rl.IsBanned(a) {
		t.Fatal("fresh IP should not be banned")
	}

	rl.RecordFailure(a)
	rl.RecordFailure(a)
	if rl.IsBanned(a) {
		t.Error("should not be banned before threshold")
	}
	rl.RecordFailure(a)
	if !rl.IsBanned(a) {
		t.Error("should be banned after threshold")
	}
}

func TestRateLimiterPerIPIsolation(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, time.Minute)
	defer rl.Close()

	a := addr{"1.2.3.4:5000"}
	b := addr{"9.9.9.9:5000"}

	rl.RecordFailure(a)
	rl.RecordFailure(a)
	if !rl.IsBanned(a) {
		t.Error("a should be banned")
	}
	if rl.IsBanned(b) {
		t.Error("b should not be banned by a's failures")
	}
}

func TestRateLimiterRecordSuccessClears(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, time.Minute)
	defer rl.Close()

	a := addr{"1.2.3.4:5000"}
	rl.RecordFailure(a)
	rl.RecordSuccess(a)
	rl.RecordFailure(a)
	if rl.IsBanned(a) {
		t.Error("should not be banned — success cleared the counter")
	}
}

func TestRateLimiterMalformedAddrIgnored(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, time.Minute)
	defer rl.Close()

	// Empty-string address — extractIP returns "" and the limiter
	// silently no-ops.
	bad := addr{""}
	rl.RecordFailure(bad)
	if rl.IsBanned(bad) {
		t.Error("malformed addr should never be banned (records dropped)")
	}
}

func TestExtractIPFromTCPAddr(t *testing.T) {
	// Spot-check: extractIP should work with a real net.TCPAddr too,
	// not just our stub addr type.
	ta := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	if got := extractIP(ta); got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %q", got)
	}
}

func TestRateLimiterGroupsIPv6By64(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute, time.Minute)
	defer rl.Close()
	for i := 1; i <= 3; i++ {
		rl.RecordFailure(&net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("2001:db8:1:2::%x", i)), Port: 1})
	}
	if !rl.IsBanned(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::ffff"), Port: 9}) {
		t.Error("rotating addresses inside one /64 should share a ban")
	}
	if rl.IsBanned(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:3::1"), Port: 9}) {
		t.Error("a different /64 must not be banned")
	}
}

func TestRateLimiterCapEvictionKeepsBans(t *testing.T) {
	rl := NewRateLimiterWithCap(1, time.Minute, time.Minute, 128)
	defer rl.Close()
	banned := &net.TCPAddr{IP: net.ParseIP("9.9.9.9"), Port: 1}
	rl.RecordFailure(banned) // count 1 >= maxFailures 1? first insert sets count=1
	rl.RecordFailure(banned)
	if !rl.IsBanned(banned) {
		t.Fatal("setup: expected ban")
	}
	for i := 0; i < 10000; i++ {
		rl.RecordFailure(&net.TCPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 1})
	}
	if !rl.IsBanned(banned) {
		t.Error("spraying fresh IPs must not flush an active ban")
	}
	rl.mu.Lock()
	n := len(rl.failures)
	rl.mu.Unlock()
	if n > 129 {
		t.Errorf("map exceeded cap: %d", n)
	}
}

func BenchmarkRecordFailureAtCap(b *testing.B) {
	rl := NewRateLimiter(1000, time.Hour, time.Minute)
	defer rl.Close()
	for i := 0; i < DefaultMaxEntries; i++ {
		rl.RecordFailure(&net.TCPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 1})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.RecordFailure(&net.TCPAddr{IP: net.IPv4(11, byte(i>>16), byte(i>>8), byte(i)), Port: 1})
	}
}
