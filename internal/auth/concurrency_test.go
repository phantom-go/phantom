package auth

import (
	"net"
	"testing"
)

func TestConcurrencyLimiterPerSource(t *testing.T) {
	l := NewConcurrencyLimiter(2)
	a := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}
	b := &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 1}
	r1, ok1 := l.Acquire(a)
	_, ok2 := l.Acquire(a)
	_, ok3 := l.Acquire(a)
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-source limit not enforced: %v %v %v", ok1, ok2, ok3)
	}
	if _, ok := l.Acquire(b); !ok {
		t.Fatal("another source must not be affected")
	}
	r1()
	r1() // idempotent
	if l.InUse(a) != 1 {
		t.Fatalf("release miscounted: %d", l.InUse(a))
	}
	// IPv6 /64 shares one budget.
	v6a := &net.TCPAddr{IP: net.ParseIP("2001:db8::1")}
	v6b := &net.TCPAddr{IP: net.ParseIP("2001:db8::2")}
	l.Acquire(v6a)
	l.Acquire(v6a)
	if _, ok := l.Acquire(v6b); ok {
		t.Fatal("addresses in one /64 must share a budget")
	}
}
