package main

import (
	"net/netip"
	"testing"
)

func TestSSRFGuard(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
		"0.0.0.0", "0.1.2.3", "100.100.100.200", "100.64.0.1", "198.18.0.1",
		"255.255.255.255", "240.0.0.1", "224.0.0.1",
		"::1", "::", "fe80::1", "fd00:ec2::254", "fc00::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"64:ff9b::7f00:1",     // NAT64 -> 127.0.0.1
		"64:ff9b::a9fe:a9fe",  // NAT64 -> 169.254.169.254
		"2002:7f00:1::1",      // 6to4 -> 127.0.0.1
		"2001:0:4136:e378::1", // Teredo
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "64:ff9b::808:808"}
	for _, s := range blocked {
		if !isDisallowedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range allowed {
		if isDisallowedAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestSafeDialRejectsLiteralPrivate(t *testing.T) {
	if _, err := safeDialTCP("127.0.0.1:1", false, 0); err == nil {
		t.Fatal("expected refusal")
	}
	if _, err := safeDialTCP("[::1]:1", false, 0); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestSafeDialRejectsHostnameResolvingPrivate(t *testing.T) {
	// "localhost" resolves to loopback; the connect-time hook must refuse.
	if c, err := safeDialTCP("localhost:1", false, 0); err == nil {
		c.Close()
		t.Fatal("expected refusal")
	}
}
