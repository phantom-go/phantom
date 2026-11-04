package transport

import (
	"net/http"
	"testing"
)

func TestClientAddr(t *testing.T) {
	mk := func(remote string, h map[string]string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name  string
		r     *http.Request
		trust bool
		want  string
	}{
		{"untrusted ignores headers", mk("9.9.9.9:1000", map[string]string{"X-Forwarded-For": "1.1.1.1"}), false, "9.9.9.9"},
		{"rightmost XFF wins", mk("127.0.0.1:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 2.2.2.2"}), true, "2.2.2.2"},
		{"X-Real-IP preferred", mk("127.0.0.1:1", map[string]string{"X-Real-IP": "3.3.3.3", "X-Forwarded-For": "6.6.6.6"}), true, "3.3.3.3"},
		{"hostname never resolved", mk("4.4.4.4:5", map[string]string{"X-Real-IP": "evil.example"}), true, "4.4.4.4"},
		{"ipv6", mk("[2001:db8::1]:5", nil), false, "2001:db8::1"},
	}
	for _, c := range cases {
		a := ClientAddr(c.r, c.trust)
		host := a.String()
		if ta, ok := a.(interface{ String() string }); ok {
			host = ta.String()
		}
		if got := hostOnly(host); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func hostOnly(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			h := s[:i]
			if len(h) > 1 && h[0] == '[' {
				h = h[1 : len(h)-1]
			}
			return h
		}
	}
	return s
}
