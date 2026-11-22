package resolver

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func FuzzParseResponse(f *testing.F) {
	name := dnsmessage.MustNewName("example.test.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}})
	msg, _ := b.Finish()
	f.Add(msg)
	f.Fuzz(func(t *testing.T, data []byte) {
		addrs, ttl, _, err := parseResponse(data, 7, name, dnsmessage.TypeA)
		if err == nil {
			for _, a := range addrs {
				if !a.Is4() {
					t.Fatalf("A query returned non-IPv4 %v", a)
				}
			}
			if ttl < 0 {
				t.Fatal("negative TTL")
			}
		}
	})
}
