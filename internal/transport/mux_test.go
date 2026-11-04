package transport

import (
	"io"
	"net"
	"testing"
	"time"
)

// With smux v1 a stream whose reader is stalled eventually exhausts the
// session-wide buffer and freezes every other stream (head-of-line
// blocking). v2 has per-stream windows, so other streams keep flowing.
func holBlocked(t *testing.T, version int) bool {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	go func() {
		s, err := AcceptMuxSessionVersion(srv, byte(version))
		if err != nil {
			return
		}
		defer s.Close()
		// stream 1: firehose; stream 2: echo
		st1, err := s.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			buf := make([]byte, 32<<10)
			for {
				if _, err := st1.Write(buf); err != nil {
					return
				}
			}
		}()
		st2, err := s.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(st2, st2)
	}()

	sess, err := NewMuxSessionVersion(cli, version)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	st1, _ := sess.OpenStream()
	st1.Write([]byte{0}) // open it; then never read
	time.Sleep(300 * time.Millisecond)

	st2, _ := sess.OpenStream()
	st2.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := st2.Write([]byte("ping")); err != nil {
		return true
	}
	buf := make([]byte, 4)
	_, err = io.ReadFull(st2, buf)
	return err != nil
}

func TestMuxV2AvoidsHeadOfLineBlocking(t *testing.T) {
	if holBlocked(t, 2) {
		t.Fatal("v2: a stalled stream blocked an unrelated stream")
	}
	t.Logf("v1 head-of-line blocked: %v (expected true; documents why v2 exists)", holBlocked(t, 1))
}

// NewMuxSession and AcceptMuxSession must always speak the same version.
func TestMuxHelpersAgree(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	go func() {
		s, err := AcceptMuxSession(srv)
		if err != nil {
			return
		}
		st, err := s.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(st, st)
	}()
	sess, err := NewMuxSession(cli)
	if err != nil {
		t.Fatal(err)
	}
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	st.SetDeadline(time.Now().Add(2 * time.Second))
	st.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("helpers disagree on smux version: %v", err)
	}
}
