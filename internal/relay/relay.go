// Package relay implements the bidirectional byte pump shared by the server
// (tunnel <-> target) and the client (SOCKS conn <-> tunnel stream).
//
// Compared with two bare io.Copy calls it adds:
//
//   - Pooled 32 KiB buffers. io.Copy allocates a fresh 32 KiB buffer per call
//     whenever neither side implements ReaderFrom/WriterTo in a useful way
//     (true for every tunnel wrapper in this project), i.e. 64 KiB of garbage
//     per proxied connection. Under load that is the dominant allocation.
//   - A shared idle timeout. The previous server code set an ABSOLUTE 5-minute
//     deadline, which killed every long download / video stream / SSH session
//     at exactly 5 minutes even while data was flowing. Here the deadline is
//     extended while either direction is active and only fires after the whole
//     connection has been silent for the idle window — which also reaps
//     half-dead peers that never send FIN.
//   - Correct teardown: a clean EOF half-closes the peer (CloseWrite) so the
//     opposite direction can drain; any hard error aborts both directions
//     immediately instead of leaving one goroutine parked until the timeout.
package relay

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// BufferSize matches smux's maximum frame payload and two TLS records.
const BufferSize = 32 * 1024

// DefaultIdleTimeout is how long a relayed connection may be completely silent
// (no bytes in either direction) before it is torn down.
const DefaultIdleTimeout = 5 * time.Minute

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, BufferSize)
		return &b
	},
}

// GetBuffer borrows a BufferSize scratch buffer. Return it with PutBuffer.
func GetBuffer() *[]byte { return bufPool.Get().(*[]byte) }

// PutBuffer returns a buffer obtained from GetBuffer.
func PutBuffer(b *[]byte) { bufPool.Put(b) }

type readDeadliner interface{ SetReadDeadline(time.Time) error }
type writeDeadliner interface{ SetWriteDeadline(time.Time) error }
type closeWriter interface{ CloseWrite() error }

type pipeState struct {
	idle     time.Duration
	lastNano atomic.Int64 // last activity in either direction (UnixNano)
	stopped  atomic.Bool  // set when the pipe is being torn down
}

func (s *pipeState) touch(now time.Time) { s.lastNano.Store(now.UnixNano()) }

func (s *pipeState) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, s.lastNano.Load()))
}

// Pipe copies a->b and b->a concurrently until both directions finish and
// returns the byte counts. idle <= 0 disables the idle timeout. Pipe does not
// close a or b; the caller owns their lifetimes.
func Pipe(a, b io.ReadWriter, idle time.Duration) (aToB, bToA int64) {
	st := &pipeState{idle: idle}
	st.touch(time.Now())

	done := make(chan int64, 1)
	go func() { done <- pump(b, a, st) }()
	bToA = pump(a, b, st)
	aToB = <-done
	return aToB, bToA
}

// pump copies src -> dst. On exit it signals the opposite direction.
func pump(dst io.Writer, src io.Reader, st *pipeState) int64 {
	bp := GetBuffer()
	defer PutBuffer(bp)
	buf := *bp

	rd, canReadDL := src.(readDeadliner)
	wd, canWriteDL := dst.(writeDeadliner)
	useIdle := st.idle > 0
	half := st.idle / 2

	var rArmed, wArmed time.Time
	var total int64
	var err error

	for {
		if useIdle && canReadDL {
			now := time.Now()
			// Re-arm lazily (at most every idle/2) so we do not pay a
			// deadline syscall/lock on every single read.
			if rArmed.Sub(now) < half {
				rArmed = now.Add(st.idle)
				_ = rd.SetReadDeadline(rArmed)
			}
		}

		var n int
		n, err = src.Read(buf)
		if n > 0 {
			if useIdle {
				now := time.Now()
				st.touch(now)
				if canWriteDL && wArmed.Sub(now) < half {
					wArmed = now.Add(st.idle)
					_ = wd.SetWriteDeadline(wArmed)
				}
			}
			var nw int
			nw, err = writeFull(dst, buf[:n])
			total += int64(nw)
			if err != nil {
				break
			}
		}
		if err != nil {
			if useIdle && canReadDL && isTimeout(err) && !st.stopped.Load() {
				// Our side timed out but the other direction may still be
				// busy (e.g. a large download with an idle upload side).
				if st.idleFor(time.Now()) < st.idle {
					rArmed = time.Time{}
					continue
				}
			}
			break
		}
	}

	if errors.Is(err, io.EOF) {
		// Clean end of this direction: propagate a half-close so the peer
		// sees EOF and the opposite direction can drain naturally.
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			return total
		}
	}
	// Hard error, idle expiry, or no half-close support: stop both sides.
	abort(dst, src, st)
	return total
}

func abort(dst io.Writer, src io.Reader, st *pipeState) {
	st.stopped.Store(true)
	now := time.Now()
	if d, ok := dst.(readDeadliner); ok {
		_ = d.SetReadDeadline(now)
	}
	if d, ok := src.(writeDeadliner); ok {
		_ = d.SetWriteDeadline(now)
	}
}

func writeFull(w io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := w.Write(p[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
