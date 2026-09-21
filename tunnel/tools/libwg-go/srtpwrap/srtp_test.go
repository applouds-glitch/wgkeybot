package srtpwrap

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// errRelayClosed is what a closed pion/turn relay conn reports: an error of
// pion's own with net.ErrClosed's text, which errors.Is does not take for it.
var errRelayClosed = errors.New("use of closed network connection")

// relayLikeConn is a UDP socket that closes the way pion's relay conn does: the
// socket stays, and every ReadFrom from then on returns at once with an OpError
// around errRelayClosed. It polls the socket rather than blocking in it, so that
// what the test asks for takes effect on a read already under way.
type relayLikeConn struct {
	*net.UDPConn
	closeCh     chan struct{}
	closedReads atomic.Int64
	reading     chan struct{} // closed by the first ReadFrom
	readingOnce sync.Once

	// oversized is how many reads are still to fail with io.ErrShortBuffer;
	// oversizedServed is how many have.
	oversized       atomic.Int64
	oversizedServed atomic.Int64

	mu       sync.Mutex
	deadline time.Time // the reader's own, which the polling must not swallow
}

func newRelayLikeConn(t *testing.T) *relayLikeConn {
	t.Helper()
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return &relayLikeConn{UDPConn: u, closeCh: make(chan struct{}), reading: make(chan struct{})}
}

func (c *relayLikeConn) SetReadDeadline(at time.Time) error {
	c.mu.Lock()
	c.deadline = at
	c.mu.Unlock()
	return nil
}

func (c *relayLikeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readingOnce.Do(func() { close(c.reading) })
	for {
		select {
		case <-c.closeCh:
			c.closedReads.Add(1)
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: errRelayClosed}
		default:
		}
		if c.oversized.Load() > 0 {
			c.oversized.Add(-1)
			c.oversizedServed.Add(1)
			return 0, nil, io.ErrShortBuffer
		}
		c.mu.Lock()
		deadline := c.deadline
		c.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		c.UDPConn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		n, from, err := c.UDPConn.ReadFrom(p)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		return n, from, err
	}
}

func (c *relayLikeConn) Close() error {
	close(c.closeCh)
	return nil
}

func startServer(t *testing.T) *Server {
	t.Helper()
	srv, err := Listen(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

// Closing the relay is how a session is ended from outside. The reader has to
// end with it, saying why, and the demux must not go on reading a closed relay:
// it used to retry that error for ever — a million reads a second — while Read
// kept waiting.
func TestClosedUnderlayEndsTheReader(t *testing.T) {
	srv := startServer(t)
	relay := newRelayLikeConn(t)
	conn, err := Client(context.Background(), relay, srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 2048))
		readErr <- err
	}()

	relay.Close()
	select {
	case err := <-readErr:
		if !errors.Is(err, errRelayClosed) {
			t.Fatalf("Read ended with %v, want the underlay's own error in the chain", err)
		}
		var op *net.OpError
		if !errors.As(err, &op) {
			t.Fatalf("the underlay's error lost its kind: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read is still waiting 2s after the underlay was closed")
	}

	time.Sleep(100 * time.Millisecond)
	if n := relay.closedReads.Load(); n != 1 {
		t.Fatalf("the demux read the closed underlay %d times, want once", n)
	}
}

// The same during the handshake, which reads through the demux too: a relay
// closed under it ends the dial at once, not at the handshake timeout.
func TestClosedUnderlayEndsTheHandshake(t *testing.T) {
	silent := newRelayLikeConn(t) // a peer that never answers
	relay := newRelayLikeConn(t)

	dialErr := make(chan error, 1)
	go func() {
		_, err := Client(context.Background(), relay, silent.LocalAddr())
		dialErr <- err
	}()
	select {
	case <-relay.reading:
	case <-time.After(2 * time.Second):
		t.Fatal("the handshake never read from its underlay")
	}
	relay.Close()
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("a handshake with nobody succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the handshake outlived its underlay (timeout is %v)", HandshakeTimeout)
	}
}

// What must not end it: one datagram too large for the buffer is dropped, and
// the conn is as good as before.
func TestOversizedDatagramDoesNotEndTheReader(t *testing.T) {
	srv := startServer(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := srv.Accept(context.Background())
		if err == nil {
			accepted <- c
		}
	}()

	relay := newRelayLikeConn(t)
	conn, err := Client(context.Background(), relay, srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the server never accepted")
	}
	defer peer.Close()

	// Nothing has been sent yet, so what Read returns below was read by the demux
	// after both failures — which are waited for, not assumed.
	relay.oversized.Store(2)
	deadline := time.Now().Add(3 * time.Second)
	for relay.oversizedServed.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the demux took %d of 2 oversized reads and stopped reading", relay.oversizedServed.Load())
		}
		time.Sleep(time.Millisecond)
	}

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			got <- "error: " + err.Error()
			return
		}
		got <- string(buf[:n])
	}()
	if _, err := peer.Write([]byte("still here")); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "still here" {
			t.Fatalf("Read gave %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing arrived after the oversized datagrams")
	}
}
