/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// failingDial stands in for the upstream side in tests that never get that far.
func failingDial(_ context.Context, _ string, _ int) (net.Conn, error) {
	return nil, errors.New("upstream not available in this test")
}

// newTestTetherProxy starts a proxy on loopback with a dial function the test
// controls, so no test here ever touches the real internet.
func newTestTetherProxy(t *testing.T, dial tetherDialFunc, tweak ...func(*tetherProxy)) *tetherProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := newTetherProxy(ln, dial)
	// Configure before the accept loop starts: tweaking a field afterwards races
	// with the goroutine reading it.
	for _, f := range tweak {
		f(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.serve(ctx)
	t.Cleanup(p.stop)
	return p
}

func dialProxy(t *testing.T, p *tetherProxy) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", p.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// readClosed reports whether the peer closed the connection within d.
func readClosed(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, context.DeadlineExceeded) && !isTimeout(err)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func waitForConns(t *testing.T, p *tetherProxy, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.conns.Load() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("proxy never reached %d live connections (have %d)", want, p.conns.Load())
}

// A client speaking neither SOCKS5 nor HTTP gets dropped instead of being held
// open: an unrecognised first byte is the only signal we have that something on
// the shared network is not a proxy client at all.
func TestTetherProxyClosesUnknownProtocol(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)

	c := dialProxy(t, p)
	if _, err := c.Write([]byte{0xff}); err != nil {
		t.Fatalf("write: %v", err)
	}

	if !readClosed(c, 2*time.Second) {
		t.Fatal("proxy kept an unknown-protocol connection open")
	}
}

// The connection cap exists so one misbehaving client cannot exhaust the phone's
// memory; over the cap we drop immediately rather than queue.
func TestTetherProxyRefusesConnectionsOverCap(t *testing.T) {
	p := newTestTetherProxy(t, failingDial, func(p *tetherProxy) {
		p.maxConns = 1
		p.handshakeTimeout = 5 * time.Second
	})

	held := dialProxy(t, p) // parks in the handshake phase, holding the only slot
	_ = held
	waitForConns(t, p, 1)

	extra := dialProxy(t, p)
	if !readClosed(extra, 2*time.Second) {
		t.Fatal("proxy accepted a connection above its cap")
	}
}

// The sheet reports "N devices", and N is distinct client addresses, not
// connections: one laptop opens dozens of sockets.
func TestTetherProxyCountsDistinctClients(t *testing.T) {
	p := newTestTetherProxy(t, failingDial)

	first := dialProxy(t, p)
	second := dialProxy(t, p)
	_, _ = first, second
	waitForConns(t, p, 2)

	if got := p.stats().Clients; got != 1 {
		t.Fatalf("two sockets from one host counted as %d clients, want 1", got)
	}
}

// An accepted socket whose protect() failed must be closed immediately and
// never served. An unprotected socket would have replies routed into the tunnel
// and dropped, causing the client to hang until its timeout expires — the safe
// outcome is to fail the connection eagerly.
func TestTetherProxyClosesUnprotectedSocket(t *testing.T) {
	failingProtect := func(net.Conn) error {
		return errors.New("VpnService.protect() failed")
	}
	p := newTestTetherProxy(t, failingDial, func(p *tetherProxy) {
		p.protect = failingProtect
	})

	c := dialProxy(t, p)
	if !readClosed(c, 2*time.Second) {
		t.Fatal("proxy served an unprotected socket; it should have closed it immediately")
	}
}

// Sharing switched off must actually sever the connections it is serving.
// splice() waits for both directions and the upstream socket carries no
// deadline, so an idle peer used to keep the handler — and its deliberately
// unprotected upstream socket — alive after the tunnel came down, egressing out
// the carrier with the user's real IP.
func TestTetherProxyStopClosesLiveConnections(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	socksGreet(t, c)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	up := dial.upstream(t)
	reply := make([]byte, 10)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("reply code 0x%02x, want 0x00 (succeeded)", reply[1])
	}
	waitForConns(t, p, 1)
	// Neither side says another word: this is the shape that used to hang.
	_ = up

	done := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		p.stop()
		done <- time.Since(started)
	}()
	select {
	case took := <-done:
		// The 2s grace is a backstop; reaching it means the connection was
		// abandoned rather than closed.
		if took >= 2*time.Second {
			t.Fatalf("stop() took %v — it waited out the drain grace instead of closing connections", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop() never returned")
	}

	if !readClosed(c, 2*time.Second) {
		t.Fatal("stop() left an established client connection open")
	}
	if p.conns.Load() != 0 {
		t.Fatalf("%d connections still counted as live after stop()", p.conns.Load())
	}
}

// scriptedListener hands the accept loop a fixed sequence of errors, then a
// permanent one, so the retry policy can be exercised without exhausting the
// host's file descriptors for real.
type scriptedListener struct {
	mu    sync.Mutex
	errs  []error
	calls int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls < len(l.errs) {
		err := l.errs[l.calls]
		l.calls++
		return nil, err
	}
	l.calls++
	return nil, errors.New("listener is gone for good")
}

func (l *scriptedListener) Close() error { return nil }

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8888}
}

func (l *scriptedListener) acceptCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// Running out of file descriptors is the phone being briefly busy, not the end
// of sharing: the loop must wait it out. An error that really is fatal has to
// retire the proxy, because leaving the accept loop while tetherCurrent stays
// set makes wgTetherStats describe a healthy session over a dead listener.
func TestTetherProxyAcceptRetriesTemporaryThenRetiresOnFatal(t *testing.T) {
	ln := &scriptedListener{errs: []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED}}
	p := newTetherProxy(ln, failingDial)
	fatal := make(chan struct{})
	p.onFatal = func() { close(fatal) }
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	t.Cleanup(cancel)

	go p.serve(ctx)

	select {
	case <-fatal:
	case <-time.After(5 * time.Second):
		t.Fatal("a fatal accept error did not retire the proxy")
	}
	if got := ln.acceptCalls(); got <= len(ln.errs) {
		t.Fatalf("accept loop made %d calls; it gave up on a temporary error instead of retrying", got)
	}
}

// A client that connects and then says nothing is dropped when the handshake
// deadline expires. Without it one silent socket — a port scanner, a client that
// crashed mid-connect — would hold a slot out of the connection cap forever.
func TestTetherProxyDropsSilentClientAfterHandshakeDeadline(t *testing.T) {
	if tetherHandshakeTimeout != 5*time.Second {
		t.Fatalf("handshake deadline is %v; the spec fixes it at 5s", tetherHandshakeTimeout)
	}
	p := newTestTetherProxy(t, failingDial, func(p *tetherProxy) {
		// Same code path, shrunk so the test does not sit out the real deadline.
		p.handshakeTimeout = 150 * time.Millisecond
	})

	c := dialProxy(t, p)
	if !readClosed(c, 2*time.Second) {
		t.Fatal("proxy held a silent client past its handshake deadline")
	}
	waitForConns(t, p, 0)
}

// The sheet shows "sent / received", so the counters have to mean what they say:
// Up is what the client pushed out, Down is what came back, and neither includes
// the proxy's own handshake bytes.
func TestTetherProxyCountsBytesBothWays(t *testing.T) {
	dial := newRecordingDial()
	p := newTestTetherProxy(t, dial.fn)

	c := dialProxy(t, p)
	socksGreet(t, c)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	up := dial.upstream(t)
	reply := make([]byte, 10)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	// A payload is counted just after it is forwarded, so reading it at the far
	// end does not by itself prove the counter has moved yet — hence the wait
	// below rather than a bare assertion.
	sent := []byte("a request from the tethered client")
	if _, err := c.Write(sent); err != nil {
		t.Fatalf("client write: %v", err)
	}
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(up, make([]byte, len(sent))); err != nil {
		t.Fatalf("upstream read: %v", err)
	}

	received := []byte("and the answer coming back down")
	if _, err := up.Write(received); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(received))); err != nil {
		t.Fatalf("client read: %v", err)
	}

	waitForBytes(t, p, int64(len(sent)), int64(len(received)))
}

// waitForBytes waits for both counters to reach what was actually forwarded.
func waitForBytes(t *testing.T, p *tetherProxy, wantUp, wantDown int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var st tetherStats
	for time.Now().Before(deadline) {
		st = p.stats()
		if st.Up == wantUp && st.Down == wantDown {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("stats() = up %d / down %d, want up %d / down %d", st.Up, st.Down, wantUp, wantDown)
}

// The handshake deadline bounds how long a client may take to state what it
// wants. It must not also bound the dial that follows: resolving through the
// tunnel and connecting over TURN relays routinely takes longer than that, and
// with one deadline covering both, the success reply was written after the clock
// had already run out — the client saw a dropped connection on a connection that
// had actually been established.
func TestTetherProxySurvivesADialSlowerThanTheHandshakeDeadline(t *testing.T) {
	dial := newRecordingDial()
	slow := func(ctx context.Context, host string, port int) (net.Conn, error) {
		time.Sleep(300 * time.Millisecond)
		return dial.fn(ctx, host, port)
	}
	p := newTestTetherProxy(t, slow, func(p *tetherProxy) {
		p.handshakeTimeout = 100 * time.Millisecond
	})

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read status after a slow dial: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status %q, want 200 Connection established", status)
	}
}

// stop() has to close BOTH ends of every live connection. Closing only the
// client end leaves the upstream→client pipe parked in upstream.Read, which a
// closed client socket does not disturb: the handler never returns, the
// deliberately unprotected upstream descriptor outlives the tunnel, and every
// teardown pays the full drain backstop.
//
// The upstream is real TCP on purpose. net.Pipe has no CloseWrite, so
// closeWrite() closes it outright and this cannot reproduce — which is exactly
// why the old behaviour looked correct under test.
func TestTetherProxyStopClosesAnIdleTCPUpstream(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		// Never read from, never closed: an idle keep-alive peer that does not
		// answer our FIN.
		if c, err := upLn.Accept(); err == nil {
			accepted <- c
		}
	}()

	p := newTestTetherProxy(t, func(context.Context, string, int) (net.Conn, error) {
		return net.Dial("tcp", upLn.Addr().String())
	})

	c := dialProxy(t, p)
	if _, err := c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 64)); err != nil {
		t.Fatalf("proxy never established the tunnel: %v", err)
	}
	select {
	case up := <-accepted:
		defer up.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection never arrived")
	}
	waitForConns(t, p, 1)

	start := time.Now()
	p.stop()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("stop() took %v — it fell through to the drain backstop instead of closing the upstream", took)
	}
	if left := p.conns.Load(); left != 0 {
		t.Fatalf("%d connection(s) still counted as live after stop()", left)
	}
}
