/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// shortRelayUserTimeout gives the relay connections of one test a timeout the
// test can wait out.
func shortRelayUserTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := relayTCPUserTimeout
	relayTCPUserTimeout = d
	t.Cleanup(func() { relayTCPUserTimeout = prev })
}

// The hole this closes, end to end. A flow hangs while the stream carries
// traffic: the writer blocks in the socket, the keepalive queues up behind it,
// and with it the dead-stream detector — nothing in the client is left to notice.
// Nobody tears the session down here, unlike the close-budget test: the stream
// has to come back by itself, on a new connection, and the relay — which did
// nothing wrong — must not be blamed for the flow.
func TestHungTCPFlowUnderLoadIsReplacedByItself(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("TCP_USER_TIMEOUT is Linux's")
	}
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	overTCP(t)
	smallRelaySendBuffers(t)
	shortRelayUserTimeout(t, 2*time.Second)

	h := runWorkersAgainst(t, 120, 1, []string{front.addr})
	t.Cleanup(front.close) // before the harness waits for its worker
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	s := h.streams[0]

	front.frozen.Store(true)
	waitFor(t, "the writer to block on the full socket", 20*time.Second, func() bool {
		for full := false; !full; {
			select {
			case s.in <- packetPool.Get().([]byte)[:1200]:
			default:
				full = true
			}
		}
		time.Sleep(300 * time.Millisecond)
		return len(s.in) == cap(s.in)
	})
	front.frozen.Store(false) // the hung flow stays hung; the next one will flow

	// The kernel checks the limit when its probe timer fires, and that backs off:
	// a 2s limit is acted on within ~6s. The dead-stream detector, were it not
	// stuck behind the writer, would need 90.
	waitFor(t, "the stream back up on a new connection", 25*time.Second, func() bool {
		return front.accepted.Load() >= 2 && h.ready() == 1
	})

	serverHealthState.Lock()
	failures := healthEntryLocked(front.addr).failures
	serverHealthState.Unlock()
	if failures != 0 {
		t.Fatalf("the relay took %d strike(s) for a flow that timed out", failures)
	}
}

// errConn fails its reads and writes with whatever it was given.
type errConn struct {
	net.Conn
	readErr, writeErr error
}

func (c *errConn) Read([]byte) (int, error)  { return 0, c.readErr }
func (c *errConn) Write([]byte) (int, error) { return 0, c.writeErr }

// The kernel's verdict arrives once, to whichever call meets it first — pion's
// read loop as often as our writer — so both directions have to note it. And
// only that verdict: a deadline of our own (the close budget) and a plain broken
// pipe are other things.
func TestRelayFlowNotesTheKernelGivingUpOnEitherSide(t *testing.T) {
	timedOut := &net.OpError{Op: "x", Net: "tcp", Err: os.NewSyscallError("x", syscall.ETIMEDOUT)}
	others := []error{
		os.ErrDeadlineExceeded,
		&net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EPIPE)},
		&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
	}

	for _, side := range []string{"read", "write"} {
		inner := &errConn{readErr: others[0], writeErr: others[0]}
		raw := &splitFirstWriteConn{Conn: &relayFlowConn{Conn: inner, gaveUp: make(chan struct{})}}
		for _, err := range others {
			inner.readErr, inner.writeErr = err, err
			raw.Read(nil)
			raw.Write(nil)
			if relayFlowTimedOut(raw) {
				t.Fatalf("%v was taken for the kernel giving the flow up", err)
			}
		}
		if side == "read" {
			inner.readErr = timedOut
			raw.Read(nil)
		} else {
			inner.writeErr = timedOut
			raw.Write(nil)
		}
		select {
		case <-relayFlowGaveUp(raw):
		default:
			t.Fatalf("ETIMEDOUT on %s went unnoticed", side)
		}
		raw.Read(nil) // and again: the channel is closed once
		raw.Write(nil)
	}

	// Over UDP there is no flow: nothing to wait for, and nothing timed out.
	if relayFlowGaveUp(&net.UDPConn{}) != nil || relayFlowTimedOut(&net.UDPConn{}) {
		t.Fatal("a UDP conn was treated as a flow")
	}
}

// cuedTimeoutConn is a healthy connection whose reads, on cue, report the
// kernel's ETIMEDOUT — once, the way the kernel does. Its writes keep working:
// what is staged is only who got to hear the verdict.
type cuedTimeoutConn struct {
	net.Conn
	cue   chan struct{}
	fired bool
}

func (c *cuedTimeoutConn) Read(p []byte) (int, error) {
	for {
		if !c.fired {
			select {
			case <-c.cue:
				c.fired = true
				return 0, &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ETIMEDOUT)}
			default:
			}
		}
		c.Conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := c.Conn.Read(p)
		if ne, ok := err.(net.Error); ok && ne.Timeout() && n == 0 {
			continue
		}
		return n, err
	}
}

// The verdict can go to pion's read loop, which drops it and stops reading —
// and on an idle tunnel no write of ours follows to break on the dead socket.
// The session must end on the verdict itself, not wait for the dead-stream
// detector a minute and a half later.
func TestFlowGivenUpUnderThePionReaderEndsTheSessionAtOnce(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)

	cue := make(chan struct{})
	prev := dialRelayTCP
	first := true
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := prev(ctx, d, addr)
		if err != nil || !first {
			return c, err
		}
		first = false
		return &cuedTimeoutConn{Conn: c, cue: cue}, nil
	}
	t.Cleanup(func() { dialRelayTCP = prev })

	h := runWorkersAgainst(t, 121, 1, []string{relay.addr})
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	close(cue)
	waitFor(t, "the stream back up on a new connection", 8*time.Second, func() bool {
		return relay.ln.accepted.Load() >= 2 && h.ready() == 1
	})
}
