/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stallingFront stands between the worker and a TCP relay and, once frozen,
// stops taking the worker's bytes. That is what a hung flow looks like from the
// phone: the connection stays up, nothing more is acknowledged, the send buffer
// fills and the next write waits for room that never comes. Loopback cannot lose
// segments, but a reader that stops reading fills the same buffer.
type stallingFront struct {
	addr   string
	frozen atomic.Bool
	done   chan struct{}
	mu     sync.Mutex
	conns  []net.Conn
}

func startStallingFront(t *testing.T, relayAddr string) *stallingFront {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &stallingFront{addr: ln.Addr().String(), done: make(chan struct{})}
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp4", relayAddr)
			if err != nil {
				down.Close()
				continue
			}
			// A small window: less to fill before the worker's writes start to wait.
			down.(*net.TCPConn).SetReadBuffer(4096)
			f.mu.Lock()
			f.conns = append(f.conns, down, up)
			f.mu.Unlock()
			go io.Copy(down, up)
			go func() {
				buf := make([]byte, 4096)
				for {
					if f.frozen.Load() {
						<-f.done
						return
					}
					n, err := down.Read(buf)
					if err != nil {
						return
					}
					if _, err := up.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		f.close()
	})
	return f
}

func (f *stallingFront) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	for _, c := range f.conns {
		c.Close()
	}
}

// smallRelaySendBuffers shrinks the send buffer of every relay connection the
// test dials, for the same reason the front shrinks its receive buffer. Neither
// is what makes the writer block — the test feeds the stream until it does.
func smallRelaySendBuffers(t *testing.T) {
	t.Helper()
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := prev(ctx, d, addr)
		if err == nil {
			c.(*net.TCPConn).SetWriteBuffer(4096)
		}
		return c, err
	}
	t.Cleanup(func() { dialRelayTCP = prev })
}

// The hang this budget exists for, end to end: a stream over TCP whose flow
// stops moving while it carries traffic. Its writer blocks in the socket; a
// teardown then has to get the worker back. Before the budget it did not — the
// release pion writes on Close queued behind the blocked writer, the transport
// waited for the writer, and the raw.Close() that would have freed both never
// ran.
func TestStalledTCPFlowDoesNotHoldTheWorkerOnTeardown(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, relay.addr)
	overTCP(t)
	smallRelaySendBuffers(t)

	h := runWorkersAgainst(t, 116, 1, []string{front.addr})
	// Registered after the harness, so it runs before the harness waits for its
	// workers: if the budget is ever lost, the test fails below instead of
	// hanging in cleanup with the worker still stuck in the socket.
	t.Cleanup(front.close)
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })
	s := h.streams[0]

	front.frozen.Store(true)
	// Loopback buffers autotune into megabytes whatever was asked of them, so
	// keep the stream's queue topped up until it stops draining: that is the
	// writer blocked in the socket, with the queue full behind it.
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

	h.cancel()
	released := make(chan struct{})
	go func() {
		h.done.Wait()
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(relayCloseWriteBudget + 3*time.Second):
		t.Fatalf("the worker is still held by its stalled TCP flow %v after the teardown", relayCloseWriteBudget+3*time.Second)
	}

	// The release could not have gone out — the socket took nothing — and that
	// has to be booked as quota still held on this relay, not as a clean release.
	key := relayIdentity{user: t.Name(), relay: front.addr}
	allocationBook.Lock()
	_, orphaned := allocationBook.orphanedTill[key]
	_, released2 := allocationBook.releasedAt[key]
	allocationBook.Unlock()
	if !orphaned || released2 {
		t.Fatalf("a release that timed out in the socket: orphaned=%v released=%v, want it booked as still held", orphaned, released2)
	}
}

// deadlineSock records the write deadlines put on it.
type deadlineSock struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineSock) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, t)
	return nil
}

func (c *deadlineSock) set() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.deadlines)
}

// closeWatchingRelay notes how many deadlines the socket had when pion's Close —
// the one that writes the release — ran.
type closeWatchingRelay struct {
	net.PacketConn
	sock        *deadlineSock
	seenAtClose []int
}

func (r *closeWatchingRelay) Close() error {
	r.seenAtClose = append(r.seenAtClose, r.sock.set())
	return nil
}

// The order is the whole mechanism: the deadline has to be on the socket before
// the release is written, and only the first Close — the one that writes — sets
// it, so a later Close cannot push a running deadline further out.
func TestRelayCloseBudgetIsOnTheSocketBeforeTheReleaseIsWritten(t *testing.T) {
	sock := &deadlineSock{}
	inner := &closeWatchingRelay{sock: sock}
	relay := boundRelayClose(inner, sock)

	before := time.Now()
	relay.Close()
	relay.Close()

	if len(inner.seenAtClose) != 2 || inner.seenAtClose[0] != 1 {
		t.Fatalf("deadlines on the socket when each Close reached the relay: %v, want the first to find one", inner.seenAtClose)
	}
	if sock.set() != 1 {
		t.Fatalf("%d write deadlines set, want 1: only the first Close writes", sock.set())
	}
	if d := sock.deadlines[0].Sub(before); d < relayCloseWriteBudget || d > relayCloseWriteBudget+time.Second {
		t.Fatalf("deadline %v ahead, want %v", d, relayCloseWriteBudget)
	}
}
