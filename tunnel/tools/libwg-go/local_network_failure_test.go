/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func relayStrikes(addr string) int {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()
	return healthEntryLocked(addr).failures
}

func opErr(op string, errno syscall.Errno) error {
	return &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, errno)}
}

// Which errors are the local stack speaking about its own network — and which
// are the far end's answer, or its silence, and stay the relay's.
func TestLocalNetworkErrorsAreToldFromTheRelaysAnswers(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ECONNABORTED, syscall.ENETUNREACH, syscall.ENETDOWN, syscall.EADDRNOTAVAIL, syscall.EPERM} {
		if err := fmt.Errorf("relay TX: %w", opErr("write", errno)); !localNetworkError(err) {
			t.Errorf("%v was read as the relay's doing", err)
		}
	}
	for _, err := range []error{
		nil,
		opErr("connect", syscall.ECONNREFUSED),
		opErr("read", syscall.ECONNRESET),
		opErr("write", syscall.EPIPE),
		opErr("connect", syscall.ETIMEDOUT),
		context.DeadlineExceeded,
		errDataPlaneHandshake,
		errors.New("all retransmissions failed"),
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}},
	} {
		if localNetworkError(err) {
			t.Errorf("%v was read as the phone's own network", err)
		}
	}
}

// The network's side of it: nothing to say while there is none, or once the one
// an attempt began on was left after it began — and only then.
func TestNetworkLeftSince(t *testing.T) {
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	resetAllocationBook(t)

	before := time.Now()
	if networkLeftSince(before) {
		t.Fatal("a proxy never told of a network excused its relays")
	}
	setBoundNetwork(5, time.Now()) // the first network: nothing was left
	if networkLeftSince(before) {
		t.Fatal("the first network's arrival read as a departure")
	}
	setBoundNetwork(5, time.Now()) // the same network again
	if networkLeftSince(before) {
		t.Fatal("the same network reported again read as a departure")
	}

	time.Sleep(2 * time.Millisecond)
	setBoundNetwork(0, time.Now())
	if !networkLeftSince(time.Now()) {
		t.Fatal("no network, and the relay still answers for what ends now")
	}
	setBoundNetwork(5, time.Now())
	if !networkLeftSince(before) {
		t.Fatal("an attempt begun before the loss answers for it after the return")
	}
	time.Sleep(2 * time.Millisecond)
	after := time.Now()
	if networkLeftSince(after) {
		t.Fatal("an attempt begun after the return was excused by the old loss")
	}

	time.Sleep(2 * time.Millisecond)
	setBoundNetwork(6, time.Now()) // exchanged for another
	if !networkLeftSince(after) {
		t.Fatal("moving to another network did not read as leaving the old one")
	}
}

// failingWrites is a healthy connection whose writes fail with errno from the
// moment it is cued; reads go on, so nothing but the write ends the session.
type failingWrites struct {
	net.Conn
	errno syscall.Errno
	cued  *atomic.Bool
}

func (c *failingWrites) Write(p []byte) (int, error) {
	if c.cued.Load() {
		return 0, opErr("write", c.errno)
	}
	return c.Conn.Write(p)
}

// breakFirstRelayConn makes the first connection's writes fail with errno once
// cued; every later connection is left alone.
func breakFirstRelayConn(t *testing.T, errno syscall.Errno, cued *atomic.Bool) {
	t.Helper()
	prev := dialRelayTCP
	var dialed atomic.Int32
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		c, err := prev(ctx, d, addr)
		if err != nil || dialed.Add(1) != 1 {
			return c, err
		}
		return &failingWrites{Conn: c, errno: errno, cued: cued}, nil
	}
	t.Cleanup(func() { dialRelayTCP = prev })
}

// sessionEndsOnAWriteError runs one stream over TCP, breaks its socket with
// errno under a data packet, and returns the strikes the relay took by the time
// the stream is back on a new connection.
func sessionEndsOnAWriteError(t *testing.T, group int, errno syscall.Errno) int {
	t.Helper()
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	var cued atomic.Bool
	breakFirstRelayConn(t, errno, &cued)

	h := runWorkersAgainst(t, group, 1, []string{relay.addr})
	waitFor(t, "a stream over TCP", 5*time.Second, func() bool { return h.ready() == 1 })

	cued.Store(true)
	h.streams[0].in <- packetPool.Get().([]byte)[:200]
	waitFor(t, "the stream back up on a new connection", 8*time.Second, func() bool {
		return relay.ln.accepted.Load() >= 2 && h.ready() == 1
	})
	return relayStrikes(relay.addr)
}

// The field case: the network is torn down under a young session. The relay did
// nothing — and the same death by an error that is NOT the local network's still
// counts, or the exemption would have swallowed the accounting whole.
func TestSessionKilledByTheLocalNetworkIsNotTheRelaysFault(t *testing.T) {
	if n := sessionEndsOnAWriteError(t, 126, syscall.ECONNABORTED); n != 0 {
		t.Fatalf("the relay took %d strike(s) for a socket Android aborted", n)
	}
}

func TestSessionKilledByABrokenPipeStillCounts(t *testing.T) {
	if n := sessionEndsOnAWriteError(t, 127, syscall.EPIPE); n != 1 {
		t.Fatalf("the relay took %d strike(s) for a young session that broke, want 1", n)
	}
}

// The Allocate: its request cannot leave. Broken from the first write, so the
// connect succeeds and the Allocate is what fails.
func allocateFailsOnAWriteError(t *testing.T, group int, errno syscall.Errno) int {
	t.Helper()
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	var cued atomic.Bool
	cued.Store(true)
	breakFirstRelayConn(t, errno, &cued)

	h := runWorkersAgainst(t, group, 1, []string{relay.addr})
	waitFor(t, "the stream up on the second connection", 12*time.Second, func() bool {
		return relay.ln.accepted.Load() >= 2 && h.ready() == 1
	})
	return relayStrikes(relay.addr)
}

func TestAllocateTheLocalNetworkRefusedIsNotTheRelaysFault(t *testing.T) {
	if n := allocateFailsOnAWriteError(t, 128, syscall.ENETUNREACH); n != 0 {
		t.Fatalf("the relay took %d strike(s) for an Allocate that never left the phone", n)
	}
}

func TestAllocateThatBrokeOtherwiseStillCounts(t *testing.T) {
	if n := allocateFailsOnAWriteError(t, 129, syscall.EPIPE); n == 0 {
		t.Fatal("a failed Allocate no longer counts against the relay at all")
	}
}

// The connect: refused by the local stack, not by the relay (whose refusal is
// TestRefusedTCPConnectCountsAgainstTheRelay).
func TestConnectTheLocalNetworkRefusedIsNotTheRelaysFault(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	prev := dialRelayTCP
	var dialed atomic.Int32
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		if dialed.Add(1) == 1 {
			return nil, opErr("connect", syscall.ENETUNREACH)
		}
		return prev(ctx, d, addr)
	}
	t.Cleanup(func() { dialRelayTCP = prev })

	h := runWorkersAgainst(t, 130, 1, []string{relay.addr})
	waitFor(t, "the stream up on the second dial", 8*time.Second, func() bool { return h.ready() == 1 })
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) for a connect with no route", n)
	}
}
