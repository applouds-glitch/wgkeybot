/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// What a live sibling excuses on a failed TCP attempt, and what it never does:
// the relay's own answer stays the relay's, whoever else it is serving.
func TestIsolatedTCPAttemptFailure(t *testing.T) {
	now := time.Now()
	const relay = "relay-a:19302"
	failing := dispatchStream(2, false, now, 8)
	silence := fmt.Errorf("%w %s", errors.New("all retransmissions failed for"), "dHJhbnNhY3Rpb24=")
	timeout := opErr("dial", syscall.ETIMEDOUT)

	if tcpAttemptFailureIsIsolated(relay, failing, timeout) {
		t.Fatal("a failure was excused with nobody else on the relay")
	}
	defer trackLiveSession(relay, dispatchStream(1, true, now, 8))()

	for _, err := range []error{
		timeout,
		opErr("connect", syscall.ECONNRESET),
		silence,
		fmt.Errorf("%w %s", errors.New("turn: failed to retransmit transaction"), "key"),
		io.EOF,
		io.ErrUnexpectedEOF,
	} {
		if !tcpAttemptFailureIsIsolated(relay, failing, err) {
			t.Errorf("%v was held against a relay another stream is hearing", err)
		}
	}
	for _, err := range []error{
		nil,
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}},
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeUnauthorized}},
		errors.New("attribute not found"),
		errors.New("all retransmissions failed for 10.0.0.1"), // text alone is not the sentinel
		errDataPlaneHandshake,
	} {
		if tcpAttemptFailureIsIsolated(relay, failing, err) {
			t.Errorf("%v was excused: that is the relay's answer, or not a transport failure at all", err)
		}
	}
	if tcpAttemptFailureIsIsolated("relay-b:19302", failing, timeout) {
		t.Fatal("a stream on one relay excused another")
	}
}

// blackholeNthRelayDial sends the nth TCP dial to a listener that accepts and
// never answers: the connect succeeds and the Allocate meets silence.
func blackholeNthRelayDial(t *testing.T, nth int32) {
	t.Helper()
	hole, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	prev := dialRelayTCP
	var dialed atomic.Int32
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		if dialed.Add(1) == nth {
			return prev(ctx, d, hole.Addr().String())
		}
		return prev(ctx, d, addr)
	}
	t.Cleanup(func() {
		dialRelayTCP = prev
		hole.Close()
		for _, c := range held {
			c.Close()
		}
	})
}

// End to end, with pion's real error: an Allocate that meets silence over TCP
// while a sibling is up on the same relay costs the relay nothing…
func TestSilentTCPAllocateBesideALiveSiblingIsNotTheRelaysFault(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	pinRelayConnectGap(t, 600*time.Millisecond) // the sibling is ready before the second dial
	blackholeNthRelayDial(t, 2)

	h := runWorkersAgainst(t, 136, 2, []string{relay.addr})
	waitFor(t, "both streams up, the second after its silent Allocate", 15*time.Second, func() bool { return h.ready() == 2 })
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) for one flow's silence with a sibling hearing it", n)
	}
}

// …and with nobody on the relay it still counts.
func TestSilentTCPAllocateAloneStillCounts(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	blackholeNthRelayDial(t, 1)

	h := runWorkersAgainst(t, 137, 1, []string{relay.addr})
	waitFor(t, "the stream up after its silent Allocate", 15*time.Second, func() bool { return h.ready() == 1 })
	if n := relayStrikes(relay.addr); n != 1 {
		t.Fatalf("the relay took %d strike(s) for a silent Allocate with nobody to vouch for it, want 1", n)
	}
}
