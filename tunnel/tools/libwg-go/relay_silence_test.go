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

// dialTimedOut is what a connect that ran out of time returns: "dial tcp X:
// i/o timeout".
func dialTimedOut() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
}

// Silence is what nothing answered, and only that: a reset, a refusal or a TURN
// answer is the relay heard, and what is not recognised stays the relay's.
func TestSilentFailureIsWhatNothingAnswered(t *testing.T) {
	for _, err := range []error{
		dialTimedOut(),
		opErr("connect", syscall.ETIMEDOUT),
		context.DeadlineExceeded,
		fmt.Errorf("%w %s", errors.New("all retransmissions failed for"), "dHJhbnNhY3Rpb24="),
		fmt.Errorf("relay proof: %w", errRelayNeverAnswered),
		fmt.Errorf("%w: %w", errRelayFlowTimedOut, opErr("write", syscall.EPIPE)),
	} {
		if !silentFailure(err) {
			t.Errorf("%v is not taken for silence", err)
		}
	}
	for _, err := range []error{
		nil,
		opErr("read", syscall.ECONNRESET),
		opErr("write", syscall.EPIPE),
		opErr("connect", syscall.ECONNREFUSED),
		&stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}},
		net.ErrClosed,
		errors.New("all retransmissions failed for 10.0.0.1"), // text alone is not the sentinel
	} {
		if silentFailure(err) {
			t.Errorf("%v is taken for silence", err)
		}
	}
}

// A silence is held against no relay only while none is heard over the same
// transport: the other transport's path says nothing about this one's.
func TestSilenceIsExcusedOnlyWhileNoRelayIsHeard(t *testing.T) {
	const relay = "relay-a:19302"
	mark := relayHeardMark(true)
	if !silenceNotToBlame(dialTimedOut(), true, mark, relay) {
		t.Fatal("a connect that timed out with no relay heard was held against its relay")
	}
	if silenceNotToBlame(opErr("connect", syscall.ECONNREFUSED), true, mark, relay) {
		t.Fatal("a refusal was excused as silence")
	}
	noteRelayHeard(false)
	if relayHeardMark(true) != mark {
		t.Fatal("a relay heard over UDP moved the count over TCP")
	}
	if !silenceNotToBlame(dialTimedOut(), true, mark, relay) {
		t.Fatal("a relay heard over UDP broke the silence over TCP")
	}
	noteRelayHeard(true)
	if silenceNotToBlame(dialTimedOut(), true, mark, relay) {
		t.Fatal("a connect that timed out while a relay was heard was excused")
	}
}

// failFirstRelayDial makes the first TCP dial to a relay fail with err; with
// heardMeanwhile, a relay is heard over TCP while it fails — another stream's,
// as far as this one can tell.
func failFirstRelayDial(t *testing.T, err error, heardMeanwhile bool) {
	t.Helper()
	prev := dialRelayTCP
	var dialed atomic.Int32
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		if dialed.Add(1) == 1 {
			if heardMeanwhile {
				noteRelayHeard(true)
			}
			return nil, err
		}
		return prev(ctx, d, addr)
	}
	t.Cleanup(func() { dialRelayTCP = prev })
}

// The field case (18.10): a connect timed out and no relay was heard meanwhile
// — the path's silence as much as the relay's, and nothing tells which.
func TestConnectThatTimedOutInTheDarkIsNotTheRelaysFault(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	failFirstRelayDial(t, dialTimedOut(), false)

	h := runWorkersAgainst(t, 149, 1, []string{relay.addr})
	waitFor(t, "the stream up on the second dial", 8*time.Second, func() bool { return h.ready() == 1 })
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) for a connect that timed out with no relay heard", n)
	}
}

// …and one that timed out while a relay was heard still counts.
func TestConnectThatTimedOutWhileARelayWasHeardStillCounts(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	failFirstRelayDial(t, dialTimedOut(), true)

	h := runWorkersAgainst(t, 150, 1, []string{relay.addr})
	waitFor(t, "the stream up on the second dial", 8*time.Second, func() bool { return h.ready() == 1 })
	if n := relayStrikes(relay.addr); n != 1 {
		t.Fatalf("the relay took %d strike(s) for a connect that timed out while a relay answered, want 1", n)
	}
}

// Over UDP: both relays silent, the head's Allocate unanswered and the race to
// the other unanswered too. Before, each took a strike for every round of it.
func TestAllocatesUnansweredByEveryRelayAreHeldAgainstNone(t *testing.T) {
	first, second := twoRelaySockets(t)
	head := &sourceCounter{PacketConn: first, seen: map[string]bool{}}
	other := &sourceCounter{PacketConn: second, seen: map[string]bool{}}
	for _, c := range []*sourceCounter{head, other} {
		go func() {
			b := make([]byte, 1500)
			for {
				if _, _, err := c.ReadFrom(b); err != nil {
					return
				}
			}
		}()
	}

	runWorkersAgainst(t, 151, 1, []string{first.LocalAddr().String(), second.LocalAddr().String()})
	// The second attempt's socket reaching the head: the first attempt has
	// failed, on both relays, and been accounted for.
	waitFor(t, "the stream's second attempt", 20*time.Second, func() bool { return head.count() >= 2 })
	for _, c := range []*sourceCounter{head, other} {
		if n := relayStrikes(c.LocalAddr().String()); n != 0 {
			t.Errorf("%s took %d strike(s) for an Allocate no relay answered", c.LocalAddr(), n)
		}
	}
}

// A relay whose port is closed refuses over ICMP, and pion hides the refusal
// behind a retransmit it could not write: the refusal is the relay heard, and
// it still counts (Codex review, 18.10).
func TestAllocateRefusedOverICMPStillCounts(t *testing.T) {
	pc := listenFakeRelay(t)
	closedPort := pc.LocalAddr().String()
	pc.Close()

	runWorkersAgainst(t, 152, 1, []string{closedPort})
	waitFor(t, "the closed port's strike", 8*time.Second, func() bool { return relayStrikes(closedPort) > 0 })
}
