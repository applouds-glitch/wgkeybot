/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"slices"
	"testing"
	"time"
)

// Two relays, the shape VK actually returns. Sorted order is A then B.
const (
	electTestA = "1.1.1.1:3478"
	electTestB = "2.2.2.2:3478"
)

// proveServer marks addr as having carried a data-plane round trip `ago` in the
// past.
func proveServer(addr string, ago time.Duration) {
	noteServerHandshakeOKAt(addr, time.Now().Add(-ago))
}

// The whole point of the feature: one relay eats the data plane, and no stream
// goes near it again. Not merely demoted to the back of the list — removed from
// it, because runWithCreds fans out to every remaining candidate at once when
// the head fails to Allocate, so a dead host left in the list can still win that
// race and cost the stream another session.
func TestAssignRelaysDropsAServerThatFailedItsDataPlane(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, time.Second)
	noteServerDemotedAt(electTestB, time.Now())

	for id := 0; id < 8; id++ {
		got := assignRelays(addrs, id, time.Now())
		if got[0] != electTestA {
			t.Fatalf("stream %d ran on %s, want the proven server %s", id, got[0], electTestA)
		}
		if slices.Contains(got, electTestB) {
			t.Fatalf("stream %d still has the dead relay as a failover candidate: %v", id, got)
		}
	}
}

// A lost uplink fails every relay at once. Demoting them all must leave the
// stream something to dial — that is an outage, not a bad host, and the next
// attempts get the whole list back: the first server, the rest as failover.
func TestAssignRelaysFallsBackWhenEveryServerIsDemoted(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, time.Second)

	now := time.Now()
	noteServerDemotedAt(electTestA, now)
	noteServerDemotedAt(electTestB, now)

	for id := 0; id < 2; id++ {
		if got := assignRelays(addrs, id, now); !slices.Equal(got, addrs) {
			t.Fatalf("stream %d outage fallback got %v, want the whole list %v", id, got, addrs)
		}
	}
}

// Nobody re-probes a demoted relay on a timer, but the ban is not a latch
// either: if one does carry a round trip — reached as a failover candidate once
// everything else was gone — its proof is newer than its failure and it is back.
func TestDemotionEndsWhenTheServerProvesItselfAgain(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	noteServerDemotedAt(electTestB, time.Now().Add(-time.Minute))
	if !serverDemoted(electTestB) {
		t.Fatal("a failed data-plane handshake did not take the server out of rotation")
	}

	proveServer(electTestB, 0)
	if serverDemoted(electTestB) {
		t.Fatal("a server that carried a round trip is still out of rotation")
	}
}

// Demotion runs beside the stand-down, not instead of it. A handshake
// failure with no sibling proof to vouch for the uplink still must not hand out
// a five-minute penalty (see TestHandshakeFailureWithoutProofFallsBackToTheStreak)
// — but it does take the server out of the rotation, which is the whole point of
// having a second, cheaper verdict.
func TestHandshakeFailureDemotesWithoutPenalising(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	attemptStart := time.Now()
	noteServerHandshakeFailureAt(electTestB, attemptStart, attemptStart.Add(2*time.Second))

	if serverPenalized(electTestB, attemptStart.Add(3*time.Second)) {
		t.Fatal("an unproven failure stood the server down on one strike")
	}
	if !serverDemoted(electTestB) {
		t.Fatal("a failed data-plane handshake left the server in the rotation")
	}
}

// standDown gives addr a streak long enough to serve a penalty right now.
func standDown(addr string) {
	now := time.Now()
	step := serverFailCoalesce + time.Second
	for strike := serverFailThreshold - 1; strike >= 0; strike-- {
		noteServerFailureAt(addr, now.Add(-time.Duration(strike)*step))
	}
}

// Field log 18.09, both sessions: A allocated in 200ms and never carried one
// SRTP handshake, B carried the tunnel but was stood down for Allocates that
// went unanswered on a flapping path. Everything had a verdict, so the whole
// list came back — in canonical order, A first — and since only a failed
// Allocate fans out, every stream spent the last minutes before the watchdog
// teardown on A. B has to lead: the verdict against it says its path blinked,
// the one against A says the relay itself eats the data plane.
//
// A's proof is the newer one on purpose: demotion has to outrank recency, or a
// relay that carried one round trip before failing would still take the head.
func TestOutageFallbackPutsTheDataPlaneFailureLast(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	proveServer(electTestB, 2*time.Minute)
	standDown(electTestB)
	proveServer(electTestA, 10*time.Second)
	noteServerDemotedAt(electTestA, time.Now())

	want := []string{electTestB, electTestA}
	for id := 0; id < 8; id++ {
		if got := assignRelays([]string{electTestA, electTestB}, id, time.Now()); !slices.Equal(got, want) {
			t.Fatalf("stream %d got %v, want %v: the relay that ate the data plane must only be failover", id, got, want)
		}
	}
}

// Among servers with the same kind of verdict, the one that carried traffic most
// recently leads; with no proof on either side the canonical order stands, so
// every group still starts on the same host.
func TestOutageFallbackPrefersTheFreshestProof(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	standDown(electTestA)
	standDown(electTestB)
	if got, want := assignRelays([]string{electTestB, electTestA}, 0, time.Now()), []string{electTestA, electTestB}; !slices.Equal(got, want) {
		t.Fatalf("no proof anywhere: got %v, want canonical %v", got, want)
	}

	proveServer(electTestA, 2*time.Minute)
	proveServer(electTestB, 30*time.Second)
	if got, want := assignRelays([]string{electTestA, electTestB}, 0, time.Now()), []string{electTestB, electTestA}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want the most recently proven server first %v", got, want)
	}
}
