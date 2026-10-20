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

// Field run 18.10: a path dark for two minutes stood every relay down, all of
// them proven seconds apart, and every stream went to the freshest proof. The
// streams take their heads in turn among the relays that carried — stream 0 the
// freshest, as before — and a relay that failed its data plane leads nobody,
// however fresh its proof.
func TestOutageFallbackSpreadsTheStreamsOverTheRelaysThatCarried(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	const c, eater = "3.3.3.3:3478", "4.4.4.4:3478"
	addrs := []string{electTestA, electTestB, c, eater}
	proveServer(electTestA, 3*time.Second)
	proveServer(electTestB, 2*time.Second)
	proveServer(c, time.Second)
	proveServer(eater, 500*time.Millisecond)
	noteServerDemotedAt(eater, time.Now())
	for _, addr := range addrs {
		standDown(addr)
	}

	heads := map[string]int{}
	for id := 0; id < 9; id++ {
		got := assignRelays(addrs, id, time.Now())
		if len(got) != len(addrs) || got[len(got)-1] != eater {
			t.Fatalf("stream %d got %v: want the whole list, the demoted relay last", id, got)
		}
		heads[got[0]]++
	}
	for _, addr := range []string{electTestA, electTestB, c} {
		if heads[addr] != 3 {
			t.Fatalf("heads %v: want each relay that carried at the head of three streams' lists", heads)
		}
	}
	if got := assignRelays(addrs, 0, time.Now())[0]; got != c {
		t.Fatalf("stream 0 leads with %s, want the freshest proof %s", got, c)
	}
}

// Every relay stood down, one that carried crowded with a credential's ghosts:
// the streams spread over the others that carried, and it goes behind them —
// but never behind a relay that ate the data plane, which would then lead
// every stream (18.09).
func TestOutageOrderStepsAroundACrowdedRelayOnlyAmongThoseThatCarried(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	const c = "3.3.3.3:3478"
	addrs := []string{electTestA, electTestB, c}
	proveServer(electTestA, 3*time.Second)
	proveServer(electTestB, 2*time.Second)
	proveServer(c, time.Second)
	for _, addr := range addrs {
		standDown(addr)
	}
	crowded := map[string]bool{electTestB: true}
	heads := map[string]int{}
	for id := 0; id < 6; id++ {
		got := assignRelaysAround(addrs, id, time.Now(), crowded)
		if got[2] != electTestB {
			t.Fatalf("stream %d got %v: want the crowded relay behind the two others that carried", id, got)
		}
		heads[got[0]]++
	}
	if heads[electTestA] != 3 || heads[c] != 3 {
		t.Fatalf("heads %v: want the two that carried and are not crowded taking turns", heads)
	}

	resetServerHealth()
	proveServer(electTestA, time.Minute)
	standDown(electTestA)
	proveServer(electTestB, 10*time.Second)
	noteServerDemotedAt(electTestB, time.Now())
	for id := 0; id < 4; id++ {
		got := assignRelaysAround([]string{electTestA, electTestB}, id, time.Now(), map[string]bool{electTestA: true})
		if got[0] != electTestA {
			t.Fatalf("stream %d got %v: a crowded relay went behind the one that eats the data plane", id, got)
		}
	}
}

// Only the relays that carried are spread over: while one has, a relay that
// never did leads nobody.
func TestOutageFallbackLeadsWithTheOnlyRelayThatCarried(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	const c = "3.3.3.3:3478"
	addrs := []string{electTestA, electTestB, c}
	proveServer(electTestB, time.Minute)
	for _, addr := range addrs {
		standDown(addr)
	}
	for id := 0; id < 6; id++ {
		if got := assignRelays(addrs, id, time.Now()); got[0] != electTestB {
			t.Fatalf("stream %d got %v: want the only relay that carried, %s, first", id, got, electTestB)
		}
	}
}

// Among servers with the same kind of verdict, the one that carried traffic most
// recently leads (for stream 0; the others take turns, see above); with no proof
// on either side the canonical order stands, so every group still starts on the
// same host.
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
