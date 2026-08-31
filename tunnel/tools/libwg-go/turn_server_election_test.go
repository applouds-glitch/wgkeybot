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
	electTestC = "3.3.3.3:3478"
)

// proveServer marks addr as having carried a data-plane round trip `ago` in the
// past, with the given Dial→Allocate latency.
func proveServer(addr string, rtt time.Duration, ago time.Duration) {
	noteServerRTT(addr, rtt)
	noteServerHandshakeOKAt(addr, time.Now().Add(-ago))
}

// The whole point of the feature: one relay eats the data plane, and no stream
// goes near it again. Not merely demoted to the back of the list — removed from
// it, because runWithCreds fans out to every remaining candidate at once when
// the head fails to Allocate, so a dead host left in the list can still win that
// race and cost the stream another session.
func TestAssignServersDropsAServerThatFailedItsDataPlane(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, 80*time.Millisecond, electionSettleWindow+time.Second)
	noteServerDemotedAt(electTestB, time.Now())

	for id := 0; id < 8; id++ {
		got := assignServers(addrs, id)
		if got[0] != electTestA {
			t.Fatalf("stream %d ran on %s, want the proven server %s", id, got[0], electTestA)
		}
		if slices.Contains(got, electTestB) {
			t.Fatalf("stream %d still has the dead relay as a failover candidate: %v", id, got)
		}
	}
}

// Both relays work, and every stream still goes to one of them — the fastest.
// Spreading the load is what the old assignment did; the election deliberately
// gives it up so a single host carries the tunnel.
func TestAssignServersRoutesEveryStreamToTheFastestProvenServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, 300*time.Millisecond, electionSettleWindow+time.Second)
	proveServer(electTestB, 60*time.Millisecond, electionSettleWindow+time.Second)

	for id := 0; id < 8; id++ {
		if got := assignServers(addrs, id)[0]; got != electTestB {
			t.Fatalf("stream %d ran on %s, want the faster server %s", id, got, electTestB)
		}
	}
}

// The settle window exists so "fastest" means something. Both relays answer
// within about a second of each other, so electing on the first proof would
// crown whichever one workerStagger happened to start first — the spread has to
// hold until every working server has reported its latency.
func TestElectionWaitsOutTheSettleWindow(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, 300*time.Millisecond, 0)

	if got := electServer(addrs, time.Now()); got != "" {
		t.Fatalf("elected %s while the settle window was still open", got)
	}

	counts := map[string]int{}
	for id := 0; id < 8; id++ {
		counts[assignServers(addrs, id)[0]]++
	}
	if counts[electTestA] != 4 || counts[electTestB] != 4 {
		t.Fatalf("spread collapsed before the election was due: %v", counts)
	}

	// Once the window has passed the same state elects the only proven server.
	if got := electServer(addrs, time.Now().Add(electionSettleWindow+time.Second)); got != electTestA {
		t.Fatalf("elected %q after the settle window, want %s", got, electTestA)
	}
}

// The incumbent keeps every stream while it is eligible. Re-running the ranking
// on each call would migrate the whole tunnel on latency jitter — and only the
// elected server keeps measuring its rtt, since nothing else is dialed, so the
// comparison would be against a number frozen at startup.
func TestElectionIsSticky(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, 60*time.Millisecond, electionSettleWindow+time.Second)
	proveServer(electTestB, 300*time.Millisecond, electionSettleWindow+time.Second)

	if got := electServer(addrs, time.Now()); got != electTestA {
		t.Fatalf("elected %q, want the faster %s", got, electTestA)
	}

	// B is now the faster of the two, but A is still working.
	noteServerRTT(electTestB, time.Millisecond)
	if got := electServer(addrs, time.Now()); got != electTestA {
		t.Fatalf("election moved to %s on latency alone — incumbent %s was still fine", got, electTestA)
	}
}

// The elected relay is not immune: when it stops proving itself the session
// re-elects rather than riding it down.
func TestElectionReplacesAnElectedServerThatFails(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, 60*time.Millisecond, electionSettleWindow+time.Second)
	proveServer(electTestB, 300*time.Millisecond, electionSettleWindow+time.Second)

	if got := electServer(addrs, time.Now()); got != electTestA {
		t.Fatalf("elected %q, want %s", got, electTestA)
	}

	noteServerDemotedAt(electTestA, time.Now())

	if got := assignServers(addrs, 0)[0]; got != electTestB {
		t.Fatalf("stream stayed on %s after it failed, want %s", got, electTestB)
	}
}

// A lost uplink fails every relay at once. Demoting them all must leave the
// stream something to dial — that is an outage, not a bad host, and the next
// attempts have to re-probe the whole list.
func TestAssignServersFallsBackWhenEveryServerIsDemoted(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{electTestA, electTestB}
	proveServer(electTestA, 60*time.Millisecond, electionSettleWindow+time.Second)
	if got := electServer(addrs, time.Now()); got != electTestA {
		t.Fatalf("elected %q, want %s", got, electTestA)
	}

	now := time.Now()
	noteServerDemotedAt(electTestA, now)
	noteServerDemotedAt(electTestB, now)

	counts := map[string]int{}
	for id := 0; id < 8; id++ {
		got := assignServers(addrs, id)
		if len(got) != len(addrs) {
			t.Fatalf("stream %d got %v, want the whole list back", id, got)
		}
		counts[got[0]]++
	}
	if counts[electTestA] != 4 || counts[electTestB] != 4 {
		t.Fatalf("outage fallback did not re-probe both servers: %v", counts)
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

	proveServer(electTestB, 60*time.Millisecond, 0)
	if serverDemoted(electTestB) {
		t.Fatal("a server that carried a round trip is still out of rotation")
	}
}

// Groups hold their own credentials, so a group's link can come back with a
// server list that does not contain the elected one. It must take the best of
// what it got without dragging the global election with it — otherwise two
// groups with different lists would take turns overwriting each other's winner.
func TestElectionLeavesTheIncumbentAloneForAGroupThatLacksIt(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	proveServer(electTestA, 60*time.Millisecond, electionSettleWindow+time.Second)
	proveServer(electTestC, 90*time.Millisecond, electionSettleWindow+time.Second)

	if got := electServer([]string{electTestA, electTestB}, time.Now()); got != electTestA {
		t.Fatalf("elected %q, want %s", got, electTestA)
	}

	// A group whose VK link returned B and C only.
	if got := electServer([]string{electTestB, electTestC}, time.Now()); got != electTestC {
		t.Fatalf("group without the incumbent elected %q, want its own best %s", got, electTestC)
	}
	// And the incumbent still holds for the group that does have it.
	if got := electServer([]string{electTestA, electTestB}, time.Now()); got != electTestA {
		t.Fatalf("incumbent was replaced by another group's choice: got %q, want %s", got, electTestA)
	}
}

// The election runs beside the stand-down, not instead of it. A handshake
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
