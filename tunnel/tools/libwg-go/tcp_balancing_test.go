/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"slices"
	"testing"
	"time"
)

// Exercise actual TCP connects, TURN allocations and peer round trips. After
// losing one relay, the five existing sessions on the other must stay up while
// it takes the five replacements.
func TestTCPPoolBalancesAndRecoversOnTheSurvivingRelay(t *testing.T) {
	a := startTCPTestRelay(t, listenTCPRelay(t))
	front := startStallingFront(t, a.addr)
	b := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	pinRelayConnectGap(t, 80*time.Millisecond)

	h := runWorkersAgainst(t, 141, 10, []string{b.addr, front.addr})
	t.Cleanup(front.close)
	waitFor(t, "ten proven TCP streams", 6*time.Second, func() bool { return h.ready() == 10 })
	if na, nb := front.accepted.Load(), b.ln.accepted.Load(); na != 5 || nb != 5 {
		t.Fatalf("initial connections %d/%d, want 5/5", na, nb)
	}

	front.frozen.Store(true)
	front.resetDownstream()
	waitFor(t, "ten streams on the surviving relay", 10*time.Second, func() bool {
		return h.ready() == 10 && liveAllocations(t.Name(), b.addr) == 10
	})
	if n := b.ln.accepted.Load(); n != 10 {
		t.Fatalf("survivor accepted %d connections, want five original plus five replacements", n)
	}
}

func TestTCPRelayPreferencesPreserveHealthAndUDPPolicy(t *testing.T) {
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	resetAllocationBook(t)
	setRelayTransport(relayTransportAsConfigured)
	t.Cleanup(func() { setRelayTransport(relayTransportAsConfigured) })
	now := time.Now()
	addrs := []string{electTestB, electTestA, electTestB}
	original := slices.Clone(addrs)
	tcp, udp := WorkerGroupConfig{}, WorkerGroupConfig{UseUDP: true}
	proveServer(electTestB, time.Millisecond, electionSettleWindow+time.Second)
	proveServer(electTestA, time.Second, electionSettleWindow+time.Second)

	for id := 0; id < 10; id++ {
		got := streamAttemptOrder("user", addrs, id, tcp, now)
		want := []string{electTestA, electTestB}[id%2]
		if len(got) != 2 || got[0] != want {
			t.Fatalf("TCP stream %d got %v, want preferred %s with one fallback", id, got, want)
		}
		if got := streamAttemptOrder("user", addrs[:2], id, udp, now); got[0] != electTestB {
			t.Fatalf("UDP stream %d ignored the elected relay: %v", id, got)
		}
	}
	if !slices.Equal(addrs, original) {
		t.Fatal("relay ordering mutated cached credentials")
	}

	// Android's per-network override must select the same policy as the config.
	setRelayTransport(relayTransportTCP)
	if got := streamAttemptOrder("user", addrs, 0, udp, now); got[0] != electTestA {
		t.Fatalf("TCP network override did not distribute streams: %v", got)
	}
	setRelayTransport(relayTransportUDP)
	if got := streamAttemptOrder("user", addrs[:2], 0, tcp, now); got[0] != electTestB {
		t.Fatalf("UDP network override did not keep election: %v", got)
	}
	setRelayTransport(relayTransportAsConfigured)

	noteServerDemotedAt(electTestA, now.Add(time.Second))
	for id := 0; id < 10; id++ {
		if got := streamAttemptOrder("user", addrs, id, tcp, now); !slices.Equal(got, []string{electTestB}) {
			t.Fatalf("failed relay still assigned to stream %d: %v", id, got)
		}
	}
	noteServerHandshakeOKAt(electTestA, now.Add(2*time.Second))
	if got := streamAttemptOrder("user", addrs, 0, tcp, now); got[0] != electTestA {
		t.Fatalf("proven relay did not rejoin the preferences: %v", got)
	}

	standDown(electTestA)
	if got := streamAttemptOrder("user", addrs, 0, tcp, time.Now()); !slices.Equal(got, []string{electTestB}) {
		t.Fatalf("TCP balancing ignored a relay penalty: %v", got)
	}
	noteServerDemotedAt(electTestB, now.Add(3*time.Second))
	for id := 0; id < 2; id++ {
		if got := streamAttemptOrder("user", addrs, id, tcp, time.Now()); !slices.Equal(got, []string{electTestA, electTestB}) {
			t.Fatalf("outage must preserve recovery order for every stream: %v", got)
		}
	}
}

func TestTCPRelayPreferencesRespectOrphanedAllocations(t *testing.T) {
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	resetAllocationBook(t)
	overTCP(t)
	now := time.Now()
	allocationBook.Lock()
	orphanLocked(relayIdentity{user: "old", relay: electTestA}, now)
	allocationBook.Unlock()
	addrs := []string{electTestA, electTestB}
	if got := streamAttemptOrder("old", addrs, 0, WorkerGroupConfig{}, now); got[0] != electTestB {
		t.Fatalf("balance sent the old credential to orphaned allocations: %v", got)
	}
	if got := streamAttemptOrder("new", addrs, 0, WorkerGroupConfig{}, now); got[0] != electTestA {
		t.Fatalf("another credential inherited the orphan penalty: %v", got)
	}
	if got := streamAttemptOrder("old", addrs, 0, WorkerGroupConfig{}, now.Add(orphanedAllocationLifetime+time.Second)); got[0] != electTestA {
		t.Fatalf("expired orphan penalty prevented balancing: %v", got)
	}
}
