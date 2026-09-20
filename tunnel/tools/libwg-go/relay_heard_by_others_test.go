/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

// choosyPeer echoes the relay-proof keepalive like the server does, but only to
// the sources answers() lets through — a peer address is one allocation, so this
// is "that flow works, this one is deaf" as seen from the phone.
func choosyPeer(t *testing.T, answers func(nth int, firstSeen time.Time) bool) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	var mu sync.Mutex
	order := map[string]int{}
	first := map[string]time.Time{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			key := from.String()
			if _, seen := order[key]; !seen {
				order[key] = len(order)
				first[key] = time.Now()
			}
			nth, since := order[key], first[key]
			mu.Unlock()
			if isStunKeepalive(buf[:n]) && answers(nth, since) {
				pc.WriteTo(buf[:n], from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func shortTCPRelayProof(t *testing.T, d time.Duration) {
	t.Helper()
	prev := relayProofTimeoutTCP
	relayProofTimeoutTCP = d
	t.Cleanup(func() { relayProofTimeoutTCP = prev })
}

func TestRelayHeardByOthers(t *testing.T) {
	now := time.Now()
	witness := dispatchStream(1, true, now, 8)
	failing := dispatchStream(2, false, now, 8)
	const relay, other = "relay-a:19302", "relay-b:19302"
	defer trackLiveSession(relay, failing)()

	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a relay with nobody else on it had an alibi")
	}
	done := trackLiveSession(relay, witness)
	if !relayHeardByOthers(relay, failing, now) {
		t.Fatal("a ready stream that has just heard the relay is no alibi")
	}
	if relayHeardByOthers(relay, witness, now) {
		t.Fatal("a stream vouched for its own relay")
	}
	if relayHeardByOthers(other, failing, now) {
		t.Fatal("a stream on one relay vouched for another")
	}
	if relayHeardByOthers(relay, failing, now.Add(dispatchStaleAfter+time.Second)) {
		t.Fatal("a stream silent for longer than dispatchStaleAfter still vouched")
	}
	witness.ready.Store(false)
	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a stream that is not ready vouched")
	}
	witness.ready.Store(true)
	witness.activity.Store(nil)
	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a stream that has received nothing yet vouched")
	}
	witness.activity.Store(newStreamActivity(now, 0))
	done()
	if relayHeardByOthers(relay, failing, now) {
		t.Fatal("a session that ended still vouched")
	}
}

// Over TCP a probe is late, not lost. A flow that starts moving after 3s — past
// the UDP limit, inside the hangs the field showed clearing — carries the stream
// on its first connection, and nothing is held against anyone.
func TestSlowTCPFlowStillProvesItsRelay(t *testing.T) {
	if relayProofTimeoutTCP != dataPlaneHandshakeTimeout {
		t.Fatalf("relayProofTimeoutTCP is %v, want dataPlaneHandshakeTimeout", relayProofTimeoutTCP)
	}
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	peer := choosyPeer(t, func(_ int, first time.Time) bool { return time.Since(first) > 3*time.Second })

	h := runWorkersAgainstPeer(t, 131, 1, []string{relay.addr}, peer)
	waitFor(t, "the stream up once its flow moves", 7*time.Second, func() bool { return h.ready() == 1 })
	if n := relay.ln.accepted.Load(); n != 1 {
		t.Fatalf("the relay was connected to %d time(s): the slow flow was given up", n)
	}
	if serverDemoted(relay.addr) || relayStrikes(relay.addr) != 0 {
		t.Fatal("the relay was held to account for a flow that was only slow")
	}
}

// The same peer over UDP keeps the 2s limit: there an unanswered probe was lost.
func TestUDPRelayProofKeepsItsLimit(t *testing.T) {
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(_ int, first time.Time) bool { return time.Since(first) > 3*time.Second })

	runWorkersAgainstPeer(t, 132, 1, []string{relay.addr}, peer)
	waitFor(t, "the relay out of rotation after 2s of silence", 2900*time.Millisecond, func() bool {
		return serverDemoted(relay.addr)
	})
}

// The field case: one flow never proves itself while another stream is on the
// same relay and hearing it. That is the flow's failure.
func TestDeafTCPFlowIsNotHeldAgainstARelayOthersHear(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	shortTCPRelayProof(t, time.Second)
	pinRelayConnectGap(t, 300*time.Millisecond)
	peer := choosyPeer(t, func(nth int, _ time.Time) bool { return nth == 0 })

	h := runWorkersAgainstPeer(t, 133, 2, []string{relay.addr}, peer)
	waitFor(t, "the first stream up and the second one's flow given up", 8*time.Second, func() bool {
		return h.ready() == 1 && relay.ln.accepted.Load() >= 3
	})
	if serverDemoted(relay.addr) {
		t.Fatal("the relay went out of rotation with a stream hearing it")
	}
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) with a stream hearing it", n)
	}
}

// With nobody on the relay to vouch for it the verdict stands, over TCP too: a
// relay that allocates and carries nothing is out after its first handshake.
func TestDeafTCPRelayNobodyHearsIsStillDemoted(t *testing.T) {
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	shortTCPRelayProof(t, time.Second)
	peer := choosyPeer(t, func(int, time.Time) bool { return false })

	runWorkersAgainstPeer(t, 134, 1, []string{relay.addr}, peer)
	waitFor(t, "the relay out of rotation", 4*time.Second, func() bool { return serverDemoted(relay.addr) })
}

// Over UDP a flow has no fate of its own, and the rule is as it was: a relay
// whose new allocation carries nothing is out, whoever else is on it.
func TestUDPHandshakeFailureIsStillTheRelays(t *testing.T) {
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(nth int, _ time.Time) bool { return nth == 0 })

	h := runWorkersAgainstPeer(t, 135, 2, []string{relay.addr}, peer)
	waitFor(t, "one stream up, the relay out of rotation for the other's silence", 5*time.Second, func() bool {
		return h.ready() == 1 && serverDemoted(relay.addr)
	})
}
