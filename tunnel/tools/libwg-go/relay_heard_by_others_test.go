/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/turn/v5"
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

// Over UDP as over TCP (22.10, the Rostelecom bench in relay_heard_by_others.go):
// one allocation that never proves itself while another stream on the same
// relay hears it is that flow's failure — the relay stays in the rotation and
// takes no strike, and the stream dials it again.
func TestDeafUDPFlowIsNotHeldAgainstARelayOthersHear(t *testing.T) {
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(nth int, _ time.Time) bool { return nth == 0 })

	h := runWorkersAgainstPeer(t, 135, 2, []string{relay.addr}, peer)
	waitFor(t, "one stream up and the other's flow given up and dialed again", 10*time.Second, func() bool {
		return h.ready() == 1 && relay.seen.count() >= 3
	})
	if serverDemoted(relay.addr) {
		t.Fatal("the relay went out of rotation with a stream hearing it")
	}
	if n := relayStrikes(relay.addr); n != 0 {
		t.Fatalf("the relay took %d strike(s) with a stream hearing it", n)
	}
}

// A handshake cut short by the phone's own network is excused before the alibi
// is weighed (stream_run_with_creds.go), so it is no flow failure either: two
// of them must not send the relay to the end of the stream's list (Codex
// review of the iOS port, 22.10).
func TestHandshakeFailedWithTheNetworkLeftIsNoFlowFailure(t *testing.T) {
	// First, so that its cleanup runs last — after the goroutine below has
	// stopped moving leftAt.
	resetNetworkSwitch(t)
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(nth int, _ time.Time) bool { return nth == 0 })
	// A worker goes into its wait after the attempt has been judged: its
	// second wait is two handshakes judged.
	var mu sync.Mutex
	waits := map[int]int{}
	prev := workerWaits
	workerWaits = func(w workerWait) {
		mu.Lock()
		waits[w.stream]++
		mu.Unlock()
	}
	t.Cleanup(func() { workerWaits = prev })
	// Every attempt has the network left under it (networkLeftSince), from
	// before the first: the deaf stream's handshakes are the network's.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			networkSwitch.Lock()
			networkSwitch.leftAt = time.Now()
			networkSwitch.Unlock()
			select {
			case <-tick.C:
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	h := runWorkersAgainstPeer(t, 138, 2, []string{relay.addr}, peer)
	waitFor(t, "one stream up and the other's handshake judged twice", 12*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, n := range waits {
			if n >= 2 {
				return h.ready() == 1
			}
		}
		return false
	})
	for _, s := range h.streams {
		if run := s.flowFails.Load(); run != nil {
			t.Fatalf("stream %d counted %d flow failure(s) on %s with the network left under it", s.id, run.n, run.relay)
		}
	}
}

// With nobody on the relay to vouch for it the verdict stands over UDP: a relay
// that allocates and carries nothing is out after its first handshake — by the
// time its worker goes into the wait before its second attempt.
func TestDeafUDPRelayNobodyHearsIsStillDemoted(t *testing.T) {
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)
	peer := choosyPeer(t, func(int, time.Time) bool { return false })
	var waited, demotedThen atomic.Bool
	prev := workerWaits
	workerWaits = func(workerWait) {
		if !waited.Swap(true) {
			demotedThen.Store(serverDemoted(relay.addr))
		}
	}
	t.Cleanup(func() { workerWaits = prev })

	runWorkersAgainstPeer(t, 136, 1, []string{relay.addr}, peer)
	waitFor(t, "the worker's wait after its first attempt", 5*time.Second, waited.Load)
	if !demotedThen.Load() {
		t.Fatal("the relay was still in rotation after its first failed handshake")
	}
}

// startTestRelayOn is startTestRelay with the relayed addresses on ip, so that
// a peer can tell which relay a packet came through.
func startTestRelayOn(t *testing.T, pc net.PacketConn, ip string) *testRelay {
	t.Helper()
	seen := &sourceCounter{PacketConn: pc, seen: map[string]bool{}}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "head-start-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "head-start-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            seen,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP(ip), Address: ip},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return &testRelay{addr: pc.LocalAddr().String(), server: server, seen: seen}
}

// relayPickyPeer echoes the relay proof to the allocations answers lets
// through: from, and how many allocations from its IP — its relay — came
// before it.
func relayPickyPeer(t *testing.T, answers func(from *net.UDPAddr, nthOfRelay int) bool) *net.UDPAddr {
	t.Helper()
	pc := listenFakeRelay(t)
	order := map[string]int{}
	perIP := map[string]int{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			u := from.(*net.UDPAddr)
			key := u.String()
			if _, seen := order[key]; !seen {
				order[key] = perIP[u.IP.String()]
				perIP[u.IP.String()]++
			}
			if isStunKeepalive(buf[:n]) && answers(u, order[key]) {
				pc.WriteTo(buf[:n], from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// A relay that carries its old session and fails every new one, with a healthy
// relay beside it: the stream whose head it is fails there twice under the
// alibi — no verdict against the relay — and then dials it last, and gets
// through on the other one (codex review 2026-10-22: without this it kept
// dialing the failing relay for as long as the old session lived).
func TestAStreamLeavesARelayItKeepsFailingOnWhileOthersHearIt(t *testing.T) {
	first, second := twoRelaySockets(t)
	failing := startTestRelayOn(t, first, "127.0.0.1")
	healthy := startTestRelayOn(t, second, "127.0.0.2")
	peer := relayPickyPeer(t, func(from *net.UDPAddr, nth int) bool {
		return from.IP.String() == "127.0.0.2" || nth == 0
	})

	// Streams 0 and 2 have the failing relay at their head, stream 1 the
	// healthy one: the first of 0 and 2 there takes the one allocation it
	// carries and vouches for it.
	h := runWorkersAgainstPeer(t, 137, 3, []string{failing.addr, healthy.addr}, peer)
	waitFor(t, "all three streams up", 15*time.Second, func() bool { return h.ready() == 3 })
	if failing.seen.count() < 3 {
		t.Fatalf("the failing relay saw %d allocation(s): want stream 2 to have tried it twice", failing.seen.count())
	}
	if serverDemoted(failing.addr) || relayStrikes(failing.addr) != 0 {
		t.Fatal("the relay was held to account with a stream hearing it")
	}
	// Which of streams 0 and 2 took the one allocation the relay carries is a
	// race; whichever failed, its run ended with its own session.
	for _, s := range h.streams {
		if a := s.avoidedRelay(); a != "" {
			t.Fatalf("stream %d still dials %s last: the run of flow failures outlived its own session", s.id, a)
		}
	}
}
