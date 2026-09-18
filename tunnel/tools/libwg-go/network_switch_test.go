/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

const (
	switchNetA = 7001
	switchNetB = 7002
)

func resetNetworkSwitch(t *testing.T) {
	t.Helper()
	reset := func() {
		networkSwitch.Lock()
		networkSwitch.current = 0
		networkSwitch.last = 0
		networkSwitch.attempts = map[uint64]*networkAttempt{}
		networkSwitch.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func cancelled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// The field case: the phone drops Wi-Fi and comes back on a new network. The
// session dialed on the old one is recycled at the moment the new one arrives,
// not while there is none — and one started on the new network is left alone.
func TestMovingToAnotherNetworkRecyclesTheOldSessions(t *testing.T) {
	resetNetworkSwitch(t)
	noteNetworkSwitch(switchNetA)
	onA, endA := beginNetworkAttempt(context.Background())

	noteNetworkSwitch(0)
	if cancelled(onA) {
		t.Fatal("losing the network recycled a session: the same network may come back")
	}
	noteNetworkSwitch(switchNetB)
	if !cancelled(onA) {
		t.Fatal("a session dialed on the old network survived the move to a new one")
	}
	onB, endB := beginNetworkAttempt(context.Background())
	noteNetworkSwitch(switchNetB)

	if cancelled(onB) {
		t.Fatal("a session on the current network was recycled")
	}
	if !endA() {
		t.Fatal("the recycled attempt did not learn that a move ended it")
	}
	if endB() {
		t.Fatal("an attempt ended by its own caller reported a move")
	}
}

// A handover without a gap — Wi-Fi arriving while mobile data stays up — moves
// the sessions too: nothing else would ever take them off the old network.
func TestAHandoverRecyclesWithoutAGap(t *testing.T) {
	resetNetworkSwitch(t)
	noteNetworkSwitch(switchNetA)
	ctx, end := beginNetworkAttempt(context.Background())
	defer end()

	noteNetworkSwitch(switchNetB)
	if !cancelled(ctx) {
		t.Fatal("A → B left the session on A")
	}
}

// The same network coming back, the first network of the process, and the same
// network reported again (Kotlin pushes on every re-addressing) move nothing.
func TestNoMoveNoRecycle(t *testing.T) {
	resetNetworkSwitch(t)
	early, endEarly := beginNetworkAttempt(context.Background()) // before any network
	defer endEarly()
	noteNetworkSwitch(switchNetA)
	if cancelled(early) {
		t.Fatal("the first network of the process recycled a session")
	}

	ctx, end := beginNetworkAttempt(context.Background())
	defer end()
	noteNetworkSwitch(switchNetA)
	noteNetworkSwitch(0)
	noteNetworkSwitch(switchNetA)
	if cancelled(ctx) {
		t.Fatal("the same network reported again, or back after a gap, recycled its session")
	}
}

// An attempt that has ended is out of the registry: a later move cannot reach
// it, and the registry does not grow with every attempt a worker ever made.
func TestEndedAttemptsLeaveTheRegistry(t *testing.T) {
	resetNetworkSwitch(t)
	noteNetworkSwitch(switchNetA)
	_, end := beginNetworkAttempt(context.Background())
	end()

	networkSwitch.Lock()
	left := len(networkSwitch.attempts)
	networkSwitch.Unlock()
	if left != 0 {
		t.Fatalf("%d attempt(s) still registered after ending", left)
	}
}

// What was learned over the old network goes with it — relay health and the
// election, transport proof, cached DNS answers — and only on a move.
func TestAMoveForgetsWhatTheOldNetworkTaught(t *testing.T) {
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	defer resetServerHealth()
	noteNetworkSwitch(switchNetA)

	learn := func() {
		noteServerDemotedAt(healthTestAddr, time.Now())
		markNetworkPathProven(beginNetworkPathGeneration())
		hostCache.mu.Lock()
		hostCache.ips["relay.example"] = "192.0.2.1"
		hostCache.mu.Unlock()
	}
	learned := func() (health, proof, dns bool) {
		serverHealthState.Lock()
		health = len(serverHealthState.byAddr) > 0
		serverHealthState.Unlock()
		_, _, proof, _, _ = networkAvailabilitySnapshot()
		hostCache.mu.Lock()
		_, dns = hostCache.ips["relay.example"]
		hostCache.mu.Unlock()
		return
	}

	learn()
	noteNetworkSwitch(switchNetA)
	if health, proof, dns := learned(); !health || !proof || !dns {
		t.Fatalf("no move, yet forgotten: health=%v proof=%v dns=%v", health, proof, dns)
	}
	noteNetworkSwitch(switchNetB)
	if health, proof, dns := learned(); health || proof || dns {
		t.Fatalf("after the move still known: health=%v proof=%v dns=%v", health, proof, dns)
	}
}

// sourceCounter counts the distinct client sockets a TURN server has heard
// from — one per dial.
type sourceCounter struct {
	net.PacketConn
	mu   sync.Mutex
	seen map[string]bool
}

func (c *sourceCounter) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.mu.Lock()
		c.seen[addr.String()] = true
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *sourceCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func waitFor(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// End to end through runWorker, over a real TURN server and a peer that echoes
// the relay proof: a live session stays put while its network drops and comes
// back, and moves — a new dial, a new session — as soon as another network
// arrives.
func TestWorkerMovesItsSessionToTheNewNetwork(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	defer resetServerHealth()

	pc := &sourceCounter{PacketConn: listenFakeRelay(t), seen: map[string]bool{}}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "switch-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "switch-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	addr := pc.LocalAddr().String()

	prev := globalGetCreds
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", []string{addr}, nil
	}
	defer func() { globalGetCreds = prev }()

	answer := make(chan struct{})
	close(answer)
	peer := fakeRelay(t, answer)
	s, _ := newNoDTLSTestStream(t)

	setBoundNetwork(switchNetA, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorker(ctx, WorkerGroupConfig{GroupID: 93, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: peer}, s, 0)
	}()
	defer func() {
		cancel()
		<-done
	}()

	waitFor(t, "first session ready", 5*time.Second, s.ready.Load)
	if n := pc.count(); n != 1 {
		t.Fatalf("%d dials before any move, want 1", n)
	}

	setBoundNetwork(0, time.Now())
	setBoundNetwork(switchNetA, time.Now())
	time.Sleep(500 * time.Millisecond)
	if n := pc.count(); n != 1 || !s.ready.Load() {
		t.Fatalf("the same network back: %d dials, ready=%v — want the session left alone", n, s.ready.Load())
	}

	// At once: a move is no failure, so no reconnect backoff (0.5s at the least).
	setBoundNetwork(switchNetB, time.Now())
	waitFor(t, "a new dial after the move", 300*time.Millisecond, func() bool { return pc.count() == 2 })
	waitFor(t, "the new session ready", 5*time.Second, s.ready.Load)
}
