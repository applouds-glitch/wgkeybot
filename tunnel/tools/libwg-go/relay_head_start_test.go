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

// testRelay is a TURN server for the race tests; seen counts the client
// sockets that have reached it (one per dial).
type testRelay struct {
	addr   string
	server *turn.Server // nil for a silent relay
	seen   *sourceCounter
}

func startTestRelay(t *testing.T, pc net.PacketConn, replyDelay time.Duration) *testRelay {
	t.Helper()
	seen := &sourceCounter{PacketConn: pc, seen: map[string]bool{}}
	var conn net.PacketConn = seen
	if replyDelay > 0 {
		conn = &delayedAllocateReplies{PacketConn: seen, delay: replyDelay}
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "head-start-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "head-start-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return &testRelay{addr: pc.LocalAddr().String(), server: server, seen: seen}
}

// twoRelaySockets returns two listening sockets in the order the session would
// dial their addresses (assignServers sorts the list), so a test can decide
// what stands first.
func twoRelaySockets(t *testing.T) (first, second net.PacketConn) {
	t.Helper()
	a, b := listenFakeRelay(t), listenFakeRelay(t)
	if assignServers([]string{a.LocalAddr().String(), b.LocalAddr().String()})[0] == a.LocalAddr().String() {
		return a, b
	}
	return b, a
}

type raceHarness struct {
	streams []*stream
	cancel  context.CancelFunc
	done    *sync.WaitGroup
}

// runWorkersAgainst runs n workers over addrs, with a peer that echoes the
// relay proof, until the test ends.
func runWorkersAgainst(t *testing.T, group int, n int, addrs []string) *raceHarness {
	t.Helper()
	answer := make(chan struct{})
	close(answer)
	return runWorkersAgainstPeer(t, group, n, addrs, fakeRelay(t, answer))
}

// runWorkersAgainstPeer is runWorkersAgainst with a peer of the test's own.
func runWorkersAgainstPeer(t *testing.T, group int, n int, addrs []string, peer *net.UDPAddr) *raceHarness {
	t.Helper()
	return runWorkersOfType(t, group, n, addrs, peer, "wireguard")
}

// runWorkersOfType is runWorkersAgainstPeer over the transport of the test's
// choice; the peer has to speak it.
func runWorkersOfType(t *testing.T, group int, n int, addrs []string, peer *net.UDPAddr, peerType string) *raceHarness {
	t.Helper()
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	resetRelayConnectPacing()
	t.Cleanup(resetRelayConnectPacing)

	prev := globalGetCreds
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", addrs, nil
	}
	t.Cleanup(func() { globalGetCreds = prev })

	ctx, cancel := context.WithCancel(context.Background())
	h := &raceHarness{cancel: cancel, done: &sync.WaitGroup{}}
	for i := 0; i < n; i++ {
		s, _ := newNoDTLSTestStream(t)
		s.id = i
		h.streams = append(h.streams, s)
		h.done.Add(1)
		go func() {
			defer h.done.Done()
			runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: true, PeerType: peerType, PeerAddr: peer}, s, 0)
		}()
	}
	t.Cleanup(func() {
		cancel()
		h.done.Wait()
	})
	return h
}

func (h *raceHarness) ready() int {
	n := 0
	for _, s := range h.streams {
		if s.ready.Load() {
			n++
		}
	}
	return n
}

// The field case: the session's relay has gone silent. Allocate there does not
// fail for ~7.8s, and until it did nothing else was dialed. Now the second
// relay is raced once the head start runs out, and the stream is up on it in
// about a second and a half. The silent relay's timeout — which arrives long
// after the race was won — still counts against it.
func TestSilentFirstRelayIsRacedAfterTheHeadStart(t *testing.T) {
	first, second := twoRelaySockets(t) // first: accepts datagrams, never answers
	live := startTestRelay(t, second, 0)
	silent := first.LocalAddr().String()

	started := time.Now()
	h := runWorkersAgainst(t, 101, 1, []string{silent, live.addr})

	waitFor(t, "a stream on the answering relay", relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if took := time.Since(started); took < relayHeadStart {
		t.Fatalf("up after %v: the second relay was dialed before the head start ran out", took)
	}
	if got := h.streams[0].serverAddr; got != live.addr {
		t.Fatalf("session runs on %s, want the answering relay %s", got, live.addr)
	}

	// pion gives up on the silent relay ~7.8s after the dial.
	waitFor(t, "the silent relay's strike", 10*time.Second, func() bool {
		serverHealthState.Lock()
		defer serverHealthState.Unlock()
		entry := serverHealthState.byAddr[silent]
		return entry != nil && entry.failures > 0
	})
}

// A healthy first relay wins alone: the second one must not even be dialed, or
// every ordinary connect would leave a surplus allocation there and scatter the
// session's streams across relays.
func TestHealthyFirstRelayIsNotRaced(t *testing.T) {
	first, second := twoRelaySockets(t)
	a := startTestRelay(t, first, 0)
	b := startTestRelay(t, second, 0)

	h := runWorkersAgainst(t, 102, 1, []string{a.addr, b.addr})
	waitFor(t, "a stream on the first relay", 3*time.Second, func() bool { return h.ready() == 1 })
	time.Sleep(relayHeadStart + 300*time.Millisecond)

	if n := b.seen.count(); n != 0 {
		t.Fatalf("the second relay was dialed %d time(s) although the first answered at once", n)
	}
	if got := h.streams[0].serverAddr; got != a.addr {
		t.Fatalf("session runs on %s, want the first relay %s", got, a.addr)
	}
}

// A first relay that is merely slow loses the race but does answer: the
// allocation it made for us must be released, not left as a ghost eating the
// credential's quota there.
func TestSlowFirstRelayLosesAndItsAllocationIsReleased(t *testing.T) {
	first, second := twoRelaySockets(t)
	// Two delayed replies (challenge, then success): Allocate takes ~1.8s.
	slow := startTestRelay(t, first, 900*time.Millisecond)
	fast := startTestRelay(t, second, 0)

	h := runWorkersAgainst(t, 103, 1, []string{slow.addr, fast.addr})
	waitFor(t, "a stream on the fast relay", relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != fast.addr {
		t.Fatalf("session runs on %s, want the fast relay %s", got, fast.addr)
	}

	waitFor(t, "the slow relay to allocate for the loser", 3*time.Second, func() bool { return slow.seen.count() == 1 })
	waitFor(t, "the loser's allocation to be released", 4*time.Second, func() bool { return slow.server.AllocationCount() == 0 })
	if n := fast.server.AllocationCount(); n != 1 {
		t.Fatalf("the winning relay holds %d allocations, want 1", n)
	}
}

// A silent relay keeps each Allocate hanging for 7.8s. The slot it holds is
// given up when the head start runs out, so the workers queued behind it start
// their own clocks instead of waiting out the whole timeout: with three slots,
// the fourth worker is up in two head starts, not in eight seconds.
func TestHangingAllocateGivesUpItsSlotAtTheHeadStart(t *testing.T) {
	first, second := twoRelaySockets(t)
	live := startTestRelay(t, second, 0)

	workers := allocSlotsPerRelay + 1
	h := runWorkersAgainst(t, 104, workers, []string{first.LocalAddr().String(), live.addr})
	waitFor(t, "every worker on the answering relay", 2*relayHeadStart+3*time.Second, func() bool { return h.ready() == workers })
}

func TestAllocSlotIsReleasedOnce(t *testing.T) {
	const addr = "192.0.2.77:3478"
	slot := acquireAllocSlot(context.Background(), addr)
	other := acquireAllocSlot(context.Background(), addr)
	slot.release()
	slot.release()
	if n := len(allocSlotsFor(addr)); n != 1 {
		t.Fatalf("%d slots held after a double release of one of two, want 1", n)
	}
	other.release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < allocSlotsPerRelay; i++ {
		defer acquireAllocSlot(context.Background(), addr).release()
	}
	if acquireAllocSlot(ctx, addr) != nil {
		t.Fatal("a cancelled wait on a full relay returned a slot")
	}
}

// After a network return every worker dials at once and queues for the relay's
// Allocate slots. Waiting in that queue is not the relay's silence: a healthy
// relay that answers each Allocate inside the head start must win them all, and
// the second relay must never be dialed.
func TestQueueingForAHealthyRelayIsNotSilence(t *testing.T) {
	first, second := twoRelaySockets(t)
	// ~0.8s per Allocate: two waves of three already outlast the head start.
	a := startTestRelay(t, first, 400*time.Millisecond)
	b := startTestRelay(t, second, 0)

	workers := 2 * allocSlotsPerRelay
	h := runWorkersAgainst(t, 105, workers, []string{a.addr, b.addr})
	waitFor(t, "every worker on the first relay", 6*time.Second, func() bool { return h.ready() == workers })
	if n := b.seen.count(); n != 0 {
		t.Fatalf("the second relay was dialed %d time(s) by workers that were only queueing", n)
	}
}

// Allocate slots are per relay: dials to the answering relay never queue behind
// Allocates hanging on the dark one. With one shared pool the first stream came
// up only after every queued worker had had its turn on the dark relay.
func TestDarkRelayDoesNotHoldUpDialsToTheOther(t *testing.T) {
	first, second := twoRelaySockets(t)
	live := startTestRelay(t, second, 0)

	workers := 3*allocSlotsPerRelay + 1
	h := runWorkersAgainst(t, 106, workers, []string{first.LocalAddr().String(), live.addr})
	waitFor(t, "the first stream on the answering relay", 2*relayHeadStart, func() bool { return h.ready() > 0 })
}
