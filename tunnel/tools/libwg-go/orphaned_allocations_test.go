/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

const (
	orphanNetA   = 101
	orphanNetB   = 202
	orphanRelay1 = "10.0.0.1:3478"
	orphanRelay2 = "10.0.0.2:3478"
	orphanRelay3 = "10.0.0.3:3478"
)

var orphanRelays = []string{orphanRelay1, orphanRelay2, orphanRelay3}

func resetAllocationBook(t *testing.T) {
	t.Helper()
	reset := func() {
		allocationBook.Lock()
		allocationBook.boundNetwork = 0
		allocationBook.live = map[relayIdentity]int{}
		allocationBook.orphanedTill = map[relayIdentity]time.Time{}
		allocationBook.announced = map[relayIdentity]bool{}
		allocationBook.releasedAt = map[relayIdentity]time.Time{}
		allocationBook.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// countingConn stands in for a pion relay conn: only Close is ever called. Its
// Nth Close returns errs[N], nil past the end — pion returns the Refresh(0)
// write error from the first close and "already closed" from later ones.
type countingConn struct {
	net.PacketConn
	closes atomic.Int32
	errs   []error
}

func (c *countingConn) Close() error {
	n := int(c.closes.Add(1)) - 1
	if n < len(c.errs) {
		return c.errs[n]
	}
	return nil
}

var errReleaseUnsent = errors.New("write: network is unreachable")

func liveAllocations(user, relay string) int {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	return allocationBook.live[relayIdentity{user: user, relay: relay}]
}

// The device case: a session on relay 1, the network drops, the reconnect on
// the same credential must go to the relays that are not full of our ghosts.
// A relay whose allocation was closed while the network was alive is not
// marked — VK released that one.
func TestLosingTheNetworkOrphansOnlyLiveAllocations(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)

	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()

	noteBoundNetwork(0, now)

	got := orderAroundOrphans("alice", orphanRelays, now.Add(time.Second))
	if want := []string{orphanRelay2, orphanRelay3, orphanRelay1}; !slices.Equal(got, want) {
		t.Fatalf("after the loss: %v, want %v", got, want)
	}
}

// A handover (A → B without a gap) orphans A's allocations just like a loss:
// their sockets are bound to A.
func TestHandingOverToAnotherNetworkOrphans(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)

	noteBoundNetwork(orphanNetB, now)

	if got := orderAroundOrphans("alice", orphanRelays, now); got[0] == orphanRelay1 {
		t.Fatalf("A → B left relay 1 first: %v", got)
	}
}

// Arriving on a network from none, and hearing about the same network again
// (Kotlin pushes on every re-addressing), release nothing and mark nothing.
func TestArrivingOrReaddressingOrphansNothing(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{}, "alice", orphanRelay1)

	noteBoundNetwork(orphanNetA, now) // from none
	noteBoundNetwork(orphanNetA, now) // the same network again

	if got := orderAroundOrphans("alice", orphanRelays, now); !slices.Equal(got, orphanRelays) {
		t.Fatalf("no network was left, yet the order changed: %v", got)
	}
}

// The mark is the allocation lifetime, counted from the loss: still in force a
// second before it ends, gone at the end.
func TestOrphanMarkLastsTheAllocationLifetime(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	noteBoundNetwork(0, now)

	if got := orderAroundOrphans("alice", orphanRelays, now.Add(orphanedAllocationLifetime-time.Second)); got[0] == orphanRelay1 {
		t.Fatalf("a second before the lifetime ends: %v, relay 1 still full", got)
	}
	if got := orderAroundOrphans("alice", orphanRelays, now.Add(orphanedAllocationLifetime)); !slices.Equal(got, orphanRelays) {
		t.Fatalf("at the end of the lifetime: %v, want the plain order back", got)
	}
}

// The quota is per credential: another credential still goes to relay 1 first.
func TestOrphanMarkIsPerCredential(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	noteBoundNetwork(0, now)

	if got := orderAroundOrphans("bob", orphanRelays, now); !slices.Equal(got, orphanRelays) {
		t.Fatalf("another credential was steered: %v", got)
	}
}

// When every relay is marked there is nowhere better to go; the order stands
// instead of being shuffled by the marks. The input is never modified.
func TestOrphanOrderWithEveryRelayMarked(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	for _, r := range orphanRelays {
		trackAllocation(&countingConn{}, "alice", r)
	}
	noteBoundNetwork(0, now)

	in := slices.Clone(orphanRelays)
	got := orderAroundOrphans("alice", in, now)
	if !slices.Equal(got, orphanRelays) {
		t.Fatalf("all marked: %v, want the order unchanged", got)
	}
	got[0] = "mutated"
	if !slices.Equal(in, orphanRelays) {
		t.Fatal("the caller's slice was shared with the result")
	}
}

func TestOrphanOrderDoesNotModifyItsInput(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	noteBoundNetwork(0, now)

	in := slices.Clone(orphanRelays)
	orderAroundOrphans("alice", in, now)
	if !slices.Equal(in, orphanRelays) {
		t.Fatalf("input reordered in place: %v", in)
	}
}

// A relay conn is closed from several places; only the first close releases
// the count, so a double close cannot hide another live allocation on the pair.
func TestTrackedRelayReleasesOnce(t *testing.T) {
	resetAllocationBook(t)
	inner := &countingConn{}
	first := trackAllocation(inner, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)

	first.Close()
	first.Close()
	if n := liveAllocations("alice", orphanRelay1); n != 1 {
		t.Fatalf("live after a double close of one of two: %d, want 1", n)
	}
	if inner.closes.Load() != 2 {
		t.Fatalf("inner conn closed %d times, want every Close passed through", inner.closes.Load())
	}

	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	noteBoundNetwork(0, now)
	if got := orderAroundOrphans("alice", orphanRelays, now); got[0] == orphanRelay1 {
		t.Fatalf("the remaining live allocation was not marked: %v", got)
	}
}

// The field order of events: the kernel refuses a write, the session ends and
// closes its relay — the release fails to go out too — and only then does
// Android report the loss. Nothing is live by then, so the network trigger
// sees nothing; the failed release must have marked the pair on its own.
func TestAReleaseThatDidNotGoOutOrphans(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1).Close()
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()
	noteBoundNetwork(0, now)

	got := orderAroundOrphans("alice", orphanRelays, now)
	if want := []string{orphanRelay2, orphanRelay3, orphanRelay1}; !slices.Equal(got, want) {
		t.Fatalf("after a failed release on relay 1 and a sent one on relay 2: %v, want %v", got, want)
	}
}

// Only the close that sent the release speaks for it: the "already closed"
// error of a later close says nothing about the relay.
func TestOnlyTheFirstCloseSpeaksForTheRelease(t *testing.T) {
	resetAllocationBook(t)
	r := trackAllocation(&countingConn{errs: []error{nil, errReleaseUnsent}}, "alice", orphanRelay1)
	r.Close()
	if err := r.Close(); err == nil {
		t.Fatal("the second close hid the inner conn's answer")
	}
	if got := orderAroundOrphans("alice", orphanRelays, time.Now()); !slices.Equal(got, orphanRelays) {
		t.Fatalf("a released allocation was marked by a later close: %v", got)
	}
}

// A mark lasts from the newest orphan: a second failed release later on
// extends it.
func TestALaterOrphanExtendsTheMark(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1).Close()
	later := now.Add(5 * time.Minute)
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, errReleaseUnsent, later)

	if got := orderAroundOrphans("alice", orphanRelays, now.Add(orphanedAllocationLifetime+time.Minute)); got[0] == orphanRelay1 {
		t.Fatalf("the first orphan's expiry ended a mark the later one extended: %v", got)
	}
}

// attemptOrder is what both the attempt and the "did the head move" check in
// runWorker use, so it has to apply the marks on top of the session's order.
func TestAttemptOrderAppliesTheMarks(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	resetServerHealth()
	now := time.Now()
	head := assignServers(orphanRelays)[0]
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", head)
	noteBoundNetwork(0, now)

	if got := attemptOrder("alice", orphanRelays, now); got[0] == head || got[len(got)-1] != head {
		t.Fatalf("attemptOrder = %v, want %s moved last", got, head)
	}
}

// End to end through the real allocation path: a successful Allocate is
// counted until its relay conn is closed.
func TestDialAndAllocateCountsTheAllocation(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	pc := listenFakeRelay(t)
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "orphan-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "orphan-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addr := pc.LocalAddr().String()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, "carol", "pass", addr, WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	defer client.Close()
	if n := liveAllocations("carol", addr); n != 1 {
		t.Fatalf("live after Allocate: %d, want 1", n)
	}
	relay.Close()
	if n := liveAllocations("carol", addr); n != 0 {
		t.Fatalf("live after closing the relay: %d, want 0", n)
	}
	if got := orderAroundOrphans("carol", []string{addr, orphanRelay1}, time.Now()); got[0] != addr {
		t.Fatalf("a release sent to a live relay marked it: %v", got)
	}
}

// The real pion path of an unsent release: the socket under the client is gone
// when the relay closes, so Refresh(0) cannot be written and Close says so.
func TestDialAndAllocateMarksAnUnsentRelease(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	pc := listenFakeRelay(t)
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "orphan-test",
		AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
			return a.Username, turn.GenerateAuthKey(a.Username, "orphan-test", "pass"), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addr := pc.LocalAddr().String()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, "dave", "pass", addr, WorkerGroupConfig{UseUDP: true}, dialOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw.Close()
	if relay.Close() == nil {
		t.Fatal("pion reported a release written to a closed socket as sent")
	}
	if got := orderAroundOrphans("dave", []string{addr, orphanRelay1}, time.Now()); got[0] == addr {
		t.Fatalf("an unsent release left the relay first: %v", got)
	}
}

// A 486 the way runWithCreds reports it after both relays refused.
func quota486() error {
	return allocateErr(turnErr(stun.CodeAllocQuotaReached))
}

// The device case: the Kotlin restart released ten allocations on relay 2 over
// a live network and dialed it again 0.6s later. Relay 1 still holds the ghosts
// of the drop before. The 486 is our own release still being processed, so the
// credential must be kept.
func TestA486RightAfterOurReleaseKeepsTheCreds(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	noteBoundNetwork(0, now)
	noteBoundNetwork(orphanNetB, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()

	attempt := []string{orphanRelay2, orphanRelay1}
	relay, age, ok := settlingQuotaError(quota486(), "alice", attempt, time.Now().Add(600*time.Millisecond))
	if !ok || relay != orphanRelay2 {
		t.Fatalf("486 0.6s after our release on relay 2: relay=%q ok=%v, want relay 2", relay, ok)
	}
	if age < 600*time.Millisecond || age >= releaseSettleWindow {
		t.Fatalf("release age %v, want about 0.6s", age)
	}
}

// Past the window a 486 is a 486 again: rotate the credential as always.
func TestReleaseSettleWindowEnds(t *testing.T) {
	resetAllocationBook(t)
	t0 := time.Now()
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, t0)

	if _, _, ok := settlingQuotaError(quota486(), "alice", orphanRelays, t0.Add(releaseSettleWindow-time.Millisecond)); !ok {
		t.Fatal("a 486 just inside the window was not read as our release settling")
	}
	if _, _, ok := settlingQuotaError(quota486(), "alice", orphanRelays, t0.Add(releaseSettleWindow)); ok {
		t.Fatal("a 486 at the end of the window still kept the credential")
	}
}

// Only a quota refusal is explained by an unprocessed release: a 401, a
// transport failure or no error at all take their usual paths.
func TestOnlyAQuotaRefusalSettles(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, now)

	for _, err := range []error{
		nil,
		allocateErr(turnErr(stun.CodeUnauthorized)),
		allocateErr(writeErr(50486, syscall.ENETUNREACH)),
	} {
		if _, _, ok := settlingQuotaError(err, "alice", orphanRelays, now); ok {
			t.Errorf("%v was read as our release settling", err)
		}
	}
}

// A relay holding our orphans answers 486 because of them, and they last ten
// minutes, not seconds: a release there does not make its 486 worth waiting for.
// A release that did not go out is no release at all.
func TestAnOrphanedRelayDoesNotSettle(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay1).Close() // released, live network
	trackAllocation(&countingConn{}, "alice", orphanRelay1)         // then lost with it
	noteBoundNetwork(0, now)
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay2).Close()

	if relay, _, ok := settlingQuotaError(quota486(), "alice", orphanRelays, time.Now()); ok {
		t.Fatalf("486 read as settling on %s, which holds our orphans", relay)
	}
}

// The release is ours on one credential and one relay: another credential's
// 486, or an attempt that never dialed that relay, is not explained by it.
func TestSettlingIsPerCredentialAndRelay(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, now)

	if _, _, ok := settlingQuotaError(quota486(), "bob", orphanRelays, now); ok {
		t.Fatal("another credential's 486 was read as alice's release settling")
	}
	if _, _, ok := settlingQuotaError(quota486(), "alice", []string{orphanRelay2, orphanRelay3}, now); ok {
		t.Fatal("an attempt that never dialed relay 1 was explained by a release there")
	}
}

// The same through runWorker itself: a relay refusing every Allocate with 486
// right after our release there gets the same credential again within seconds,
// and the credential is never rotated (the path that fetched a new one from VK).
func TestWorkerRetriesTheSameCredsWhileOurReleaseSettles(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	pc, _ := startInitialRefusalServer(t, 100, stun.CodeAllocQuotaReached)
	addr := pc.LocalAddr().String()

	prev := globalGetCreds
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", []string{addr}, nil
	}
	defer func() { globalGetCreds = prev }()

	const group = 91
	cacheID := group * streamsPerCredValue()
	cache := getStreamCache(cacheID)
	defer func() {
		credentialsStore.mu.Lock()
		delete(credentialsStore.caches, cacheID)
		credentialsStore.mu.Unlock()
	}()
	releaseAllocation(relayIdentity{user: t.Name(), relay: addr}, nil, time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: true, PeerType: "wireguard"}, &stream{}, 0)

	cache.refreshMu.Lock()
	rotated := !cache.lastRefresh.IsZero()
	cache.refreshMu.Unlock()
	if rotated {
		t.Fatal("a 486 right after our own release rotated the credential")
	}
	if n := pc.count(); n < 2 {
		t.Fatalf("%d Allocate attempt(s) in 3.5s, want the same credential tried again", n)
	}
}
