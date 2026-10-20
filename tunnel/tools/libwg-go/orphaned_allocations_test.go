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
		allocationBook.tracked = map[*trackedRelay]bool{}
		allocationBook.orphanedTill = map[relayIdentity]time.Time{}
		allocationBook.orphans = map[relayIdentity]int{}
		allocationBook.announced = map[relayIdentity]bool{}
		allocationBook.releasedAt = map[relayIdentity]time.Time{}
		allocationBook.succeeded = map[string]bool{}
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

// ghosts is how many of user's ghosts the mark in force at now counts on relay.
func ghosts(user, relay string, now time.Time) int {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	key := relayIdentity{user: user, relay: relay}
	if till, ok := allocationBook.orphanedTill[key]; !ok || !now.Before(till) {
		return 0
	}
	return allocationBook.orphans[key]
}

// orphanOrder is addrs with the relays crowded with user's ghosts put last.
func orphanOrder(user string, addrs []string, now time.Time) []string {
	return behindCrowded(addrs, crowdedRelays(user, addrs, now))
}

// behindCrowded moves the crowded relays of order to its end, keeping the order
// within both parts; if all or none are crowded, nowhere is better to go and the
// order stands. It returns a new slice.
func behindCrowded(order []string, crowded map[string]bool) []string {
	var clean, full []string
	for _, addr := range order {
		if crowded[addr] {
			full = append(full, addr)
		} else {
			clean = append(clean, addr)
		}
	}
	if len(clean) == 0 || len(full) == 0 {
		return append([]string(nil), order...)
	}
	return append(clean, full...)
}

// loseOn tracks n live allocations of user's on relay and leaves the network
// they are bound to: n ghosts there.
func loseOn(user, relay string, n int, now time.Time) {
	noteBoundNetwork(orphanNetA, now)
	for i := 0; i < n; i++ {
		trackAllocation(&countingConn{}, user, relay)
	}
	noteBoundNetwork(0, now)
}

// The network drops under two allocations on relay 1: two ghosts there. One on
// relay 2 closed while the network was alive is none — VK released that one.
// Two ghosts leave room under the quota, so the order stands.
func TestLosingTheNetworkOrphansOnlyLiveAllocations(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)

	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()

	noteBoundNetwork(0, now)

	later := now.Add(time.Second)
	if n1, n2 := ghosts("alice", orphanRelay1, later), ghosts("alice", orphanRelay2, later); n1 != 2 || n2 != 0 {
		t.Fatalf("ghosts after the loss: %d on relay 1, %d on relay 2; want 2 and 0", n1, n2)
	}
	if got := orphanOrder("alice", orphanRelays, later); !slices.Equal(got, orphanRelays) {
		t.Fatalf("two ghosts steered: %v", got)
	}
}

// The device case of 2026-09-18: a session's streams all on relay 1, the
// network drops, and the reconnect on the same credential must go to the relays
// that are not full of our ghosts.
func TestARelayCrowdedWithGhostsGoesLast(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	got := orphanOrder("alice", orphanRelays, now.Add(time.Second))
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

	if n := ghosts("alice", orphanRelay1, now); n != 1 {
		t.Fatalf("A → B left %d ghost(s) on relay 1, want 1", n)
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

	if n := ghosts("alice", orphanRelay1, now); n != 0 {
		t.Fatalf("no network was left, yet %d ghost(s) were counted", n)
	}
}

// The mark is the allocation lifetime, counted from the loss: still in force a
// second before it ends, gone at the end.
func TestOrphanMarkLastsTheAllocationLifetime(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	if got := orphanOrder("alice", orphanRelays, now.Add(orphanedAllocationLifetime-time.Second)); got[0] == orphanRelay1 {
		t.Fatalf("a second before the lifetime ends: %v, relay 1 still full", got)
	}
	if got := orphanOrder("alice", orphanRelays, now.Add(orphanedAllocationLifetime)); !slices.Equal(got, orphanRelays) {
		t.Fatalf("at the end of the lifetime: %v, want the plain order back", got)
	}
}

// The quota is per credential: another credential still goes to relay 1 first.
func TestOrphanMarkIsPerCredential(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	if got := orphanOrder("alice", orphanRelays, now); got[0] == orphanRelay1 {
		t.Fatalf("alice was not steered: %v", got)
	}
	if got := orphanOrder("bob", orphanRelays, now); !slices.Equal(got, orphanRelays) {
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
		for i := 0; i < orphanSteerAt; i++ {
			trackAllocation(&countingConn{}, "alice", r)
		}
	}
	noteBoundNetwork(0, now)

	in := slices.Clone(orphanRelays)
	got := orphanOrder("alice", in, now)
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
	loseOn("alice", orphanRelay1, orphanSteerAt, now)

	in := slices.Clone(orphanRelays)
	if got := orphanOrder("alice", in, now); got[0] == orphanRelay1 {
		t.Fatalf("relay 1 was not steered: %v", got)
	}
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
	if n := ghosts("alice", orphanRelay1, now); n != 1 {
		t.Fatalf("%d ghost(s) after the loss, want the one remaining live allocation", n)
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

	if n1, n2 := ghosts("alice", orphanRelay1, now), ghosts("alice", orphanRelay2, now); n1 != 1 || n2 != 0 {
		t.Fatalf("after a failed release on relay 1 and a sent one on relay 2: %d and %d ghost(s), want 1 and 0", n1, n2)
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
	if n := ghosts("alice", orphanRelay1, time.Now()); n != 0 {
		t.Fatalf("a released allocation was counted a ghost by a later close: %d", n)
	}
}

// A mark lasts from the newest orphan: a second failed release later on adds a
// ghost and extends it, both ghosts expiring with the later one.
func TestALaterOrphanExtendsTheMark(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1).Close()
	later := now.Add(5 * time.Minute)
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, errReleaseUnsent, later, nil)

	if n := ghosts("alice", orphanRelay1, now.Add(orphanedAllocationLifetime+time.Minute)); n != 2 {
		t.Fatalf("%d ghost(s) after the first one's lifetime, want both, the mark extended", n)
	}
	if n := ghosts("alice", orphanRelay1, later.Add(orphanedAllocationLifetime)); n != 0 {
		t.Fatalf("%d ghost(s) after the later one's lifetime, want none", n)
	}
}

// streamAttemptOrder is what both the attempt and the "did the head move"
// check in attemptOnce use, so it has to apply the marks on top of the
// stream's own order: a few ghosts keep the stream's own relay, a crowd of
// them moves it last.
func TestStreamAttemptOrderAppliesTheMarks(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	resetServerHealth()
	now := time.Now()
	head := assignRelays(orphanRelays, 0, now)[0]
	loseOn("alice", head, orphanSteerAt-1, now)

	if got := streamAttemptOrder("alice", orphanRelays, 0, WorkerGroupConfig{UseUDP: true}, now); got[0] != head {
		t.Fatalf("streamAttemptOrder = %v with %d ghosts on %s, want it kept first", got, orphanSteerAt-1, head)
	}
	loseOn("alice", head, 1, now)
	got := streamAttemptOrder("alice", orphanRelays, 0, WorkerGroupConfig{UseUDP: true}, now)
	if got[0] == head || got[len(got)-1] != head {
		t.Fatalf("streamAttemptOrder = %v with %d ghosts on %s, want it moved last", got, orphanSteerAt, head)
	}
}

// Field runs 18.10: after a dark, a few ghosts on most relays sent every stream
// to the one relay left without any. The streams are spread over the relays
// that are not crowded — rotated among them, not before the crowded ones are
// put last, which would hand each crowded relay's streams to the next one.
func TestCrowdedRelaysAreSteeredAroundAndTheRestSpread(t *testing.T) {
	resetAllocationBook(t)
	defer resetServerHealth()
	resetServerHealth()
	now := time.Now()
	a, b, c, d, e, f := "10.0.1.1:3478", "10.0.1.2:3478", "10.0.1.3:3478", "10.0.1.4:3478", "10.0.1.5:3478", "10.0.1.6:3478"
	addrs := []string{a, b, c, d, e, f}
	for _, r := range []string{b, c, d} {
		loseOn("alice", r, orphanSteerAt, now)
	}
	loseOn("alice", e, 4, now) // as many as one relay held in those runs: still one to spread over

	var heads []string
	for id := 0; id < 8; id++ {
		got := streamAttemptOrder("alice", addrs, id, WorkerGroupConfig{UseUDP: true}, now)
		heads = append(heads, got[0])
		if tail := got[3:]; !slices.Contains(tail, b) || !slices.Contains(tail, c) || !slices.Contains(tail, d) {
			t.Fatalf("stream %d: %v, want the crowded relays behind the rest", id, got)
		}
	}
	if want := []string{a, e, f, a, e, f, a, e}; !slices.Equal(heads, want) {
		t.Fatalf("heads %v, want %v", heads, want)
	}
}

// One allocation is one ghost, whichever of its triggers speak for it: the
// network it was bound to left (twice over), its release failed, and its relay
// no longer knew it. Two allocations lost in two outages are two.
func TestEachAllocationIsCountedOnceAsAGhost(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	r := trackAllocation(&countingConn{errs: []error{errReleaseUnsent}}, "alice", orphanRelay1)
	noteBoundNetwork(0, now)
	noteBoundNetwork(orphanNetB, now)
	noteBoundNetwork(0, now)
	r.Close()
	noteOutOfReach("alice", orphanRelay1, trackedAllocation(r), now)
	if n := ghosts("alice", orphanRelay1, now); n != 1 {
		t.Fatalf("one allocation counted as %d ghosts", n)
	}

	noteBoundNetwork(orphanNetA, now.Add(time.Minute))
	trackAllocation(&countingConn{}, "alice", orphanRelay1)
	noteBoundNetwork(0, now.Add(time.Minute))
	if n := ghosts("alice", orphanRelay1, now.Add(time.Minute)); n != 2 {
		t.Fatalf("two allocations lost in two outages counted as %d ghosts", n)
	}
}

// A session's network leaves, comes back with the session alive
// (network_switch.go keeps it), and leaves again: the ghost is held from the
// later loss, not dropped when the first one's mark runs out — and lost once
// more after that mark ran out too, it counts under the new one (Codex review,
// 18.10).
func TestAnAllocationLostAgainIsHeldFromTheLaterLoss(t *testing.T) {
	resetAllocationBook(t)
	t0 := time.Now()
	noteBoundNetwork(orphanNetA, t0)
	r := trackAllocation(&countingConn{}, "alice", orphanRelay1)
	noteBoundNetwork(0, t0)
	noteBoundNetwork(orphanNetA, t0.Add(20*time.Second))
	noteBoundNetwork(0, t0.Add(500*time.Second))
	if n := ghosts("alice", orphanRelay1, t0.Add(600*time.Second)); n != 1 {
		t.Fatalf("%d ghost(s) when the first loss's mark ran out, want the one, held from the second", n)
	}

	noteBoundNetwork(orphanNetA, t0.Add(520*time.Second))
	noteBoundNetwork(0, t0.Add(1200*time.Second))
	if n := ghosts("alice", orphanRelay1, t0.Add(1201*time.Second)); n != 1 {
		t.Fatalf("lost under a new mark: %d ghost(s), want it counted again", n)
	}
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, errReleaseUnsent, t0.Add(1210*time.Second), trackedAllocation(r))
	if n := ghosts("alice", orphanRelay1, t0.Add(1211*time.Second)); n != 1 {
		t.Fatalf("its failed release after that: %d ghost(s), want still one", n)
	}
}

// Under the close budget over TCP the allocation is still found, so its out of
// reach report is told from its failed release.
func TestTrackedAllocationIsFoundUnderTheCloseBudget(t *testing.T) {
	resetAllocationBook(t)
	r := trackAllocation(&countingConn{}, "alice", orphanRelay1)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := trackedAllocation(boundRelayClose(r, a)); got != r {
		t.Fatalf("trackedAllocation = %v, want the allocation beneath the close budget", got)
	}
	if got := trackedAllocation(&countingConn{}); got != nil {
		t.Fatalf("trackedAllocation of an untracked conn = %v, want nil", got)
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
	if n := ghosts("carol", addr, time.Now()); n != 0 {
		t.Fatalf("a release sent to a live relay counted %d ghost(s)", n)
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
	if n := ghosts("dave", addr, time.Now()); n != 1 {
		t.Fatalf("an unsent release counted %d ghost(s), want 1", n)
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
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, t0, nil)

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
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, now, nil)

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
	releaseAllocation(relayIdentity{user: "alice", relay: orphanRelay1}, nil, now, nil)

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
	releaseAllocation(relayIdentity{user: t.Name(), relay: addr}, nil, time.Now(), nil)

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
