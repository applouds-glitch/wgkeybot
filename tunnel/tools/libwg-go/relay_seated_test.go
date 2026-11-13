/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Crowded is not full (orphaned_allocations.go): a crowded extra with a seat
// left for the credential is dialed ahead of the link's own relays.

const seatUser = "1762819200:seat-test"

var seatOwn = []string{moveR42, moveR252}

// seatRig is a link's own pair with the config's extras over it, the books
// clean: the relays an attempt orders, and its config.
func seatRig(t *testing.T, extras ...string) (addrs []string, cfg WorkerGroupConfig) {
	t.Helper()
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	resetAllocationBook(t)
	cfg = WorkerGroupConfig{UseUDP: true, ExtraRelays: extras}
	return withExtraRelays(seatOwn, cfg), cfg
}

// seatDial brings n streams up one after another, each on the head of its
// order, and returns how many came up on each relay.
func seatDial(addrs []string, cfg WorkerGroupConfig, n int, now time.Time) map[string]int {
	on := map[string]int{}
	for id := 0; id < n; id++ {
		head := streamAttemptOrder(seatUser, addrs, id, cfg, now)[0]
		trackAllocation(&countingConn{}, seatUser, head)
		on[head]++
	}
	return on
}

// Two extras carry five streams each — what the bot's script gives a config it
// adds extras to. The network they ran on goes: five ghosts on each, both
// crowded, each with the room the five had. The ten come back on the extras;
// before 2026-11-11 every one of them went to the link's own for the ten
// minutes of the mark. With the quota taken by the count, the next goes to the
// link's own and the extras behind them, as a crowded relay always did.
func TestExtrasCrowdedByOneLostNetworkKeepTheirStreams(t *testing.T) {
	addrs, cfg := seatRig(t, moveR144, moveR179)
	now := time.Now()
	loseOn(seatUser, moveR144, orphanSteerAt, now)
	loseOn(seatUser, moveR179, orphanSteerAt, now)
	later := now.Add(2 * time.Second)

	if on := seatDial(addrs, cfg, 10, later); on[moveR144] != 5 || on[moveR179] != 5 {
		t.Fatalf("streams per relay after the loss: %v, want five back on each extra", on)
	}
	order := streamAttemptOrder(seatUser, addrs, 10, cfg, later)
	if len(order) != 4 || !slices.Contains(seatOwn, order[0]) || !slices.Contains(seatOwn, order[1]) {
		t.Fatalf("with the quota taken on both extras the next stream dials %v, want the link's own first", order)
	}
}

// Three extras, two networks lost within the life of the mark: 8, 6 and 6
// ghosts, as on the field run of 2026-11-07 (relay_return.go), where all ten
// sessions came up on the link's own. The seats left are two, four and four.
func TestExtrasCrowdedByTwoLostNetworksFillTheSeatsLeft(t *testing.T) {
	addrs, cfg := seatRig(t, moveR144, moveR179, moveR190)
	now := time.Now()
	loseOn(seatUser, moveR144, 8, now)
	loseOn(seatUser, moveR179, 6, now)
	loseOn(seatUser, moveR190, 6, now)
	later := now.Add(2 * time.Second)

	if on := seatDial(addrs, cfg, 10, later); on[moveR144] != 2 || on[moveR179] != 4 || on[moveR190] != 4 {
		t.Fatalf("streams per relay after the losses: %v, want 2, 4 and 4 on the extras", on)
	}
	if head := streamAttemptOrder(seatUser, addrs, 10, cfg, later)[0]; !slices.Contains(seatOwn, head) {
		t.Fatalf("with no seat left on any extra the next stream dials %s first, want one of the link's own", head)
	}
}

// An Allocate still running holds its seat: the streams that reconnect together
// see one another before any of them is booked live.
func TestAnAllocateStillRunningTakesTheSeat(t *testing.T) {
	addrs, cfg := seatRig(t, moveR144, moveR179)
	now := time.Now()
	loseOn(seatUser, moveR144, orphanSteerAt, now)
	loseOn(seatUser, moveR179, orphanSteerAt, now)
	later := now.Add(2 * time.Second)

	for i := 0; i < 5; i++ {
		t.Cleanup(noteAllocating(seatUser, moveR144))
	}
	for id := 0; id < 4; id++ {
		if head := streamAttemptOrder(seatUser, addrs, id, cfg, later)[0]; head != moveR179 {
			t.Fatalf("stream %d dials %s first with five ghosts and five Allocates running on %s, want %s", id, head, moveR144, moveR179)
		}
	}
	for i := 0; i < 5; i++ {
		t.Cleanup(noteAllocating(seatUser, moveR179))
	}
	if head := streamAttemptOrder(seatUser, addrs, 0, cfg, later)[0]; !slices.Contains(seatOwn, head) {
		t.Fatalf("with the Allocates running taking every seat the stream dials %s first, want one of the link's own", head)
	}
}

// A seat among the ghosts is second to a relay without them: beside clean
// extras the crowded one waits behind, as it always has, and only the link's
// own wait behind it.
func TestACrowdedExtraWithASeatWaitsBehindTheCleanOnes(t *testing.T) {
	addrs, cfg := seatRig(t, moveR144, moveR179, moveR190)
	now := time.Now()
	loseOn(seatUser, moveR144, orphanSteerAt, now)
	later := now.Add(2 * time.Second)

	for id := 0; id < 6; id++ {
		order := streamAttemptOrder(seatUser, addrs, id, cfg, later)
		if len(order) != 5 || slices.Contains(order[:2], moveR144) || order[2] != moveR144 {
			t.Fatalf("stream %d: %v, want the clean extras, then %s, then the link's own", id, order, moveR144)
		}
	}
}

// One of the link's own that is crowded is not put ahead of an extra, whatever
// the count says of either. A credential read back from disk has ghosts assumed
// on every relay (noteCredsFromEarlierProcess), and a count made of assumed
// ghosts must not take the streams off the extras: with one extra resting, the
// ten come up on the other, as they did before.
func TestALinksOwnCrowdedRelayIsNotPutAheadOfAnExtra(t *testing.T) {
	addrs, cfg := seatRig(t, moveR144, moveR179)
	now := time.Now()
	noteCredsFromEarlierProcess(seatUser, addrs, now)
	noteRelayResting(moveR179, now)

	if on := seatDial(addrs, cfg, 10, now); on[moveR144] != 10 {
		t.Fatalf("streams per relay on a credential from disk: %v, want all ten on the extra in rotation", on)
	}
}

// A session moved off a rested extra takes the seat on the other one, crowded
// as it is, and the next one — the quota taken with the first's pick — goes to
// the link's own; the attempt after the move dials each where the move put it.
func TestAMoveTakesAnExtrasSeatBeforeTheLinksOwn(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	resetAllocationBook(t)
	extras := []string{moveR144, moveR179}
	setExtraRelaysConfigured(extras)
	t.Cleanup(func() { setExtraRelaysConfigured(nil) })
	now := time.Now()
	link := []string{moveR42, moveR144, moveR179}
	s0, _ := movingSessionOn(t, moveR144, link)
	s1, _ := movingSessionOn(t, moveR144, link)
	s0.id, s1.id = 0, 1
	for _, s := range []*stream{s0, s1} {
		u := seatUser
		s.user.Store(&u)
	}
	// .179: five ghosts of the credential and four of its sessions — crowded,
	// and room for one.
	loseOn(seatUser, moveR179, orphanSteerAt, now)
	for i := 0; i < 4; i++ {
		trackAllocation(&countingConn{}, seatUser, moveR179)
		t.Cleanup(trackLiveSession(moveR179, &stream{id: 10 + i}))
	}
	noteRelayResting(moveR144, now)
	out := recycleRelaySessions(context.Background(), moveR144, now, nil)
	if want := []movedHead{{0, moveR179}, {1, moveR42}}; !slices.Equal(out.heads, want) {
		t.Fatalf("heads %v, want %v: the seat on the extra, then the link's own", out.heads, want)
	}
	cfg := WorkerGroupConfig{UseUDP: true, ExtraRelays: extras}
	for i, s := range []*stream{s0, s1} {
		move := s.takeMove(now)
		if move == nil || move.head != out.heads[i].relay {
			t.Fatalf("stream %d carries %+v, want the head %s", s.id, move, out.heads[i].relay)
		}
		if move.full[moveR179] != (i == 1) {
			t.Fatalf("stream %d: the move found %v full, want %s full for the second only", s.id, move.full, moveR179)
		}
		if order := s.attemptOrder(seatUser, link, cfg, now, move); order[0] != move.head {
			t.Fatalf("stream %d: the move picked %s, the attempt dials %v", s.id, move.head, order)
		}
	}
}
