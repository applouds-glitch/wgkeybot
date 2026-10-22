/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"
)

// The relays of the bench of 2026-10-22 (relay_move.go), in canonical order.
const (
	moveR21  = "193.203.43.21:19302"
	moveR42  = "193.203.43.42:19302"
	moveR252 = "90.156.234.252:19302"
	moveR92  = "90.156.236.92:19302"
	moveR144 = "95.163.34.144:19302"
	moveR179 = "95.163.34.179:19302"
	moveR190 = "95.163.34.190:19302"
	moveR48  = "95.163.34.48:19302"
)

var moveRelays = []string{moveR21, moveR42, moveR252, moveR92, moveR144, moveR179, moveR190, moveR48}

func lossSample(relay string, packets int, rate float64) relayLossSample {
	lost := int(rate*float64(packets) + 0.5)
	return relayLossSample{relay: relay, rx: packets - lost, lost: lost}
}

// The window of the verdict at 07:48:55: the judge rested .42 on it, and
// .21, .252 and .92 lost too, under the verdict's bar.
func moveVerdictWindow() []relayLossSample {
	return []relayLossSample{
		lossSample(moveR21, 676, 0.006),
		lossSample(moveR42, 699, 0.033),
		lossSample(moveR252, 349, 0.023),
		lossSample(moveR144, 352, 0),
		lossSample(moveR92, 347, 0.017),
		lossSample(moveR190, 350, 0),
		lossSample(moveR179, 349, 0),
		lossSample(moveR48, 351, 0),
	}
}

func withCleanRelayLossy(t *testing.T) {
	t.Helper()
	noteLossyRelays(nil, time.Time{})
	t.Cleanup(func() { noteLossyRelays(nil, time.Time{}) })
}

func TestLossyRelays(t *testing.T) {
	want := map[string]bool{moveR21: true, moveR42: true, moveR252: true, moveR92: true}
	if got := lossyRelays(moveVerdictWindow()); !maps.Equal(got, want) {
		t.Fatalf("verdict window: losing %v, want %v", got, want)
	}

	// Only .42 was judged in that window: the others were under the verdict's
	// bar, which is why the spread could hand them its sessions.
	var j relayJudge
	j.step(moveVerdictWindow())
	if v := j.step(moveVerdictWindow()); len(v) != 1 || v[0].relay != moveR42 {
		t.Fatalf("verdicts %v, want .42 alone", v)
	}

	cases := []struct {
		name    string
		samples []relayLossSample
		want    map[string]bool
	}{
		{"an ordinary window of the same night: 0.2% on a clean relay is noise", []relayLossSample{
			lossSample(moveR144, 2782, 0.002), lossSample(moveR179, 2800, 0), lossSample(moveR190, 2799, 0),
		}, nil},
		{"saturated alike: 9% against 6% is not three times the best", []relayLossSample{
			lossSample(moveR144, 2000, 0.06), lossSample(moveR179, 2000, 0.09),
		}, nil},
		{"one relay weighed: nothing to compare against", []relayLossSample{
			lossSample(moveR42, 3000, 0.05), lossSample(moveR144, 150, 0),
		}, nil},
		{"a quiet relay is not weighed, however it lost", []relayLossSample{
			lossSample(moveR42, 150, 0.5), lossSample(moveR144, 3000, 0), lossSample(moveR179, 3000, 0),
		}, nil},
		{"losing against a best that loses too", []relayLossSample{
			lossSample(moveR42, 2000, 0.04), lossSample(moveR144, 2000, 0.01), lossSample(moveR179, 2000, 0.02),
		}, map[string]bool{moveR42: true}},
	}
	for _, c := range cases {
		if got := lossyRelays(c.samples); !maps.Equal(got, c.want) {
			t.Errorf("%s: losing %v, want %v", c.name, got, c.want)
		}
	}
}

// The bench's move again: with .42 resting, the spread put streams 1 and 9 on
// .252 and .92. With the window's losing relays behind, they go to the clean
// ones, and the losing ones stay their failover.
func TestAssignRelaysAroundDialsLosingRelaysAfterTheClean(t *testing.T) {
	withCleanRelayRest(t)
	now := time.Now()
	noteRelayResting(moveR42, now)
	lossy := lossyRelays(moveVerdictWindow())

	for id, before := range map[int]string{1: moveR252, 9: moveR92} {
		if got := assignRelays(moveRelays, id, now)[0]; got != before {
			t.Fatalf("stream %d → %s without the losing relays behind, want %s as on the bench", id, got, before)
		}
	}
	clean := []string{moveR144, moveR179, moveR190, moveR48}
	losing := []string{moveR21, moveR252, moveR92}
	heads := map[string]int{}
	for id := 0; id < 8; id++ {
		got := assignRelaysAround(moveRelays, id, now, nil, lossy)
		if len(got) != 7 || slices.Contains(got, moveR42) {
			t.Fatalf("stream %d → %v: want the seven relays not resting", id, got)
		}
		for i, relay := range got {
			if (i < len(clean)) != slices.Contains(clean, relay) {
				t.Fatalf("stream %d → %v: want the clean relays %v first, the losing %v after", id, got, clean, losing)
			}
		}
		heads[got[0]]++
	}
	for _, relay := range clean {
		if heads[relay] != 2 {
			t.Fatalf("heads %v: want eight streams spread two to a clean relay", heads)
		}
	}

	// Nothing losing: the spread as before.
	for id := 0; id < 8; id++ {
		if got, want := assignRelaysAround(moveRelays, id, now, nil, nil), assignRelays(moveRelays, id, now); !slices.Equal(got, want) {
			t.Fatalf("stream %d: %v with no losing relays, want %v", id, got, want)
		}
	}
	// Every relay left losing: the spread over all of them, as before.
	all := map[string]bool{}
	for _, relay := range moveRelays {
		all[relay] = true
	}
	for id := 0; id < 8; id++ {
		if got, want := assignRelaysAround(moveRelays, id, now, nil, all), assignRelays(moveRelays, id, now); !slices.Equal(got, want) {
			t.Fatalf("stream %d: %v with every relay losing, want %v", id, got, want)
		}
	}
	// Crowded and losing: crowded, last.
	crowded := map[string]bool{moveR144: true, moveR252: true}
	got := assignRelaysAround(moveRelays, 0, now, crowded, lossy)
	want := []string{moveR179, moveR190, moveR48, moveR21, moveR92, moveR252, moveR144}
	if !slices.Equal(got, want) {
		t.Fatalf("crowded %v, losing %v → %v, want %v", slices.Sorted(maps.Keys(crowded)), slices.Sorted(maps.Keys(lossy)), got, want)
	}
}

// movingSessionOn is sessionOn that also returns the stream.
func movingSessionOn(t *testing.T, relay string, link []string) (*stream, *attemptHandle) {
	t.Helper()
	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	s := &stream{id: 1}
	s.attempt.Store(h.a)
	s.relays.Store(&link)
	untrack := trackLiveSession(relay, s)
	t.Cleanup(func() {
		untrack()
		h.end()
	})
	return s, h
}

// A session moved off .42 carries the window's losing relays into its next
// attempt, which dials them last; once. A session with nowhere else to go
// stays and carries nothing.
func TestSessionMovedOffARestedRelayDialsTheLosingRelaysLast(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	now := time.Now()
	s, h := movingSessionOn(t, moveR42, moveRelays)
	pinned, _ := movingSessionOn(t, moveR42, []string{moveR42})

	noteLossyRelays(lossyRelays(moveVerdictWindow()), now)
	noteRelayResting(moveR42, now)
	out := recycleRelaySessions(context.Background(), moveR42, now, nil)
	if out.moved != 1 || out.stayed != 1 {
		t.Fatalf("moved %d, stayed %d: want the session with other relays moved, the pinned one left", out.moved, out.stayed)
	}
	losing := []string{moveR21, moveR252, moveR92}
	if !slices.Equal(out.last, losing) {
		t.Fatalf("dialed last %v, want %v", out.last, losing)
	}
	select {
	case <-h.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the session stayed on the rested relay")
	}

	next := now.Add(time.Second)
	got := streamAttemptOrderAround("move-test", moveRelays, s.id, WorkerGroupConfig{UseUDP: true}, next, s.takeMove(next))
	tail := slices.Sorted(slices.Values(got[4:]))
	if got[0] != moveR179 || !slices.Equal(tail, losing) {
		t.Fatalf("moved stream 1 dials %v: want a clean relay first and %v last", got, losing)
	}
	if again := s.takeMove(next); again != nil {
		t.Fatalf("the attempt after carries %+v: want the move's order for one attempt only", again)
	}
	if p := pinned.takeMove(next); p != nil {
		t.Fatalf("a session with nowhere else to go carries %+v", p)
	}
}

// A window older than relayMoveLossyFresh says nothing about the move: the
// moved session spreads as before. Nor does a move older than that about the
// attempt that finally follows it.
func TestAStaleWindowOrMoveOrdersNothing(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	now := time.Now()
	s, _ := movingSessionOn(t, moveR42, moveRelays)

	noteLossyRelays(lossyRelays(moveVerdictWindow()), now.Add(-relayMoveLossyFresh-time.Second))
	noteRelayResting(moveR42, now)
	if out := recycleRelaySessions(context.Background(), moveR42, now, nil); out.moved != 1 || out.last != nil {
		t.Fatalf("moved %d with %v dialed last: want the move without a stale window's order", out.moved, out.last)
	}
	if got := s.takeMove(now); got == nil || got.lossy != nil || got.head == "" {
		t.Fatalf("carries %+v: want a head and nothing from a stale window", got)
	}

	s.move.Store(&relayMove{lossy: lossyRelays(moveVerdictWindow()), head: moveR144, at: now})
	if got := s.takeMove(now.Add(relayMoveLossyFresh + time.Second)); got != nil {
		t.Fatalf("an attempt long after the move takes %+v", got)
	}
}

// benchSessions puts the ten streams of the bench on their relays as the
// spread did (stream id % 8 over moveRelays), streams 1 and 9 on .42, and
// returns the streams.
func benchSessions(t *testing.T) []*stream {
	t.Helper()
	streams := make([]*stream, 10)
	for id := range streams {
		relay := moveRelays[id%len(moveRelays)]
		if relay == moveR42 {
			s, _ := movingSessionOn(t, relay, moveRelays)
			s.id = id
			streams[id] = s
			continue
		}
		s := &stream{id: id}
		t.Cleanup(trackLiveSession(relay, s))
		streams[id] = s
	}
	return streams
}

// The bench's move once more, with every stream on it: the two sessions moved
// off .42 go first to two different clean relays — the least loaded, one
// session each there already — not both to .179 beside stream 5, and the
// losing relays stay their last (review 2026-10-22).
func TestSessionsMovedOffARestedRelaySpreadOverTheLeastLoaded(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	now := time.Now()
	streams := benchSessions(t)

	noteLossyRelays(lossyRelays(moveVerdictWindow()), now)
	noteRelayResting(moveR42, now)
	out := recycleRelaySessions(context.Background(), moveR42, now, nil)
	if out.moved != 2 || out.stayed != 0 {
		t.Fatalf("moved %d, stayed %d: want streams 1 and 9 moved", out.moved, out.stayed)
	}
	want := []movedHead{{1, moveR179}, {9, moveR144}}
	if !slices.Equal(out.heads, want) {
		t.Fatalf("heads %v, want %v", out.heads, want)
	}
	if note := out.note(); note != "; first to 95.163.34.179:19302 (stream 1), 95.163.34.144:19302 (stream 9); they dial 193.203.43.21:19302, 90.156.234.252:19302, 90.156.236.92:19302 last, losing in this window" {
		t.Fatalf("note %q", note)
	}

	next := now.Add(time.Second)
	lossy := lossyRelays(moveVerdictWindow())
	for _, h := range want {
		s := streams[h.id]
		got := streamAttemptOrderAround("move-test", moveRelays, s.id, WorkerGroupConfig{UseUDP: true}, next, s.takeMove(next))
		if got[0] != h.relay {
			t.Fatalf("stream %d dials %v: want %s first", h.id, got, h.relay)
		}
		for i, relay := range got {
			if (i >= 4) != lossy[relay] {
				t.Fatalf("stream %d dials %v: want the losing relays last", h.id, got)
			}
		}
	}
}

// Two relays rested in one judge turn share a load: the sessions moved off the
// second see where those of the first went.
func TestTwoRelaysRestedTogetherShareTheLoad(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	now := time.Now()
	link := []string{moveR21, moveR42, moveR144, moveR179}
	a, _ := movingSessionOn(t, moveR21, link)
	b, _ := movingSessionOn(t, moveR42, link)
	a.id, b.id = 0, 2 // the same tie-break turn on two relays

	restJudgedRelays(context.Background(), []relayVerdict{{relay: moveR21, rate: 0.05}, {relay: moveR42, rate: 0.05}}, now)
	ma, mb := a.move.Load(), b.move.Load()
	if ma == nil || mb == nil || ma.head == "" || ma.head == mb.head {
		t.Fatalf("moves %+v and %+v: want two heads on two relays", ma, mb)
	}
}

// A clean relay nobody is on takes the first session moved, whatever the
// stream's turn among the ties would have said: the load is what is running
// there, not only what the move has sent.
func TestAMoveGoesWhereNobodyIs(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	now := time.Now()
	link := []string{moveR42, moveR144, moveR179, moveR190}
	s, _ := movingSessionOn(t, moveR42, link)
	s.id = 1
	for i, relay := range []string{moveR144, moveR179, moveR179, moveR144} {
		t.Cleanup(trackLiveSession(relay, &stream{id: 10 + i}))
	}
	noteRelayResting(moveR42, now)
	if out := recycleRelaySessions(context.Background(), moveR42, now, nil); len(out.heads) != 1 || out.heads[0].relay != moveR190 {
		t.Fatalf("heads %v: want stream 1 on %s, where nobody is", out.heads, moveR190)
	}
}

// The move weighs the session's credential: a relay crowded with its ghosts
// goes behind the rest, as the attempt would put it — a head picked there
// would be passed over and its stream land on the next session's relay — and
// so does one where the credential has its quota's worth of allocations with
// the turn's picks: two streams of one credential are not sent where one
// fits (codex review 2026-10-22).
func TestAMoveLeavesRelaysFullForTheCredentialLast(t *testing.T) {
	const user = "1761234567:move-test"
	t.Run("crowded with ghosts", func(t *testing.T) {
		withCleanRelayRest(t)
		withCleanRelayLossy(t)
		resetAllocationBook(t)
		now := time.Now()
		link := []string{moveR42, moveR144, moveR179, moveR190}
		s0, _ := movingSessionOn(t, moveR42, link)
		s1, _ := movingSessionOn(t, moveR42, link)
		s0.id, s1.id = 0, 1
		for _, s := range []*stream{s0, s1} {
			u := user
			s.user.Store(&u)
		}
		t.Cleanup(trackLiveSession(moveR179, &stream{id: 10}))
		t.Cleanup(trackLiveSession(moveR190, &stream{id: 11}))
		loseOn(user, moveR144, orphanSteerAt, now)
		noteRelayResting(moveR42, now)
		out := recycleRelaySessions(context.Background(), moveR42, now, nil)
		if len(out.heads) != 2 || out.heads[0].relay == moveR144 || out.heads[1].relay == moveR144 || out.heads[0].relay == out.heads[1].relay {
			t.Fatalf("heads %v: want %s and %s, not the crowded %s", out.heads, moveR179, moveR190, moveR144)
		}
	})
	t.Run("no room in the quota", func(t *testing.T) {
		withCleanRelayRest(t)
		withCleanRelayLossy(t)
		resetAllocationBook(t)
		now := time.Now()
		link := []string{moveR42, moveR144, moveR179}
		s0, _ := movingSessionOn(t, moveR42, link)
		s1, _ := movingSessionOn(t, moveR42, link)
		s0.id, s1.id = 0, 1
		for _, s := range []*stream{s0, s1} {
			u := user
			s.user.Store(&u)
		}
		// .144: five sessions of the credential and four of its ghosts —
		// room for one; .179: eight sessions of other groups.
		loseOn(user, moveR144, orphanSteerAt-1, now)
		for i := 0; i < 5; i++ {
			trackAllocation(&countingConn{}, user, moveR144)
			t.Cleanup(trackLiveSession(moveR144, &stream{id: 10 + i}))
		}
		for i := 0; i < 8; i++ {
			t.Cleanup(trackLiveSession(moveR179, &stream{id: 20 + i}))
		}
		noteRelayResting(moveR42, now)
		out := recycleRelaySessions(context.Background(), moveR42, now, nil)
		want := []movedHead{{0, moveR144}, {1, moveR179}}
		if !slices.Equal(out.heads, want) {
			t.Fatalf("heads %v, want %v: one where the quota has room for one, the other beside the eight", out.heads, want)
		}
	})
}

// The head goes first only while it is in the attempt's first tier: crowded
// with the credential's ghosts since the move, resting since, or gone from the
// relays the attempt has, it leaves the order as the spread has it.
func TestTheMovesHeadGoesFirstOnlyFromTheFirstTier(t *testing.T) {
	withCleanRelayRest(t)
	now := time.Now()
	order := assignRelaysAround(moveRelays, 0, now, nil, nil)
	if got := headFirst(slices.Clone(order), moveR179, nil, nil, now); got[0] != moveR179 || len(got) != len(order) {
		t.Fatalf("head %s → %v: want it first and nothing lost", moveR179, got)
	}
	crowded := map[string]bool{moveR179: true}
	if got := headFirst(slices.Clone(order), moveR179, crowded, nil, now); got[0] != order[0] {
		t.Fatalf("crowded head %s → %v: want the order as it was", moveR179, got)
	}
	lossy := map[string]bool{moveR179: true}
	if got := headFirst(slices.Clone(order), moveR179, nil, lossy, now); got[0] != order[0] {
		t.Fatalf("losing head %s → %v: want the order as it was", moveR179, got)
	}
	if got := headFirst(slices.Clone(order), "203.0.113.1:19302", nil, nil, now); !slices.Equal(got, order) {
		t.Fatalf("a head not among the relays → %v: want the order as it was", got)
	}
	noteRelayResting(moveR179, now)
	rested := assignRelaysAround(moveRelays, 0, now, nil, nil)
	if got := headFirst(slices.Clone(rested), moveR179, nil, nil, now); !slices.Equal(got, rested) {
		t.Fatalf("a head resting since → %v: want the order as it was", got)
	}
}
