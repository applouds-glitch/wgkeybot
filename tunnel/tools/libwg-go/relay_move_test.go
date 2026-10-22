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
	moved, stayed, last := recycleRelaySessions(context.Background(), moveR42, now)
	if moved != 1 || stayed != 1 {
		t.Fatalf("moved %d, stayed %d: want the session with other relays moved, the pinned one left", moved, stayed)
	}
	losing := []string{moveR21, moveR252, moveR92}
	if !slices.Equal(last, losing) {
		t.Fatalf("dialed last %v, want %v", last, losing)
	}
	select {
	case <-h.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the session stayed on the rested relay")
	}

	next := now.Add(time.Second)
	got := streamAttemptOrderAround("move-test", moveRelays, s.id, WorkerGroupConfig{UseUDP: true}, next, s.takeMoveLossy(next))
	tail := slices.Sorted(slices.Values(got[4:]))
	if got[0] != moveR179 || !slices.Equal(tail, losing) {
		t.Fatalf("moved stream 1 dials %v: want a clean relay first and %v last", got, losing)
	}
	if again := s.takeMoveLossy(next); again != nil {
		t.Fatalf("the attempt after carries %v: want the move's order for one attempt only", again)
	}
	if p := pinned.takeMoveLossy(next); p != nil {
		t.Fatalf("a session with nowhere else to go carries %v", p)
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
	if moved, _, last := recycleRelaySessions(context.Background(), moveR42, now); moved != 1 || last != nil {
		t.Fatalf("moved %d with %v dialed last: want the move without a stale window's order", moved, last)
	}
	if got := s.takeMoveLossy(now); got != nil {
		t.Fatalf("carries %v from a stale window", got)
	}

	s.moveLossy.Store(&relayMove{lossy: lossyRelays(moveVerdictWindow()), at: now})
	if got := s.takeMoveLossy(now.Add(relayMoveLossyFresh + time.Second)); got != nil {
		t.Fatalf("an attempt long after the move takes %v", got)
	}
}
