/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// withRelayHeardAt makes at the last time a relay was heard over UDP for this
// test (the zero time: never), clears the record of the path's silences over
// both transports — an earlier test with a long pause over TCP must not show
// through — and puts it all back after it.
func withRelayHeardAt(t *testing.T, at time.Time) {
	t.Helper()
	var prevHeard, prevGap [2]int64
	for i := range relayHeardAt {
		prevHeard[i], prevGap[i] = relayHeardAt[i].Load(), relayGapEndAt[i].Load()
		relayGapEndAt[i].Store(0)
	}
	t.Cleanup(func() {
		for i := range relayHeardAt {
			relayHeardAt[i].Store(prevHeard[i])
			relayGapEndAt[i].Store(prevGap[i])
		}
	})
	if at.IsZero() {
		relayHeardAt[0].Store(0)
		return
	}
	relayHeardAt[0].Store(int64(at.Sub(relayHeardBase)))
}

// A reader whose time is behind the one already stored neither sets the time
// back nor makes up a silence out of the gap the later reader measured.
func TestALateReaderDoesNotSetTheTimeHeardBack(t *testing.T) {
	now := time.Now()
	withRelayHeardAt(t, now.Add(time.Hour)) // a later reader got there first
	noteRelayHeard(false)
	if got := relayBaseTime(relayHeardAt[0].Load()); got.Before(now.Add(time.Hour)) {
		t.Fatalf("the time last heard went back to %v", got.Sub(now))
	}
	if pathGapEndedSince(false, now.Add(-time.Hour)) {
		t.Fatal("a late reader recorded a silence")
	}
}

// relayBaseTime is a value of relayHeardAt as a time.
func relayBaseTime(v int64) time.Time { return relayHeardBase.Add(time.Duration(v)) }

// The first relay heard after no relay at all was, for longer than
// wholePathGap, marks the end of the path's silence; a shorter pause — the
// keepalive grid's own — and the very first relay ever heard do not.
func TestTheEndOfAWholePathSilenceIsRecorded(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name  string
		heard time.Time // the relay last heard before this one
		gap   bool
	}{
		{"after a dark minute", now.Add(-time.Minute), true},
		{"just past the gap", now.Add(-wholePathGap - time.Second), true},
		{"a keepalive interval", now.Add(-keepaliveInterval), false},
		{"never heard before", time.Time{}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			withRelayHeardAt(t, c.heard)
			noteRelayHeard(false)
			if got := pathGapEndedSince(false, now.Add(-time.Second)); got != c.gap {
				t.Fatalf("a silence ending now recorded = %v, want %v", got, c.gap)
			}
			if pathGapEndedSince(false, time.Now().Add(time.Second)) {
				t.Fatal("a silence read as ending after it did")
			}
			if c.gap && pathGapEndedSince(true, now.Add(-time.Hour)) {
				t.Fatal("a silence over UDP was recorded for TCP")
			}
		})
	}
}

// An end recorded later is never taken back by one recorded earlier — what two
// racing readers, swapping their times in out of order, would otherwise do.
func TestAWholePathSilenceEndOnlyMovesForward(t *testing.T) {
	var end atomic.Int64
	advanceGapEnd(&end, 200)
	advanceGapEnd(&end, 100)
	if got := end.Load(); got != 200 {
		t.Fatalf("the end moved back to %d", got)
	}
	advanceGapEnd(&end, 300)
	if got := end.Load(); got != 300 {
		t.Fatalf("the end did not move forward: %d", got)
	}
}

// A silence of the whole path that was over before this session's own began
// excuses nothing: the deaf sessions still rest the relay.
func TestAWholePathSilenceBeforeTheDeafnessExcusesNothing(t *testing.T) {
	withCleanRelayDeaf(t)
	link := []string{deafRelay, witnessRelay}
	now := time.Now()
	withPathGapEnd(t, now.Add(-5*time.Minute))
	liveStream(t, 1, witnessRelay, false, now.Add(-10*time.Minute), now.Add(-5*time.Second))
	deaf := &deadStreamError{silent: deadStreamTimeout}
	for i, id := range []int{8, 2, 0} {
		s, _ := deafStream(t, id, deafRelay, link, false)
		noteDeafSession(s, deafRelay, deafPeer, false, deaf, now, now.Add(time.Duration(i)*time.Second))
	}
	if !relayResting(deafRelay, now) {
		t.Fatal("deaf sessions after the path's silence was over did not rest the relay")
	}
}
