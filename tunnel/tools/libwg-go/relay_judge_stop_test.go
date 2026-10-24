/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A judge whose proxy stops after it has looked at its context and before it
// acts still touches nothing of the next proxy's. TestACancelledJudgeMovesNoSession
// covers a judge cancelled before it starts; these cover the moments after the
// check at its entry (Codex review, 23.10).

// firstCheckContext tells, on checked, that ctx.Err() has been asked once —
// the judge is past its entry check.
type firstCheckContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *firstCheckContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

// The judge passed its entry check, then waited for liveSessions while the
// proxy stopped and the next one booked a session on the relay: it neither
// moves that session nor recycles it.
func TestAJudgeStoppedBeforeItReadsTheSessionsMovesNoneOfTheNextProxys(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	resetNetworkSwitch(t)
	old, stop := context.WithCancel(context.Background())
	defer stop()
	judge := &firstCheckContext{Context: old, checked: make(chan struct{})}

	liveSessions.Lock()
	prior := liveSessions.byRelay
	liveSessions.byRelay = map[string]map[*stream]struct{}{}
	var unlock sync.Once
	release := func() { unlock.Do(liveSessions.Unlock) }
	defer release()
	t.Cleanup(func() {
		liveSessions.Lock()
		liveSessions.byRelay = prior
		liveSessions.Unlock()
	})
	result := make(chan relayMoveOut, 1)
	go func() { result <- recycleRelaySessions(judge, moveR42, time.Now(), nil) }()
	select {
	case <-judge.checked:
	case <-time.After(2 * time.Second):
		t.Fatal("the judge never reached its entry check")
	}
	stop()
	next, stopNext := context.WithCancel(context.Background())
	defer stopNext()
	h := beginAttempt(next, WorkerGroupConfig{UseUDP: true})
	defer h.end()
	s := &stream{id: 1, ctx: next}
	relays := []string{moveR42, moveR179}
	s.relays.Store(&relays)
	s.attempt.Store(h.a)
	liveSessions.byRelay[moveR42] = map[*stream]struct{}{s: {}}
	release()

	var out relayMoveOut
	select {
	case out = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("the judge never returned")
	}
	if out.moved != 0 || s.move.Load() != nil {
		t.Errorf("the stopped proxy's judge moved the next one's session: moved %d, move %+v", out.moved, s.move.Load())
	}
	select {
	case <-h.ctx.Done():
		t.Error("the stopped proxy's judge recycled the next one's session")
	case <-time.After(relayRecycleGap + 100*time.Millisecond):
	}
}

// The first of two verdicts rested its relay and waited on the disk while the
// proxy stopped and the next one named another server: the second rests
// nothing for that server.
func TestAJudgeStoppedWhileItsRestIsSavedRestsNothingForTheNextServer(t *testing.T) {
	withRelayRestFile(t)
	withCleanRelayLossy(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	relayRestSaving.Lock()
	var unlock sync.Once
	release := func() { unlock.Do(relayRestSaving.Unlock) }
	defer release()
	done := make(chan struct{})
	go func() {
		defer close(done)
		restJudgedRelays(ctx, []relayVerdict{{relay: moveR42, rate: 0.05}, {relay: moveR179, rate: 0.04}}, time.Now())
	}()
	waitFor(t, "the first rest marked, its save waiting", 2*time.Second, func() bool {
		_, ok := peekRelayRest(moveR42, "server:1")
		return ok
	})
	stop()
	setRelayRestPeer("next-server:2")
	release()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the judge never returned")
	}
	if m, ok := peekRelayRest(moveR179, "next-server:2"); ok {
		t.Fatalf("the stopped proxy's verdict rested a relay for the next server: %+v", m)
	}
}

// A rest that had run out is read back — and saved, which waits on the disk —
// while the proxy stops and the next one names another server: neither judge
// then rests the relay for that server.
func TestAJudgeStoppedWhileReadingARestRestsNothingForTheNextServer(t *testing.T) {
	for _, judge := range []string{"loss", "deaf"} {
		t.Run(judge, func(t *testing.T) {
			withRelayRestFile(t)
			withCleanRelayLossy(t)
			now := time.Now()
			relayRest.Lock()
			relayRest.marks[moveR42+"→server:1"] = relayRestMark{until: now.Add(-time.Second), rest: relayRestFor}
			relayRest.Unlock()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			relayRestSaving.Lock()
			var unlock sync.Once
			release := func() { unlock.Do(relayRestSaving.Unlock) }
			defer release()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if judge == "loss" {
					restJudgedRelays(ctx, []relayVerdict{{relay: moveR42, rate: 0.05}}, now)
				} else {
					restDeafRelay(ctx, relayDeafVerdict{relay: moveR42, deaths: relayDeafStrikes}, 1, now)
				}
			}()
			waitFor(t, "the run-out rest read back, its save waiting", 2*time.Second, func() bool {
				m, ok := peekRelayRest(moveR42, "server:1")
				return ok && m.returned
			})
			stop()
			setRelayRestPeer("next-server:2")
			release()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("the judge never returned")
			}
			if m, ok := peekRelayRest(moveR42, "next-server:2"); ok {
				t.Fatalf("the stopped proxy's %s judge rested the relay for the next server: %+v", judge, m)
			}
		})
	}
}
