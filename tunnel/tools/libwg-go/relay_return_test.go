/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"testing"
	"time"
)

const returnUser = "1762500000:return-test"

// returnRig is a proxy's sessions for the return pass: streams of one
// credential dialing the extras E1 and E2 and the link's own O.
type returnRig struct {
	t       *testing.T
	streams []*stream
	untrack map[*stream]func()
	handles map[*stream]*attemptHandle
	now     time.Time
	returns relayReturns
}

const (
	returnE1 = moveR144
	returnE2 = moveR179
	returnO  = moveR42
)

var returnLink = []string{returnE1, returnE2, returnO}

func newReturnRig(t *testing.T, onRelay ...string) *returnRig {
	t.Helper()
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	// The streams' group 0, whose slot serves their redials for a day.
	setReturnSlot(t, returnUser, time.Now().Add(24*time.Hour))
	setExtraRelaysConfigured([]string{returnE1, returnE2})
	t.Cleanup(func() { setExtraRelaysConfigured(nil) })
	r := &returnRig{t: t, untrack: map[*stream]func(){}, handles: map[*stream]*attemptHandle{}, now: time.Now()}
	for i, relay := range onRelay {
		s := &stream{id: i}
		u := returnUser
		s.user.Store(&u)
		link := returnLink
		s.relays.Store(&link)
		r.streams = append(r.streams, s)
		r.session(s, relay)
	}
	t.Cleanup(func() {
		for s, untrack := range r.untrack {
			untrack()
			r.handles[s].end()
		}
	})
	return r
}

// setReturnSlot puts user into group 0's credential slot until expires, and
// what the slot held back at cleanup.
func setReturnSlot(t *testing.T, user string, expires time.Time) {
	t.Helper()
	cache := getStreamCache(0)
	cache.mutex.Lock()
	prev := cache.creds
	cache.creds = TurnCredentials{Username: user, Password: "p", FetchedAt: time.Now(), ExpiresAt: expires}
	cache.mutex.Unlock()
	t.Cleanup(func() { cache.mutex.Lock(); cache.creds = prev; cache.mutex.Unlock() })
}

// down ends s's session the way a worker that gets no further does: closed,
// not ready, and no other one coming up.
func (r *returnRig) down(s *stream) {
	r.untrack[s]()
	delete(r.untrack, s)
	r.handles[s].end()
	s.ready.Store(false)
	s.attempt.Store(nil)
}

// session puts s on relay with a fresh attempt, ready — its next session,
// after the one before ended: the attempt takes the move given, as a worker's
// does (attemptOnce).
func (r *returnRig) session(s *stream, relay string) {
	if untrack := r.untrack[s]; untrack != nil {
		untrack()
		r.handles[s].end()
	}
	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	s.attempt.Store(h.a)
	s.takeMove(r.now)
	r.handles[s] = h
	s.ready.Store(true)
	r.untrack[s] = trackLiveSession(relay, s)
}

// pass advances the clock by d and runs the return pass.
func (r *returnRig) pass(d time.Duration) {
	r.now = r.now.Add(d)
	r.returns.returnPass(context.Background(), r.now, liveSessionList, func() bool { return false })
}

// returning is the stream whose return is in flight, nil if none.
func (r *returnRig) returning() *stream {
	if r.returns.pending == nil {
		return nil
	}
	return r.returns.pending.stream
}

// Three sessions on the link's own, the extras free: none returns before it has
// sat there relayReturnSettle; then one, to an extra, its attempt recycled; the
// next only once that one has run ready on an extra for relayReturnConfirm.
func TestASessionOnTheReserveReturnsToAFreeExtra(t *testing.T) {
	r := newReturnRig(t, returnO, returnO, returnO)
	r.pass(0)
	if r.returning() != nil {
		t.Fatal("a return started on the first sight of the reserve")
	}
	r.pass(relayReturnSettle + time.Second)
	s := r.returning()
	if s == nil {
		t.Fatal("no return started after the settle")
	}
	move := s.move.Load()
	if move == nil || (move.head != returnE1 && move.head != returnE2) || !r.handles[s].a.stale.Load() {
		t.Fatalf("the return: move %+v, attempt recycled %v; want an extra as its head and the attempt recycled", move, r.handles[s].a.stale.Load())
	}
	head := move.head
	r.session(s, head) // its next session, on the extra
	r.pass(relayReturnEvery)
	if r.returning() != s {
		t.Fatal("the return was settled before it was confirmed")
	}
	r.pass(relayReturnEvery)
	r.pass(relayReturnEvery)
	if next := r.returning(); next == nil || next == s {
		t.Fatalf("after %v on the extra: in flight %v; want the return confirmed and the next one started", relayReturnConfirm, next)
	}
}

// No return where no extra is free for it: both crowded with the credential's
// ghosts, both resting; and none of the last session ready.
func TestNoReturnWithoutAFreeExtraOrAnotherSessionReady(t *testing.T) {
	t.Run("crowded", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		loseOn(returnUser, returnE1, orphanSteerAt, r.now)
		loseOn(returnUser, returnE2, orphanSteerAt, r.now)
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		if r.returning() != nil {
			t.Fatal("returned to an extra crowded with the credential's ghosts")
		}
	})
	t.Run("resting", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		noteRelayResting(returnE1, r.now)
		noteRelayResting(returnE2, r.now)
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		if r.returning() != nil {
			t.Fatal("returned to a resting extra")
		}
	})
	t.Run("the last one carrying", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnE1)
		r.streams[1].sendStalled.Store(true) // ready, but its socket stalled
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		if r.returning() != nil {
			t.Fatal("returned the only session carrying")
		}
	})

	t.Run("no extras", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		setExtraRelaysConfigured(nil)
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		if r.returning() != nil {
			t.Fatal("returned with no extras configured")
		}
	})
	t.Run("a move given already", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO, returnE1)
		r.pass(0)
		r.streams[2].move.Store(&relayMove{head: returnE2, at: r.now.Add(relayReturnSettle)})
		r.pass(relayReturnSettle + time.Second)
		if r.returning() != nil {
			t.Fatal("a return started while a rested relay's move was still to run")
		}
	})
	t.Run("the path silent", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		r.pass(0)
		r.now = r.now.Add(relayReturnSettle + time.Second)
		r.returns.returnPass(context.Background(), r.now, liveSessionList, func() bool { return true })
		if r.returning() != nil {
			t.Fatal("a return started with the path to the relays silent")
		}
	})
}

// The minute on the extra is one session's: a session that ends and a new one
// that comes up between two passes start it over (Codex, 2026-11-07); the new
// one, begun after the move was taken, is the return's as well.
func TestAReturnIsConfirmedByOneSession(t *testing.T) {
	r := newReturnRig(t, returnO, returnO)
	r.pass(0)
	r.pass(relayReturnSettle + time.Second)
	s := r.returning()
	if s == nil {
		t.Fatal("no return started")
	}
	head := s.move.Load().head
	r.session(s, head)
	r.pass(relayReturnEvery)
	r.session(s, head) // its session ends, the next comes up on the same extra
	r.pass(relayReturnEvery)
	r.pass(relayReturnEvery)
	if r.returning() != s {
		t.Fatal("confirmed on a minute two sessions made between them")
	}
	r.pass(relayReturnEvery)
	if r.returning() == s {
		t.Fatal("not confirmed after the second session's minute")
	}
}

// An extra short of room in the credential's quota does not stand in for one
// that has it (Codex, 2026-11-07): nine of the credential's allocations on E1,
// none on E2 — the return goes to E2; and the Allocates still running count —
// a race's losers, a reconnect's — as the ones held do.
func TestAReturnGoesWhereTheQuotaHasRoom(t *testing.T) {
	for name, fill := range map[string]func(){
		"held": func() {
			for i := 0; i < 9; i++ {
				trackAllocation(&countingConn{}, returnUser, returnE1)
			}
		},
		"allocating": func() {
			for i := 0; i < 9; i++ {
				t.Cleanup(noteAllocating(returnUser, returnE1))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newReturnRig(t, returnO, returnO)
			fill()
			r.pass(0)
			r.pass(relayReturnSettle + time.Second)
			if s := r.returning(); s == nil || s.move.Load().head != returnE2 {
				t.Fatalf("the return: %+v; want it to E2", r.returns.pending)
			}
		})
	}
}

// A stream that does not come up blocks nothing: the others return (Codex,
// 2026-11-07). And a session the stream runs that did not take the return's
// move — begun before it was given — is no outcome of it.
func TestAReturnIsTheMoveTakersAlone(t *testing.T) {
	r := newReturnRig(t, returnO, returnO, returnO)
	r.untrack[r.streams[2]]() // between sessions, for good
	delete(r.untrack, r.streams[2])
	r.pass(0)
	r.pass(relayReturnSettle + time.Second)
	s := r.returning()
	if s == nil {
		t.Fatal("a stream that never came up blocked the return")
	}
	// A session of an attempt that took no move, on the reserve.
	r.untrack[s]()
	r.handles[s].end()
	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	s.attempt.Store(h.a)
	r.handles[s] = h
	r.untrack[s] = trackLiveSession(returnO, s)
	r.pass(relayReturnEvery)
	if r.returning() != s || r.returns.pause != 0 {
		t.Fatalf("in flight %v, pause %v: a session that took no move counted as the outcome", r.returning(), r.returns.pause)
	}
	// The next attempt takes it while that session, begun before, is still
	// listed on the reserve as it closes: still no outcome.
	taker := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	defer taker.end()
	s.attempt.Store(taker.a)
	s.takeMove(r.now)
	r.pass(relayReturnEvery)
	if r.returning() != s || r.returns.pause != 0 {
		t.Fatalf("in flight %v, pause %v: a session begun before the move was taken counted as the outcome", r.returning(), r.returns.pause)
	}
	// The attempt after it comes up on the extra: back.
	r.session(s, returnE1)
	for i := 0; i < 3; i++ {
		r.pass(relayReturnEvery)
	}
	if r.returning() == s {
		t.Fatal("not confirmed on the session of the attempt that took the move")
	}
}

// Called off, held against nothing: the network lost and the same one back
// between two passes; another move given to the stream while the return runs.
func TestAReturnIsCalledOffByTheNetworkOrAnotherMove(t *testing.T) {
	t.Run("the same network back", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		setNetworkState(101, relayTransportAsConfigured, r.now)
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		if r.returning() == nil {
			t.Fatal("no return started")
		}
		setNetworkState(0, relayTransportAsConfigured, r.now)
		setNetworkState(101, relayTransportAsConfigured, r.now)
		r.pass(relayReturnEvery)
		if r.returning() != nil || r.returns.pause != 0 {
			t.Fatalf("after the network lost and back: in flight %v, pause %v; want it off, no pause", r.returning(), r.returns.pause)
		}
	})
	t.Run("another move queued after ours was taken", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		s := r.returning()
		if s == nil {
			t.Fatal("no return started")
		}
		r.session(s, s.move.Load().head)                  // took ours, up on the extra
		s.giveMove(&relayMove{head: returnE2, at: r.now}) // a rested relay's, not taken yet
		r.pass(relayReturnEvery)
		if r.returning() != nil || r.returns.pause != 0 {
			t.Fatalf("with another move queued: in flight %v, pause %v; want it off, no pause", r.returning(), r.returns.pause)
		}
	})
	t.Run("another move", func(t *testing.T) {
		r := newReturnRig(t, returnO, returnO)
		r.pass(0)
		r.pass(relayReturnSettle + time.Second)
		s := r.returning()
		if s == nil {
			t.Fatal("no return started")
		}
		s.giveMove(&relayMove{head: returnE2, at: r.now}) // a deaf judge's in its place
		r.session(s, returnO)                             // taken, and on the reserve before the pass
		r.pass(relayReturnEvery)
		if r.returning() != nil || r.returns.pause != 0 {
			t.Fatalf("after another move: in flight %v, pause %v; want it off, no pause", r.returning(), r.returns.pause)
		}
	})
}

// A return that ends on the link's own again has failed — however long the
// session took to come up — and pauses the returns, the pause doubling; one
// that never comes up fails at relayReturnGiveUp; a move of the network or the
// transport calls it off without either. The session the return ended, still
// listed on the reserve as it closes, is no outcome.
func TestAFailedReturnPausesTheReturns(t *testing.T) {
	r := newReturnRig(t, returnO, returnO)
	r.pass(0)
	r.pass(relayReturnSettle + time.Second)
	s := r.returning()
	if s == nil {
		t.Fatal("no return started")
	}
	r.pass(relayReturnEvery) // the session the return ended, still closing
	if r.returning() != s {
		t.Fatal("the session the return ended counted as its outcome")
	}
	r.untrack[s]()
	delete(r.untrack, s)
	r.pass(relayReturnEvery) // coming up: on no relay
	r.session(s, returnO)    // the staged race gave it to the reserve
	r.pass(relayReturnEvery)
	if r.returning() != nil || r.returns.pause != relayReturnPauseMin {
		t.Fatalf("in flight %v, pause %v; want the return failed and a pause of %v", r.returning(), r.returns.pause, relayReturnPauseMin)
	}
	r.pass(relayReturnEvery)
	if r.returning() != nil {
		t.Fatal("a return started during the pause")
	}
	r.pass(relayReturnPauseMin)
	s = r.returning()
	if s == nil {
		t.Fatal("no return after the pause")
	}
	r.untrack[s]() // gone, and never back
	delete(r.untrack, s)
	r.handles[s].end()
	for i := 0; i < int(relayReturnGiveUp/relayReturnEvery); i++ {
		r.pass(relayReturnEvery)
	}
	if r.returns.pause != 2*relayReturnPauseMin {
		t.Fatalf("pause %v after a return that never came up, want %v", r.returns.pause, 2*relayReturnPauseMin)
	}

	// The network moves while a return is in flight: off, held against nothing.
	r2 := newReturnRig(t, returnO, returnO)
	r2.pass(0)
	r2.pass(relayReturnSettle + time.Second)
	if r2.returning() == nil {
		t.Fatal("no return started")
	}
	setNetworkState(202, relayTransportAsConfigured, r2.now)
	r2.pass(relayReturnEvery)
	if r2.returning() != nil || r2.returns.pause != 0 {
		t.Fatalf("after a move of the network: in flight %v, pause %v; want it off and no pause", r2.returning(), r2.returns.pause)
	}
}

// A return closes the session it takes, and the session redials through
// fetchCreds: only one whose slot still serves its credential for as long as the
// return may take to settle is taken. Not one whose slot holds another
// credential, has expired or expires within relayReturnGiveUp, or is being
// fetched for — and the same session returns once the slot serves it again.
// Audit of 2026-11-10: the pass used to close healthy sessions whatever the slot
// held, and with VK giving no credential each stayed down.
func TestNoReturnOfASessionWhoseSlotWouldNotServeItsRedial(t *testing.T) {
	for _, c := range []struct {
		name    string
		user    string
		expires time.Duration
	}{
		{"another credential", "1762500001:return-test", 24 * time.Hour},
		{"expired", returnUser, -time.Second},
		{"expiring within the give-up", returnUser, relayReturnGiveUp},
		{"being fetched", returnUser, 24 * time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newReturnRig(t, returnO, returnO, returnO)
			setReturnSlot(t, c.user, time.Now().Add(c.expires))
			r.pass(0)
			if c.name == "being fetched" {
				cache := getStreamCache(0)
				cache.mutex.Lock()
				r.pass(relayReturnSettle + time.Second)
				cache.mutex.Unlock()
			} else {
				r.pass(relayReturnSettle + time.Second)
			}
			if s := r.returning(); s != nil {
				t.Fatalf("stream %d returned, its slot not serving its redial", s.id)
			}
			setReturnSlot(t, returnUser, time.Now().Add(24*time.Hour))
			r.pass(relayReturnEvery)
			if r.returning() == nil {
				t.Fatal("no return once the slot serves the redial again")
			}
		})
	}
}

// A returned stream that has not come up anywhere since — its worker stuck
// short of a session — holds the returns until it is up again, past the pause:
// each next return would close another healthy session the same way. Audit of
// 2026-11-10: with workers that never came back, the passes took down four
// sessions of five in 17 minutes.
func TestNoReturnWhileAReturnedStreamIsDown(t *testing.T) {
	for _, c := range []struct {
		name string
		took bool // the worker took the move and its session then went
	}{
		{"never took its move", false},
		{"took its move, never came up", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newReturnRig(t, returnO, returnO, returnO, returnO, returnO)
			r.pass(0)
			r.pass(relayReturnSettle + time.Second)
			s := r.returning()
			if s == nil {
				t.Fatal("no return started")
			}
			if c.took {
				r.session(s, s.move.Load().head)
				r.pass(relayReturnEvery)
			}
			r.down(s)
			start := r.now
			for r.now.Sub(start) < 90*time.Minute {
				r.pass(relayReturnEvery)
				if other := r.returning(); other != nil && other != s {
					t.Fatalf("stream %d returned at +%v while stream %d, returned before, was still down",
						other.id, r.now.Sub(start), s.id)
				}
			}
			if r.returning() != nil || r.returns.down != s {
				t.Fatalf("in flight %v, the returns waiting for %v; want the return failed and stream %d waited for",
					r.returning(), r.returns.down, s.id)
			}
			r.session(s, returnO) // up again, anywhere
			for i := 0; i < 4 && r.returning() == nil; i++ {
				r.pass(relayReturnEvery)
			}
			if r.returning() == nil {
				t.Fatal("no return once the stream was up again")
			}
		})
	}
}

// An Allocate is counted while it runs, by credential and relay, and no longer
// once it has its answer (dialAndAllocate).
func TestAnAllocateIsCountedWhileItRuns(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	relay := startTestRelay(t, listenFakeRelay(t), 300*time.Millisecond)
	user := t.Name()
	done := make(chan error, 1)
	go func() {
		client, raw, alloc, _, _, err := dialAndAllocate(context.Background(), &stream{}, user, "pass", relay.addr, WorkerGroupConfig{UseUDP: true}, dialOpts{})
		if err == nil {
			alloc.Close()
			client.Close()
			raw.Close()
		}
		done <- err
	}()
	waitFor(t, "the Allocate counted while it runs", 3*time.Second, func() bool { return allocatingOn(user, relay.addr) == 1 })
	if err := <-done; err != nil {
		t.Fatalf("dialAndAllocate: %v", err)
	}
	if n := allocatingOn(user, relay.addr); n != 0 {
		t.Fatalf("%d Allocate(s) still counted after the answer", n)
	}
}

// A move offered is never the running attempt's to have taken: it is given
// only while the stream runs the attempt weighed, which is the one to end, and
// the next takes the move. An attempt published since — not yet past its
// takeMove — is not offered it, so it is never ended holding the move (Codex,
// 2026-11-07).
func TestAMoveOfferedEndsTheAttemptThatDidNotTakeIt(t *testing.T) {
	resetNetworkSwitch(t)
	s := &stream{}
	a := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	defer a.end()
	s.attempt.Store(a.a)
	m := &relayMove{head: returnE1, at: time.Now()}
	if !s.offerMove(m, a.a) {
		t.Fatal("not offered to the stream running the attempt weighed")
	}
	if s.offerMove(&relayMove{}, a.a) {
		t.Fatal("a second move given over the first")
	}
	b := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true}) // the worker's next
	defer b.end()
	s.attempt.Store(b.a)
	if got := s.takeMove(time.Now()); got != m {
		t.Fatalf("took %v, want the move offered", got)
	}
	recycleAttempt(a.a)
	if b.a.stale.Load() || s.tookMove.Load().attempt != b.a {
		t.Fatal("the attempt that took the move was the one ended")
	}

	// The weighed attempt ended and the next published, not yet past its
	// takeMove: the move is not offered, and nothing is queued for it.
	c := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	defer c.end()
	s.attempt.Store(c.a)
	if s.offerMove(&relayMove{head: returnE1, at: time.Now()}, b.a) {
		t.Fatal("offered to a stream gone on to another attempt")
	}
	if queued, _ := s.moveState(); queued != nil {
		t.Fatal("a move queued for an attempt that was not weighed")
	}
	if s.offerMove(&relayMove{}, nil) {
		t.Fatal("offered with no attempt weighed")
	}
}

// Given and taken in one step: read together, a move given is queued or booked
// as taken, never neither (Codex, 2026-11-07).
func TestAMovesHandoverIsOneStep(t *testing.T) {
	resetNetworkSwitch(t)
	s := &stream{}
	a := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	defer a.end()
	s.attempt.Store(a.a)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				s.takeMove(time.Now())
			}
		}
	}()
	for i := 0; i < 20000; i++ {
		m := &relayMove{at: time.Now()}
		if !s.offerMove(m, a.a) {
			continue
		}
		if queued, took := s.moveState(); queued != m && (took == nil || took.move != m) {
			close(stop)
			<-done
			t.Fatalf("iteration %d: the move given is neither queued nor taken", i)
		}
	}
	close(stop)
	<-done
}
