/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

const (
	deafRelay    = "193.203.43.37:19302"
	witnessRelay = "95.163.34.166:19302"
	// deafPeer is the server behind the relays the staged sessions run to.
	deafPeer = "203.0.113.7:56000"
)

// Two deaf sessions under one server and a third after the tunnel moved to
// another server on the same network: not a verdict — the rest it would give
// is the relay's from the second server, and the second has seen one. The
// count starts over with the server, as with the network.
func TestRelayDeafCountStartsOverWithAnotherServer(t *testing.T) {
	var j relayDeafJudge
	at := fieldClock(t, "06:31:39")
	under := func(peer string, d deafSession) deafSession { d.peer = peer; return d }
	for i := 0; i < relayDeafStrikes-1; i++ {
		if n, v := j.note(under(deafPeer, deafOn(deafRelay, at.Add(time.Duration(i)*time.Second)))); n != i+1 || v != nil {
			t.Fatalf("death %d under the first server: counted %d, verdict %+v", i+1, n, v)
		}
	}
	other := "198.51.100.9:56000"
	if n, v := j.note(under(other, deafOn(deafRelay, at.Add(10*time.Second)))); n != 1 || v != nil {
		t.Fatalf("first death under another server: counted %d, verdict %+v — the first server's deaths carried over", n, v)
	}
	// And the same server throughout is a verdict, as before.
	var same relayDeafJudge
	for i := 0; i < relayDeafStrikes; i++ {
		n, v := same.note(under(deafPeer, deafOn(deafRelay, at.Add(time.Duration(i)*time.Second))))
		if (v != nil) != (i == relayDeafStrikes-1) || n != i+1 {
			t.Fatalf("death %d under one server: counted %d, verdict %+v", i+1, n, v)
		}
	}
}

// deafOn is a UDP session found deaf on relay at at, with a witness on the
// other relay and somewhere to go.
func deafOn(relay string, at time.Time) deafSession {
	witness := witnessRelay
	if relay == witnessRelay {
		witness = deafRelay
	}
	return deafSession{relay: relay, network: 1144, at: at, elsewhere: true, witness: witness}
}

func fieldClock(t *testing.T, hms string) time.Time {
	t.Helper()
	at, err := time.Parse("2006-01-02 15:04:05", "2026-10-21 "+hms)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// The field log of 2026-10-21: streams 8, 2 and 0 went deaf on 193.203.43.37
// at 06:31:39, 06:32:08 and 06:32:20 while the streams on 95.163.34.166 were
// heard. The third rests the relay; streams 4 and 6, deaf at 06:32:46, are
// the start of a new count.
func TestRelayDeafJudgeRestsTheRelayOfTheFieldLog(t *testing.T) {
	var j relayDeafJudge
	for i, hms := range []string{"06:31:39", "06:32:08"} {
		if n, v := j.note(deafOn(deafRelay, fieldClock(t, hms))); n != i+1 || v != nil {
			t.Fatalf("death at %s: counted %d, verdict %+v", hms, n, v)
		}
	}
	n, v := j.note(deafOn(deafRelay, fieldClock(t, "06:32:20")))
	if n != 3 || v == nil {
		t.Fatalf("third death: counted %d, no verdict", n)
	}
	if v.relay != deafRelay || v.deaths != 3 || v.span != 41*time.Second || v.witness != witnessRelay {
		t.Fatalf("verdict = %+v, want %s, 3 deaths in 41s, witness %s", v, deafRelay, witnessRelay)
	}
	if n, v := j.note(deafOn(deafRelay, fieldClock(t, "06:32:46"))); n != 1 || v != nil {
		t.Fatalf("after the verdict: counted %d, verdict %+v — the count does not start over", n, v)
	}
}

// What the judge must not count, however often it comes.
func TestRelayDeafJudgeCountsOnlyAWitnessedDeafnessOverUDP(t *testing.T) {
	cases := map[string]func(*deafSession){
		// A path silent as a whole has no stream heard on any relay.
		"no witness":           func(d *deafSession) { d.witness = "" },
		"witness on the relay": func(d *deafSession) { d.witness = d.relay },
		// Over TCP flows die on their own, beside neighbours that carry on.
		"over TCP": func(d *deafSession) { d.overTCP = true },
		// Resting the only relay the session can go to moves nothing.
		"nowhere else to go": func(d *deafSession) { d.elsewhere = false },
		// Across a freeze a NAT forgets flows, whichever relay is behind them.
		"freeze in the silence": func(d *deafSession) { d.froze = true },
	}
	at := fieldClock(t, "06:31:39")
	for name, spoil := range cases {
		var j relayDeafJudge
		for i := 0; i < 2*relayDeafStrikes; i++ {
			d := deafOn(deafRelay, at.Add(time.Duration(i)*10*time.Second))
			spoil(&d)
			if n, v := j.note(d); n != 0 || v != nil {
				t.Fatalf("%s: death %d counted %d, verdict %+v", name, i+1, n, v)
			}
		}
	}
}

// A death that does not count says nothing either way: the deaths counted
// before it stand.
func TestRelayDeafJudgeKeepsTheCountThroughAnUnwitnessedDeath(t *testing.T) {
	var j relayDeafJudge
	at := fieldClock(t, "06:31:39")
	j.note(deafOn(deafRelay, at))
	j.note(deafOn(deafRelay, at.Add(30*time.Second)))
	silent := deafOn(deafRelay, at.Add(time.Minute))
	silent.witness = ""
	j.note(silent)
	if n, v := j.note(deafOn(deafRelay, at.Add(90*time.Second))); n != 3 || v == nil {
		t.Fatalf("counted %d, verdict %+v after an unwitnessed death in between", n, v)
	}
}

// Ten minutes hold two cycles of a stream alone on its relay (2.5-4 min each on
// 2026-10-21); deaths further apart do not add up.
func TestRelayDeafJudgeCountsWithinTheWindow(t *testing.T) {
	at := fieldClock(t, "06:28:59")

	var lone relayDeafJudge
	lone.note(deafOn(deafRelay, at))
	lone.note(deafOn(deafRelay, at.Add(4*time.Minute)))
	if n, v := lone.note(deafOn(deafRelay, at.Add(8*time.Minute))); n != 3 || v == nil {
		t.Fatalf("a lone stream's third death in 8 min: counted %d, no verdict", n)
	}

	var sparse relayDeafJudge
	sparse.note(deafOn(deafRelay, at))
	sparse.note(deafOn(deafRelay, at.Add(6*time.Minute)))
	if n, v := sparse.note(deafOn(deafRelay, at.Add(relayDeafWindow+time.Second))); n != 2 || v != nil {
		t.Fatalf("the first death out of the window: counted %d, verdict %+v", n, v)
	}
	if n, v := sparse.note(deafOn(deafRelay, at.Add(relayDeafWindow+time.Minute))); n != 3 || v == nil {
		t.Fatalf("three inside the window again: counted %d, no verdict", n)
	}
}

// What a relay did to the sessions on one network says nothing about the next.
func TestRelayDeafJudgeStartsOverOnAnotherNetwork(t *testing.T) {
	var j relayDeafJudge
	at := fieldClock(t, "06:31:39")
	j.note(deafOn(deafRelay, at))
	j.note(deafOn(deafRelay, at.Add(30*time.Second)))
	moved := deafOn(deafRelay, at.Add(time.Minute))
	moved.network = 1145
	if n, v := j.note(moved); n != 1 || v != nil {
		t.Fatalf("first death on another network: counted %d, verdict %+v", n, v)
	}
}

// Each relay has a count of its own: two relays that both deafen sessions, each
// witnessed by the other, do not add up into a verdict on either.
func TestRelayDeafJudgeCountsEachRelayApart(t *testing.T) {
	var j relayDeafJudge
	at := fieldClock(t, "06:31:39")
	for i := 0; i < 2; i++ {
		for _, relay := range []string{deafRelay, witnessRelay} {
			if _, v := j.note(deafOn(relay, at.Add(time.Duration(i)*time.Minute))); v != nil {
				t.Fatalf("verdict %+v after %d deaths per relay", v, i+1)
			}
		}
	}
	if _, v := j.note(deafOn(witnessRelay, at.Add(3*time.Minute))); v == nil || v.relay != witnessRelay {
		t.Fatalf("verdict = %+v, want %s on its third death", v, witnessRelay)
	}
}

// liveStream puts a ready stream with a session begun at start, its relay last
// heard at heard, on relay — the way runSession books it.
func liveStream(t *testing.T, id int, relay string, overTCP bool, start, heard time.Time) *stream {
	t.Helper()
	s := &stream{id: id}
	a := newStreamActivity(start, 0)
	a.noteRx(heard)
	s.activity.Store(a)
	s.overTCP.Store(overTCP)
	s.ready.Store(true)
	t.Cleanup(trackLiveSession(relay, s))
	return s
}

// The witness is a stream on another relay, over UDP, that has run since before
// the deaf session fell silent and is hearing its own relay now.
func TestDeafWitnessIsAStreamThatLivedThroughTheSilence(t *testing.T) {
	now := time.Now()
	before := now.Add(-5 * time.Minute)

	// None of these vouches for the path through 90 s of silence.
	liveStream(t, 0, deafRelay, false, before, now.Add(-time.Second))       // on the deaf relay itself
	liveStream(t, 2, witnessRelay, true, before, now.Add(-time.Second))     // over TCP
	liveStream(t, 4, witnessRelay, false, now.Add(-10*time.Second), now)    // a redial heard on its proof alone
	liveStream(t, 6, witnessRelay, false, before, now.Add(-40*time.Second)) // stale
	idle := liveStream(t, 8, witnessRelay, false, before, now.Add(-time.Second))
	idle.ready.Store(false) // not up
	if relay, id := deafWitness(deafRelay, now.Add(-90*time.Second), now); relay != "" {
		t.Fatalf("stream %d on %s taken for a witness", id, relay)
	}

	// Nor, through the half minute of silence a post-wake probe can end on, a
	// stream heard last before that silence began.
	liveStream(t, 10, witnessRelay, false, before, now.Add(-33*time.Second))
	if relay, id := deafWitness(deafRelay, now.Add(-31*time.Second), now); relay != "" {
		t.Fatalf("stream %d on %s, not heard since the silence began, taken for a witness", id, relay)
	}

	liveStream(t, 1, witnessRelay, false, before, now.Add(-5*time.Second))
	if relay, id := deafWitness(deafRelay, now.Add(-31*time.Second), now); relay != witnessRelay || id != 1 {
		t.Fatalf("witness = stream %d on %q, want stream 1 on %s", id, relay, witnessRelay)
	}
}

// deafStream is a stream whose session on relay, dialed from link, is ending
// deaf: registered as attemptOnce and runSession register it.
func deafStream(t *testing.T, id int, relay string, link []string, overTCP bool) (*stream, *attemptHandle) {
	t.Helper()
	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	s := &stream{id: id}
	s.attempt.Store(h.a)
	s.relays.Store(&link)
	s.overTCP.Store(overTCP)
	untrack := trackLiveSession(relay, s)
	t.Cleanup(func() {
		untrack()
		h.end()
	})
	return s, h
}

func withCleanRelayDeaf(t *testing.T) {
	t.Helper()
	withCleanRelayRest(t)
	resetRelayDeaf()
	t.Cleanup(resetRelayDeaf)
	// A real silence of the whole path, left by any test that ran relays
	// before this one, must not excuse the deaths these tests stage.
	withPathGapEnd(t, time.Time{})
}

// withPathGapEnd makes at the end of the last silence of the whole UDP path for
// this test (the zero time: none), and puts the real record back after it.
func withPathGapEnd(t *testing.T, at time.Time) {
	t.Helper()
	prev := relayGapEndAt[0].Load()
	t.Cleanup(func() { relayGapEndAt[0].Store(prev) })
	if at.IsZero() {
		relayGapEndAt[0].Store(0)
		return
	}
	relayGapEndAt[0].Store(int64(at.Sub(relayHeardBase)))
}

// Three sessions deaf on one relay while a stream on the other keeps hearing
// its own: the relay rests, and the sessions on it — the one that has just gone
// deaf among them — move to the other relay of their link.
func TestDeafSessionsRestTheRelayAndMoveItsSessions(t *testing.T) {
	withCleanRelayDeaf(t)
	link := []string{deafRelay, witnessRelay}
	now := time.Now()
	liveStream(t, 1, witnessRelay, false, now.Add(-5*time.Minute), now.Add(-5*time.Second))
	healthy := sessionOn(t, deafRelay, link)

	deaf := &deadStreamError{silent: deadStreamTimeout}
	var last *attemptHandle
	for i, id := range []int{8, 2, 0} {
		s, h := deafStream(t, id, deafRelay, link, false)
		last = h
		noteDeafSession(s, deafRelay, deafPeer, false, deaf, now, now.Add(time.Duration(i)*time.Second))
		if resting := relayResting(deafRelay, now); resting != (i == 2) {
			t.Fatalf("after deaf session %d: resting = %v", i+1, resting)
		}
	}
	for name, h := range map[string]*attemptHandle{"the session still on the relay": healthy, "the deaf session": last} {
		select {
		case <-h.ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("%s was not moved off the rested relay", name)
		}
	}
}

// Over TCP, with nothing heard on the other relay, across a freeze, or under a
// failure of the phone's own network, the same deaths leave the relay in
// rotation; so do sessions we ended ourselves.
func TestDeafSessionsWithoutAVerdictLeaveTheRelayInRotation(t *testing.T) {
	link := []string{deafRelay, witnessRelay}
	deaf := &deadStreamError{silent: deadStreamTimeout}
	cases := map[string]struct {
		overTCP, cancelled, witness, pathGap bool
		err                                  error
	}{
		"over TCP":       {overTCP: true, witness: true, err: deaf},
		"no witness":     {err: deaf},
		"ended by us":    {cancelled: true, witness: true, err: deaf},
		"a freeze in it": {witness: true, err: &deadStreamError{silent: deadStreamTimeout, froze: true}},
		// The witness was dark too and has just been heard again: the whole
		// path's silence, not this relay's (Codex review, 23.10).
		"a whole-path silence in it": {witness: true, pathGap: true, err: deaf},
		"not deaf":                   {witness: true, err: errors.New("relay RX: read: connection refused")},
		"the phone's network": {witness: true,
			err: errors.Join(deaf, fmt.Errorf("relay TX: %w", syscall.ENETUNREACH))},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			withCleanRelayDeaf(t)
			now := time.Now()
			if c.witness {
				liveStream(t, 1, witnessRelay, false, now.Add(-5*time.Minute), now.Add(-5*time.Second))
			}
			if c.pathGap {
				withPathGapEnd(t, now.Add(-deadStreamTimeout/2))
			}
			for i := 0; i < 2*relayDeafStrikes; i++ {
				s, _ := deafStream(t, 2*i, deafRelay, link, c.overTCP)
				noteDeafSession(s, deafRelay, deafPeer, c.cancelled, c.err, now, now)
			}
			if relayResting(deafRelay, now) {
				t.Fatal("the relay is resting")
			}
		})
	}
}

// The detector says whether a freeze fell inside the silence it ends.
func TestDeadStreamSaysWhetherTheSilenceHadAFreezeInIt(t *testing.T) {
	for _, froze := range []bool{false, true} {
		now := time.Now()
		activity := newStreamActivity(now.Add(-5*time.Minute), 0)
		if froze {
			activity.resetLiveness(now.Add(-deadStreamTimeout - time.Second))
		} else {
			activity.noteRx(now.Add(-deadStreamTimeout - time.Second))
		}
		got := make(chan error, 1)
		(&stream{id: 3}).runKeepalive(context.Background(), activity, func(err error) { got <- err }, func(int) error { return nil }, nil)
		var dead *deadStreamError
		select {
		case err := <-got:
			if !errors.As(err, &dead) || dead.froze != froze {
				t.Fatalf("freeze %v: the detector reported %#v", froze, err)
			}
		default:
			t.Fatalf("freeze %v: the detector returned without reporting", froze)
		}
	}
}

// A judge whose proxy has stopped moves nothing: the sessions booked on the
// relay by then may be the next proxy's (Codex review of the iOS port, 22.10).
func TestACancelledJudgeMovesNoSession(t *testing.T) {
	withCleanRelayRest(t)
	withCleanRelayLossy(t)
	s, h := movingSessionOn(t, moveR42, []string{moveR42, moveR179})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	restJudgedRelays(ctx, []relayVerdict{{relay: moveR42, rate: 0.05}}, time.Now())
	if out := recycleRelaySessions(ctx, moveR42, time.Now(), nil); out.moved != 0 {
		t.Fatalf("a cancelled judge moved %d session(s)", out.moved)
	}
	restDeafRelay(ctx, relayDeafVerdict{relay: moveR42, deaths: relayDeafStrikes}, 1, time.Now())
	if relayResting(moveR42, time.Now()) {
		t.Fatal("a cancelled judge rested the relay")
	}
	if s.move.Load() != nil {
		t.Fatal("a cancelled judge left a move on the session")
	}
	select {
	case <-h.ctx.Done():
		t.Fatal("a cancelled judge recycled the session")
	case <-time.After(relayRecycleGap + 100*time.Millisecond):
	}
}
