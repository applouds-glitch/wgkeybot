/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- the step: a pure function of what each poll step observed ----------------

const underLoadTestStep = 100 * time.Millisecond

// stepUntil feeds st steps of underLoadTestStep, heard never, witnessed as the
// function says for each step (counted from 1), until a verdict that ends the
// probe or max steps; it returns that verdict, the step it came on and the
// pings asked for on the way.
func stepUntil(st *underLoadProbeState, max int, witnessed func(step int) bool) (v underLoadProbeVerdict, at, resends int) {
	for i := 1; i <= max; i++ {
		switch v = st.step(underLoadTestStep, false, witnessed(i)); v {
		case underLoadProbeWait:
		case underLoadProbeResend:
			resends++
		default:
			return v, i, resends
		}
	}
	return underLoadProbeWait, max, resends
}

// Thirty seconds of witnessed listening, a ping a second, the last with its
// second to be answered: the stream is given up then and not a step sooner.
func TestUnderLoadProbeGivesUpAfterItsWindowOfWitnessedListening(t *testing.T) {
	var st underLoadProbeState
	v, at, resends := stepUntil(&st, 1000, func(int) bool { return true })
	want := int(underLoadProbeWindow / underLoadTestStep)
	if v != underLoadProbeDead || at != want {
		t.Fatalf("verdict %v at step %d, want dead at step %d", v, at, want)
	}
	// The first ping is the runner's, before any step; one more for every second
	// but the last.
	if wantResends := int(underLoadProbeWindow/wakeProbeResendEvery) - 1; resends != wantResends {
		t.Errorf("%d pings asked for on the way, want %d", resends, wantResends)
	}
	if st.listened != underLoadProbeWindow {
		t.Errorf("listened %v, want %v", st.listened, underLoadProbeWindow)
	}
}

// A second no other stream vouches for is not listening: with the path heard
// elsewhere only half the time, the window takes twice as long to fill — and a
// gap shorter than underLoadProbeQuiet does not end the probe.
func TestUnderLoadProbeCountsOnlyWitnessedSeconds(t *testing.T) {
	var st underLoadProbeState
	const block = 50 // 5 s heard elsewhere, 5 s not, and so on
	v, at, _ := stepUntil(&st, 2000, func(i int) bool { return ((i-1)/block)%2 == 0 })
	// Six witnessed blocks make the window; the sixth ends at 55 s of wall clock.
	if want := 11 * block; v != underLoadProbeDead || at != want {
		t.Fatalf("verdict %v at step %d, want dead at step %d", v, at, want)
	}
	if st.listened != underLoadProbeWindow {
		t.Errorf("listened %v, want %v", st.listened, underLoadProbeWindow)
	}
}

// The verdict is never reached on a step nobody vouches for, however much has
// been listened through: the path may have gone dark this very second.
func TestUnderLoadProbeGivesNoVerdictOnAnUnwitnessedStep(t *testing.T) {
	st := underLoadProbeState{listened: underLoadProbeWindow, sinceSend: wakeProbeResendEvery - underLoadTestStep}
	if v := st.step(underLoadTestStep, false, false); v != underLoadProbeResend {
		t.Fatalf("an unwitnessed step past the window: %v, want another ping", v)
	}
	// The ping that went out on it has its second, with a witness: now it is dead.
	v, _, _ := stepUntil(&st, int(wakeProbeResendEvery/underLoadTestStep), func(int) bool { return true })
	if v != underLoadProbeDead {
		t.Fatalf("after the witnessed second that followed: %v, want dead", v)
	}
}

// No witness for underLoadProbeQuiet in a row: the load is gone and the stream
// goes back to the detector. One witnessed step starts that count again.
func TestUnderLoadProbeLetsGoWhenTheLoadIsGone(t *testing.T) {
	quiet := int(underLoadProbeQuiet / underLoadTestStep)
	var st underLoadProbeState
	if v, at, _ := stepUntil(&st, 1000, func(int) bool { return false }); v != underLoadProbeIdle || at != quiet {
		t.Fatalf("verdict %v at step %d, want idle at step %d", v, at, quiet)
	}
	if st.listened != 0 {
		t.Errorf("listened %v through a silence of the whole path, want none", st.listened)
	}

	st = underLoadProbeState{}
	v, at, _ := stepUntil(&st, 1000, func(i int) bool { return i == quiet })
	if v != underLoadProbeIdle || at != 2*quiet {
		t.Fatalf("with a witness on step %d: verdict %v at step %d, want idle at step %d", quiet, v, at, 2*quiet)
	}
}

// A packet in ends the probe whatever else the step would have said; a step far
// longer than its timer is a freeze, and that is looked at before anything.
func TestUnderLoadProbeHearsBeforeItJudgesAndSeesAFreezeFirst(t *testing.T) {
	due := underLoadProbeState{listened: underLoadProbeWindow, sinceSend: wakeProbeResendEvery}
	st := due
	if v := st.step(underLoadTestStep, true, true); v != underLoadProbeHeard {
		t.Errorf("heard on the step that would have ended the stream: %v, want heard", v)
	}
	st = due
	if v := st.step(wakeProbeFreezeStep+time.Millisecond, false, true); v != underLoadProbeThawed {
		t.Errorf("a step longer than wakeProbeFreezeStep: %v, want thawed", v)
	}
	st = due
	if v := st.step(wakeProbeFreezeStep+time.Millisecond, true, true); v != underLoadProbeThawed {
		t.Errorf("a freeze with a packet in after it: %v, want thawed (the post-wake probe's)", v)
	}
	if st != due {
		t.Errorf("a frozen step was counted: %+v", st)
	}
}

// While the latest ping could not be written there is nothing out to be
// answered: the time is not listening, and no verdict comes of it.
func TestUnderLoadProbeDoesNotListenForAPingThatWasNotWritten(t *testing.T) {
	st := underLoadProbeState{owed: true}
	v, _, resends := stepUntil(&st, 1000, func(int) bool { return true })
	if v != underLoadProbeWait || resends != int(1000*underLoadTestStep/wakeProbeResendEvery) {
		t.Fatalf("verdict %v, %d pings asked for; want none, and a ping a second", v, resends)
	}
	if st.listened != 0 {
		t.Errorf("listened %v with no ping out", st.listened)
	}
	st = underLoadProbeState{listened: underLoadProbeWindow, sinceSend: wakeProbeResendEvery, owed: true}
	if v := st.step(underLoadTestStep, false, true); v != underLoadProbeResend {
		t.Errorf("window full, the last ping unwritten: %v, want another ping", v)
	}
}

// The witness: another ready UDP stream that has heard its relay just now.
func TestUnderLoadWitness(t *testing.T) {
	now := time.Now()
	mk := func(ready, overTCP bool, heard time.Time) *stream {
		s := &stream{}
		a := newStreamActivity(now.Add(-time.Minute), 0)
		a.noteRx(heard)
		s.activity.Store(a)
		s.ready.Store(ready)
		s.overTCP.Store(overTCP)
		return s
	}
	self := mk(true, false, now)
	fresh := now.Add(-silentUnderLoadEcho / 2)
	for name, c := range map[string]struct {
		other *stream
		want  bool
	}{
		"a stream heard just now":           {mk(true, false, fresh), true},
		"one heard too long ago":            {mk(true, false, now.Add(-silentUnderLoadEcho-time.Second)), false},
		"one over TCP":                      {mk(true, true, fresh), false},
		"one not ready":                     {mk(false, false, fresh), false},
		"one with no session":               {&stream{}, false},
		"nobody but the stream being asked": {self, false},
	} {
		if got := underLoadWitness(self, []*stream{self, c.other}, now); got != c.want {
			t.Errorf("%s: witness = %v, want %v", name, got, c.want)
		}
	}
}

// The probe is for a UDP stream whose verdict stands, with no freeze in the
// silence.
func TestUnderLoadProbeDue(t *testing.T) {
	now := time.Now()
	verdict := func() *streamActivity {
		a := newStreamActivity(now.Add(-10*time.Second), 0)
		a.markSilentUnderLoad(a.lastHeard.Load())
		return a
	}
	udp, tcp := &stream{}, &stream{}
	tcp.overTCP.Store(true)

	if !udp.underLoadProbeDue(verdict()) {
		t.Error("a UDP stream found silent under load is not probed")
	}
	if tcp.underLoadProbeDue(verdict()) {
		t.Error("a TCP stream is probed: the kernel gives such a flow up by itself")
	}
	if udp.underLoadProbeDue(newStreamActivity(now, 0)) {
		t.Error("a stream with no verdict is probed")
	}
	heard := verdict()
	heard.noteRx(now)
	if udp.underLoadProbeDue(heard) {
		t.Error("a stream heard since its verdict is probed")
	}
	froze := verdict()
	froze.resetLiveness(now)
	if udp.underLoadProbeDue(froze) {
		t.Error("a stream with a freeze in its silence is probed: that is the post-wake probe's")
	}
}

// --- the probe in the keepalive loop ------------------------------------------

func shrinkUnderLoadProbe(t *testing.T) {
	t.Helper()
	shrinkWakeProbe(t)
	w, q := underLoadProbeWindow, underLoadProbeQuiet
	underLoadProbeWindow, underLoadProbeQuiet = 300*time.Millisecond, 150*time.Millisecond
	t.Cleanup(func() { underLoadProbeWindow, underLoadProbeQuiet = w, q })
}

// withUnderLoadWitness makes another stream of the running proxy hear its
// relay for the whole test: its last packet is dated ahead, so its age reads
// zero whenever it is asked for.
func withUnderLoadWitness(t *testing.T) {
	t.Helper()
	w := &stream{id: 9}
	w.activity.Store(newStreamActivity(time.Now().Add(time.Hour), 0))
	w.ready.Store(true)
	set := []*stream{w}
	activeStreams.Store(&set)
	t.Cleanup(func() { activeStreams.Store(nil) })
}

// underLoadLoop runs runKeepalive on a stream heard just now, with send as its
// keepalive (nil: a write that succeeds) and probe as its sequenced ping.
func underLoadLoop(t *testing.T, overTCP bool, send func(tick int) error, probe func(seq uint64) error) (activity *streamActivity, errs chan error) {
	t.Helper()
	if send == nil {
		send = func(int) error { return nil }
	}
	s := &stream{id: 3}
	s.overTCP.Store(overTCP)
	activity = newStreamActivity(time.Now(), 0)
	errs = make(chan error, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runKeepalive(ctx, activity, func(err error) { errs <- err }, send, probe)
	}()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(20 * time.Millisecond) // let the loop park in its wait
	return activity, errs
}

func loopError(t *testing.T, errs chan error) error {
	t.Helper()
	select {
	case err := <-errs:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("the loop reported nothing")
		return nil
	}
}

// settled waits for the pings to stop coming and returns how many went out.
func settled(sent *sentPings) int {
	n := len(sent.all())
	for {
		time.Sleep(120 * time.Millisecond)
		m := len(sent.all())
		if m == n {
			return n
		}
		n = m
	}
}

// The bench of 2026-11-10: a relay goes mute under a download. The judge finds
// its stream silent, the stream asks the relay a ping a second, and with other
// streams hearing theirs it is ended after the probe's window — as a dead
// stream of the detector's kind, not as a socket the relay has forgotten.
func TestAStreamSilentUnderLoadIsAskedAndEnded(t *testing.T) {
	shrinkUnderLoadProbe(t)
	withUnderLoadWitness(t)
	var sent sentPings
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error { sent.add(seq); return nil })

	began := time.Now()
	activity.markSilentUnderLoad(activity.lastHeard.Load())
	err := loopError(t, errs)
	took := time.Since(began)

	var dead *deadStreamError
	if !errors.As(err, &dead) || !dead.underLoad || dead.probe || dead.froze {
		t.Fatalf("the loop reported %#v, want the verdict of the probe under load", err)
	}
	if took < underLoadProbeWindow || dead.listened < underLoadProbeWindow {
		t.Errorf("ended after %v with %v listened, want no less than the window of %v", took, dead.listened, underLoadProbeWindow)
	}
	if dead.silent < underLoadProbeWindow {
		t.Errorf("silent for %v, want the whole silence since the last packet", dead.silent)
	}
	pings := sent.all()
	if len(pings) < 4 {
		t.Errorf("only %d pings in a window of %v with one every %v", len(pings), underLoadProbeWindow, wakeProbeResendEvery)
	}
	for i, seq := range pings {
		if seq != uint64(i+1) {
			t.Fatalf("pings %v, want every seq once and in order", pings)
		}
	}
	if !strings.HasPrefix(err.Error(), "dead-stream: no answer to the probe under load") {
		t.Errorf("error text %q", err)
	}
	// Graded and re-dialled as the detector's dead stream is.
	if sessionOutOfReach(noBlackhole, err) {
		t.Error("read as a session out of the relay's reach: that is the post-wake probe's finding")
	}
	if !pathWideFailure(err) {
		t.Error("not read as a silence, as the detector's dead stream is")
	}
}

// Anything heard ends the probe and the verdict with it; the next silence under
// load is asked about anew.
func TestAnAnswerEndsTheProbeUnderLoad(t *testing.T) {
	shrinkUnderLoadProbe(t)
	withUnderLoadWitness(t)
	var sent sentPings
	var activity *streamActivity
	var answer atomic.Bool
	answer.Store(true)
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error {
		sent.add(seq)
		if seq == 3 && answer.Load() {
			go func() { time.Sleep(time.Millisecond); activity.noteRx(time.Now()) }()
		}
		return nil
	})

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	sent.waitFor(t, 3)
	n := settled(&sent)
	noError(t, errs)
	if n > 4 {
		t.Errorf("%d pings, want them to stop at the answer to the third", n)
	}
	if activity.foundSilentUnderLoad() {
		t.Error("the verdict still stands after a packet")
	}

	// A new silence, a new verdict, a new probe — this one to the end.
	answer.Store(false)
	activity.markSilentUnderLoad(activity.lastHeard.Load())
	var dead *deadStreamError
	if err := loopError(t, errs); !errors.As(err, &dead) || !dead.underLoad {
		t.Fatalf("the second silence: the loop reported %#v", err)
	}
	if got := sent.all(); len(got) <= n || got[n] != uint64(n+1) {
		t.Errorf("pings %v: the second probe's must go on from seq %d", got, n+1)
	}
}

// A token left by a verdict that a packet has since lifted wakes the loop for
// nothing.
func TestALiftedVerdictIsNotProbed(t *testing.T) {
	shrinkUnderLoadProbe(t)
	withUnderLoadWitness(t)
	var sent sentPings
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error { sent.add(seq); return nil })

	activity.silentUnderLoad.Store(activity.lastHeard.Load())
	activity.noteRx(time.Now())
	activity.underLoad <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	noError(t, errs)
	if got := sent.all(); len(got) != 0 {
		t.Errorf("pings %v for a verdict already lifted", got)
	}
}

// The accident of the same bench — a detector at 10 s rested eight healthy
// relays of an idle tunnel — is what the witness is for: with no other stream
// heard, the probe counts nothing, gives the stream back to the 90 s detector
// and does not start again for the same silence.
func TestWithNoStreamHeardElsewhereTheProbeLetsTheStreamBe(t *testing.T) {
	shrinkUnderLoadProbe(t)
	var sent sentPings
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error { sent.add(seq); return nil })

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	sent.waitFor(t, 2)
	n := settled(&sent)
	noError(t, errs)
	// underLoadProbeQuiet of pings, one every wakeProbeResendEvery — not the
	// window's worth, and none after.
	if limit := int(underLoadProbeWindow / wakeProbeResendEvery); n >= limit {
		t.Errorf("%d pings with no witness, want fewer than the window's %d", n, limit)
	}
	time.Sleep(2 * underLoadProbeWindow)
	noError(t, errs)
	if got := len(sent.all()); got != n {
		t.Errorf("%d more pings for a silence already asked about", got-n)
	}
}

// Over TCP the kernel gives a silent flow up by itself (relayTCPUserTimeout),
// and the deaf-relay judge counts no TCP session.
func TestATCPStreamIsNotProbedUnderLoad(t *testing.T) {
	shrinkUnderLoadProbe(t)
	withUnderLoadWitness(t)
	var sent sentPings
	activity, errs := underLoadLoop(t, true, nil, func(seq uint64) error { sent.add(seq); return nil })

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	time.Sleep(2 * underLoadProbeWindow)
	noError(t, errs)
	if got := sent.all(); len(got) != 0 {
		t.Errorf("pings %v on a TCP stream", got)
	}
}

// The stream's own keepalive goes out ahead of the first ping: it carries the
// session header, by which a server that forgot this stream takes it back.
func TestTheProbeUnderLoadSendsTheKeepaliveFirst(t *testing.T) {
	shrinkUnderLoadProbe(t)
	withUnderLoadWitness(t)
	var mu sync.Mutex
	var order []string
	note := func(what string) { mu.Lock(); order = append(order, what); mu.Unlock() }
	activity, errs := underLoadLoop(t, false,
		func(int) error { note("keepalive"); return nil },
		func(uint64) error { note("ping"); return nil })

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	loopError(t, errs)
	mu.Lock()
	defer mu.Unlock()
	// A grid point that fell before the verdict may have put a keepalive of the
	// loop's own in front; what matters is what stands right before the first ping.
	for i, what := range order {
		if what != "ping" {
			continue
		}
		if i == 0 || order[i-1] != "keepalive" {
			t.Fatalf("sent %v: the first ping went out with no keepalive before it", order)
		}
		return
	}
	t.Fatalf("sent %v: no ping at all", order)
}

// 90 s stays the ceiling: a probe whose witnessed seconds come too slowly hands
// the stream to the detector, which ends it in its own words.
func TestTheDetectorStaysTheCeilingOfTheProbeUnderLoad(t *testing.T) {
	shrinkUnderLoadProbe(t)
	underLoadProbeWindow = 10 * time.Second
	shortDeadStream(t, 200*time.Millisecond)
	withUnderLoadWitness(t)
	var sent sentPings
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error { sent.add(seq); return nil })

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	err := loopError(t, errs)
	var dead *deadStreamError
	if !errors.As(err, &dead) || dead.underLoad || dead.probe {
		t.Fatalf("the loop reported %#v, want the detector's dead stream", err)
	}
	if !strings.HasPrefix(err.Error(), "dead-stream: no RX for") {
		t.Errorf("error text %q", err)
	}
	if len(sent.all()) == 0 {
		t.Error("the probe never asked before the detector's time came")
	}
}

// A freeze inside the probe is not listening and not the probe's to judge: the
// liveness clock is reset, as at any thaw, and the post-wake probe asks the
// relay from there — here it hears nothing, and the verdict is its own.
func TestAFreezeInsideTheProbeUnderLoadIsThePostWakeProbes(t *testing.T) {
	shrinkUnderLoadProbe(t)
	underLoadProbeWindow = 10 * time.Second
	withUnderLoadWitness(t)
	var leap atomic.Int64
	wakeProbeClock = func() time.Time { return time.Now().Add(time.Duration(leap.Load())) }
	var sent sentPings
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error {
		sent.add(seq)
		if seq == 2 { // the process freezes a moment after the second ping is written
			go func() { time.Sleep(5 * time.Millisecond); leap.Store(int64(time.Minute)) }()
		}
		return nil
	})

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	err := loopError(t, errs)
	var dead *deadStreamError
	if !errors.As(err, &dead) || !dead.probe || dead.underLoad || !dead.froze {
		t.Fatalf("the loop reported %#v, want the post-wake probe's verdict with a freeze in the silence", err)
	}
}

// Pings that cannot be written are no listening: the probe gives up after
// wakeProbeSendRetries of them and the stream is left to the loop's retry.
func TestTheProbeUnderLoadGivesUpOnPingsItCannotWrite(t *testing.T) {
	shrinkUnderLoadProbe(t)
	withUnderLoadWitness(t)
	var sent sentPings
	activity, errs := underLoadLoop(t, false, nil, func(seq uint64) error {
		sent.add(seq)
		return errors.New("write: no buffer space available")
	})

	activity.markSilentUnderLoad(activity.lastHeard.Load())
	sent.waitFor(t, wakeProbeSendRetries)
	n := settled(&sent)
	time.Sleep(2 * underLoadProbeWindow)
	noError(t, errs)
	if n != wakeProbeSendRetries || len(sent.all()) != n {
		t.Errorf("%d pings tried (%d a while later), want %d and no more", n, len(sent.all()), wakeProbeSendRetries)
	}
}

// --- the deaf-relay judge -----------------------------------------------------

// Sessions ended by the probe under load count against their relay as the
// detector's do, under the same conditions: three of them with a stream on
// another relay heard through the silence rest the relay.
func TestSessionsEndedByTheProbeUnderLoadRestTheRelay(t *testing.T) {
	withCleanRelayDeaf(t)
	link := []string{deafRelay, witnessRelay}
	now := time.Now()
	liveStream(t, 1, witnessRelay, false, now.Add(-5*time.Minute), now.Add(-time.Second))

	deaf := &deadStreamError{silent: dispatchStaleAfter, underLoad: true, listened: underLoadProbeWindow}
	for i, id := range []int{8, 2, 0} {
		s, _ := deafStream(t, id, deafRelay, link, false)
		noteDeafSession(s, deafRelay, deafPeer, false, deaf, now, now.Add(time.Duration(i)*100*time.Millisecond))
		if resting := relayResting(deafRelay, now); resting != (i == 2) {
			t.Fatalf("after session %d ended by the probe under load: resting = %v", i+1, resting)
		}
	}
}

// And the same deaths leave the relay alone where the detector's would: with
// nothing heard on another relay, with a witness that came up only after the
// silence began, across a freeze, over TCP.
func TestTheProbeUnderLoadGivesTheDeafJudgeNoNewGrounds(t *testing.T) {
	link := []string{deafRelay, witnessRelay}
	const silent = 35 * time.Second
	deaf := &deadStreamError{silent: silent, underLoad: true, listened: underLoadProbeWindow}
	cases := map[string]struct {
		overTCP      bool
		witnessStart time.Duration // how long ago the stream on the other relay began; 0: none
		err          error
	}{
		"no witness":          {err: deaf},
		"a witness too young": {witnessStart: silent - 5*time.Second, err: deaf},
		"a freeze in it":      {witnessStart: 5 * time.Minute, err: &deadStreamError{silent: silent, underLoad: true, froze: true}},
		"over TCP":            {overTCP: true, witnessStart: 5 * time.Minute, err: deaf},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			withCleanRelayDeaf(t)
			now := time.Now()
			if c.witnessStart > 0 {
				liveStream(t, 1, witnessRelay, false, now.Add(-c.witnessStart), now.Add(-time.Second))
			}
			for i := 0; i < 2*relayDeafStrikes; i++ {
				s, _ := deafStream(t, 2*i, deafRelay, link, c.overTCP)
				noteDeafSession(s, deafRelay, deafPeer, false, c.err, now, now)
			}
			if relayResting(deafRelay, now) {
				t.Fatal("the relay is resting")
			}
		})
	}
}
