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

// The post-wake probe (wake_probe.go), a port of anton48/vk-turn-proxy-ios
// build 422–427. The thresholds in the rule's tests are LITERALS on purpose: a
// test that derives them from the constants stays green when a constant is
// halved.

func TestWakeProbeStepIsFactsAndListening(t *testing.T) {
	const ms = time.Millisecond
	t.Run("any pong of the probe's own pings answers it — the first one's too, not only the last", func(t *testing.T) {
		for _, pong := range []uint64{46, 47, 50} {
			s := wakeProbeState{first: 46, resends: 3}
			if v := s.step(100*ms, pong); v != wakeProbeEchoed {
				t.Errorf("pong %d against a probe whose first ping was 46: verdict %d, want echoed", pong, v)
			}
		}
	})
	t.Run("a mark below the probe's first ping answers nothing", func(t *testing.T) {
		s := wakeProbeState{first: 46}
		if v := s.step(100*ms, 45); v != wakeProbeWait {
			t.Errorf("pong 45 against first 46: verdict %d, want wait", v)
		}
	})
	t.Run("asked again after one second of listening", func(t *testing.T) {
		s := wakeProbeState{first: 1}
		for i := 1; i <= 9; i++ {
			if v := s.step(100*ms, 0); v != wakeProbeWait {
				t.Fatalf("step %d (%.1f s listened): verdict %d, want wait", i, s.listened.Seconds(), v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeResend {
			t.Fatalf("at 1.0 s of listening: verdict %d, want a re-send", v)
		}
		if s.resends != 1 || s.sinceSend != 0 {
			t.Errorf("after the re-send: resends %d sinceSend %s, want 1 and 0", s.resends, s.sinceSend)
		}
	})
	t.Run("a frozen step is not listening, and is followed by a ping at once", func(t *testing.T) {
		s := wakeProbeState{first: 1, listened: 2 * time.Second, sinceSend: 400 * ms}
		if v := s.step(57*time.Second, 0); v != wakeProbeThawed {
			t.Fatalf("a 57-s step: verdict %d, want thawed — a ping at once", v)
		}
		if s.listened != 2*time.Second {
			t.Errorf("listened %s after a frozen step, want it unchanged at 2s — the process could not hear", s.listened)
		}
		if s.freezes != 1 || s.sinceSend != 0 {
			t.Errorf("freezes %d sinceSend %s, want 1 and 0", s.freezes, s.sinceSend)
		}
	})
	t.Run("an answer that is already in when a frozen step ends is from BEFORE the freeze: asked again, not believed", func(t *testing.T) {
		s := wakeProbeState{first: 46, listened: 300 * ms}
		if v := s.step(150*time.Second, 46); v != wakeProbeThawed {
			t.Errorf("a 150-s step with pong 46 in: verdict %d, want thawed — a mapping goes in a sleep like that", v)
		}
	})
	t.Run("the verdict takes thirty seconds of LISTENING — not one step sooner", func(t *testing.T) {
		s := wakeProbeState{first: 1}
		for i := 1; i <= 299; i++ {
			if v := s.step(100*ms, 0); v == wakeProbeDead || v == wakeProbeEchoed {
				t.Fatalf("step %d (%.1f s listened): verdict %d before thirty seconds", i, s.listened.Seconds(), v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeDead {
			t.Fatalf("at 30.0 s of listening with nothing heard: verdict %d, want dead", v)
		}
		if s.resends != 29 {
			t.Errorf("asked again %d times in thirty seconds, want 29 (once a second)", s.resends)
		}
	})
	t.Run("the last look: an answer that is in when the verdict is due wins", func(t *testing.T) {
		s := wakeProbeState{first: 7, listened: 29900 * ms, sinceSend: 900 * ms}
		if v := s.step(100*ms, 7); v != wakeProbeEchoed {
			t.Errorf("verdict %d, want echoed — the mark is read before the verdict", v)
		}
	})
	t.Run("no verdict before the latest ping has had its second", func(t *testing.T) {
		s := wakeProbeState{first: 1, listened: 29950 * ms, sinceSend: 950 * ms}
		if v := s.step(90*time.Second, 0); v != wakeProbeThawed {
			t.Fatalf("the frozen step: verdict %d, want thawed", v)
		}
		for i := 1; i <= 9; i++ {
			if v := s.step(100*ms, 0); v != wakeProbeWait {
				t.Fatalf("%d00 ms after the thaw's ping: verdict %d, want wait", i, v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeDead {
			t.Errorf("a full second after the thaw's ping, thirty seconds listened: verdict %d, want dead", v)
		}
	})
	t.Run("while a fresh ping is OWED there is no verdict, and the pause is not listening", func(t *testing.T) {
		s := wakeProbeState{first: 5, owed: true, listened: 29950 * ms}
		for i := 1; i <= 9; i++ {
			if v := s.step(100*ms, 0); v != wakeProbeWait {
				t.Fatalf("%d00 ms into the pause: verdict %d, want wait", i, v)
			}
		}
		if v := s.step(100*ms, 0); v != wakeProbeResend {
			t.Fatalf("a second after the three crossed writes, the window long run out: verdict %d, want the owed ping sent — never dead", v)
		}
		if s.listened != 29950*ms {
			t.Errorf("listened %s, want it unchanged at 29.95s — nothing that could be heard was out", s.listened)
		}
	})
	t.Run("while a fresh ping is owed no pong answers — nothing sent so far may", func(t *testing.T) {
		s := wakeProbeState{first: 4, owed: true}
		if v := s.step(100*ms, 4); v != wakeProbeWait {
			t.Errorf("pong 4 with the fresh ping still owed: verdict %d, want wait", v)
		}
	})
}

// Their night of 2026-09-19: the process runs about two seconds per wake and is
// frozen for minutes in between. A wall-clock deadline killed at the first
// thaw; this rule counts only what it could hear.
func TestANightOfShortWakesKillsNobodyWhoCouldNotHear(t *testing.T) {
	const ms = time.Millisecond
	s := wakeProbeState{first: 1}
	var wall time.Duration
	wake := func(pongAtEnd uint64) wakeProbeVerdict {
		for i := 0; i < 20; i++ { // two seconds awake
			wall += 100 * ms
			if v := s.step(100*ms, 0); v == wakeProbeDead || v == wakeProbeEchoed {
				return v
			}
		}
		wall += 140 * time.Second // frozen
		return s.step(140*time.Second, pongAtEnd)
	}
	for n := 1; n <= 10; n++ {
		if v := wake(0); v != wakeProbeThawed {
			t.Fatalf("wake %d (wall %s, listened %s): verdict %d at the thaw, want thawed", n, wall, s.listened, v)
		}
	}
	if s.listened != 20*time.Second {
		t.Errorf("listened %s over ten two-second wakes, want 20s", s.listened)
	}
	s.first = 30 // the caller re-bases the probe on the ping it sent at the last thaw
	if v := s.step(100*ms, 30); v != wakeProbeEchoed {
		t.Errorf("the pong of the thaw's ping at last: verdict %d, want echoed", v)
	}
	// The control: a stream that never answers IS ended — after thirty seconds it could hear.
	s = wakeProbeState{first: 1}
	wakes := 0
	for {
		wakes++
		if v := wake(0); v == wakeProbeDead {
			break
		} else if v == wakeProbeEchoed || wakes > 40 {
			t.Fatalf("wake %d: verdict %d — a silent stream must end dead", wakes, v)
		}
	}
	if wakes != 15 || s.listened != 30*time.Second {
		t.Errorf("dead at wake %d with %s listened, want wake 15 and exactly 30s — fifteen two-second wakes", wakes, s.listened)
	}
}

// The ping is the plain 20-byte STUN keepalive the server echoes verbatim, with
// the seq where the server does not look; the echo names its ping, and the
// mark it moves never moves back.
func TestStunProbeEchoNamesItsPing(t *testing.T) {
	p := stunProbe(0x0102030405060708)
	if !isStunKeepalive(p) {
		t.Fatal("a probe is not a STUN keepalive to the client's own RX path")
	}
	if isFeedbackPacket(p) {
		t.Fatal("a probe reads as a WGH1 control frame")
	}
	if got := stunProbeSeq(p); got != 0x0102030405060708 {
		t.Fatalf("seq round trip: %x", got)
	}
	if got := stunProbeSeq(stunBindingIndication); got != 0 {
		t.Fatalf("the plain keepalive names seq %d, want 0", got)
	}
	a := newStreamActivity(time.Now(), 0)
	a.probeSent.Store(9)
	a.notePong(7)
	a.notePong(5)
	if a.pongMark() != 7 {
		t.Fatalf("a late echo moved the mark back to %d", a.pongMark())
	}
	a.notePong(9)
	if a.pongMark() != 9 {
		t.Fatalf("mark %d, want 9", a.pongMark())
	}
}

func shrinkWakeProbe(t *testing.T) {
	t.Helper()
	w, r, po, f, j, th, re, c := wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeJitter, wakeProbeThrottle, wakeProbeRecentEcho, wakeProbeClock
	wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeJitter, wakeProbeThrottle, wakeProbeRecentEcho =
		300*time.Millisecond, 30*time.Millisecond, 3*time.Millisecond, 10*time.Second, time.Millisecond, 0, 0
	t.Cleanup(func() {
		wakeProbeWindow, wakeProbeResendEvery, wakeProbePoll, wakeProbeFreezeStep, wakeProbeJitter, wakeProbeThrottle, wakeProbeRecentEcho, wakeProbeClock = w, r, po, f, j, th, re, c
	})
}

type sentPings struct {
	mu   sync.Mutex
	seqs []uint64
}

func (s *sentPings) add(seq uint64) { s.mu.Lock(); s.seqs = append(s.seqs, seq); s.mu.Unlock() }
func (s *sentPings) all() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.seqs...)
}

func (s *sentPings) waitFor(t *testing.T, n int) []uint64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.all(); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %v sent, want %d pings", s.all(), n)
	return nil
}

// probeLoop runs runKeepalive on a stream whose relay was last heard heardAgo
// ago, with probe as its sequenced ping; the loop's errors land on errs.
func probeLoop(t *testing.T, heardAgo time.Duration, probe func(seq uint64) error) (activity *streamActivity, errs chan error, stop func()) {
	t.Helper()
	activity = newStreamActivity(time.Now().Add(-heardAgo), 0)
	errs = make(chan error, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&stream{id: 3}).runKeepalive(ctx, activity, func(err error) { errs <- err }, func(int) error { return nil }, probe)
	}()
	stop = func() { cancel(); <-done }
	t.Cleanup(stop)
	// A wake broadcast before the loop has taken its first look at the epoch
	// is not this session's to serve (newWakeWatch); let it park first.
	time.Sleep(20 * time.Millisecond)
	return activity, errs, stop
}

func noError(t *testing.T, errs chan error) {
	t.Helper()
	select {
	case err := <-errs:
		t.Fatalf("the loop reported %v", err)
	default:
	}
}

// Their 2026-09-20, both fatal wakes: the ping never left the phone. A wake()
// probes the stream, the lost first ping is asked again, and the stream lives.
func TestAWakeProbesAndALostPingIsAskedAgain(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		if seq >= 2 { // the first ping is lost on the way out; the relay answers from the second on
			go func() { time.Sleep(time.Millisecond); activity.notePong(seq) }()
		}
		return nil
	})
	broadcastHostWake()
	got := sent.waitFor(t, 2)
	time.Sleep(50 * time.Millisecond)
	noError(t, errs)
	if got[0] != 1 || got[1] != 2 {
		t.Errorf("pings sent %v, want 1 and then 2", got)
	}
}

// The pong of the probe's FIRST ping answers it, however many were sent after.
func TestAPongOfTheFirstPingAnswersAfterLaterPings(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		if seq == 3 { // the pong of ping ONE arrives late — after two re-sends, none of which is ever answered
			go func() { time.Sleep(time.Millisecond); activity.notePong(1) }()
		}
		return nil
	})
	broadcastHostWake()
	sent.waitFor(t, 3)
	time.Sleep(60 * time.Millisecond)
	noError(t, errs)
	if n := len(sent.all()); n > 4 {
		t.Errorf("%d pings sent after pong 1 had answered — the probe did not stop", n)
	}
}

// The process running, the window listened through, nothing heard: the stream
// is ended with the typed error, which no classifier reads as credentials.
func TestASilentStreamIsEndedAfterTheWindowOfListening(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	_, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error { sent.add(seq); return nil })
	t0 := time.Now()
	broadcastHostWake()
	select {
	case err := <-errs:
		var dead *deadStreamError
		if !errors.As(err, &dead) || !dead.probe {
			t.Fatalf("the loop reported %v, want the probe's dead-stream error", err)
		}
		if !strings.HasPrefix(err.Error(), "dead-stream: no echo to the post-wake probe") {
			t.Fatalf("the error reads %q", err)
		}
		if classifyCredError(err) || isTransportError(err) {
			t.Fatalf("%q was classified as a credential or transport error", err)
		}
		if el := time.Since(t0); el < 300*time.Millisecond {
			t.Errorf("ended after %s, before the window (300ms here) had been listened through", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a silent stream was not ended")
	}
	if n := len(sent.all()); n < 5 {
		t.Errorf("%d pings in the window, want the probe asked again and again", n)
	}
}

// wake() comes in bursts: a stream probed a moment ago is not probed again.
func TestAWakeWithinTheThrottleIsNotProbedTwice(t *testing.T) {
	shrinkWakeProbe(t)
	wakeProbeThrottle = time.Second
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		go func() { time.Sleep(time.Millisecond); activity.notePong(seq) }()
		return nil
	})
	broadcastHostWake()
	sent.waitFor(t, 1)
	time.Sleep(20 * time.Millisecond)
	broadcastHostWake()
	time.Sleep(50 * time.Millisecond)
	noError(t, errs)
	if got := sent.all(); len(got) != 1 {
		t.Errorf("pings sent %v, want the first wake's alone", got)
	}
}

// A stream that has just heard its relay has nothing to ask.
func TestAStreamThatJustEchoedIsNotProbed(t *testing.T) {
	shrinkWakeProbe(t)
	wakeProbeRecentEcho = 5 * time.Second
	var sent sentPings
	_, errs, _ := probeLoop(t, 0, func(seq uint64) error { sent.add(seq); return nil })
	broadcastHostWake()
	time.Sleep(50 * time.Millisecond)
	noError(t, errs)
	if got := sent.all(); len(got) != 0 {
		t.Errorf("pings sent %v, want none", got)
	}
}

// The dispatcher trusts a stream on a real echo. A thaw resets the detector's
// clock for every stream at once; it must not put a stream whose mapping died
// in the freeze back into the rotation for 35 s.
func TestDispatchTrustsARealEchoNotTheFreezeReset(t *testing.T) {
	now := time.Now()
	s := &stream{id: 5}
	a := newStreamActivity(now.Add(-time.Minute), 0)
	s.activity.Store(a)
	if !s.dispatchStale(now) {
		t.Fatal("a stream silent for a minute is not stale")
	}
	a.resetLiveness(now)
	if !s.dispatchStale(now) {
		t.Fatal("the freeze reset made a silent stream look heard")
	}
	a.noteRx(now)
	if s.dispatchStale(now) {
		t.Fatal("a real echo did not bring the stream back")
	}
}

// A freeze inside the probe (their build 425): the wall clock leaps ninety
// seconds while the probe listens. It is not listening — the stream lives,
// asked again at the thaw — and it is a freeze the loop never saw, so the
// probe resets the detector's clock and stamps the thaw itself (review of
// 2026-09-28: without that the 90-s detector closed the stream the moment the
// probe handed the turn back).
func TestAFreezeInsideTheProbeIsNotSilence(t *testing.T) {
	shrinkWakeProbe(t)
	wakeProbeFreezeStep = 5 * time.Second
	var leap atomic.Int64
	wakeProbeClock = func() time.Time { return time.Now().Add(time.Duration(leap.Load())) }
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		switch seq {
		case 1: // the process freezes a moment AFTER its first ping has been written
			go func() { time.Sleep(5 * time.Millisecond); leap.Store(int64(90 * time.Second)) }()
		case 2:
			go func() { time.Sleep(time.Millisecond); activity.notePong(2) }() // the thaw's ping is answered
		}
		return nil
	})
	broadcastHostWake()
	sent.waitFor(t, 2)
	time.Sleep(60 * time.Millisecond)
	noError(t, errs)
	if age := activity.rxAge(time.Now()); age > 30*time.Second {
		t.Errorf("the detector's clock still reads %v after a freeze inside the probe, want it reset", age)
	}
}

// Their build 426: a wake that crosses a ping's write voids whatever was
// heard before it — the pong of THAT ping answers nothing, the probe is
// re-based on a fresh one.
func TestAWakeCrossingThePingWriteVoidsWhatWasHeard(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		switch seq {
		case 1:
			broadcastHostWake()                                                // the phone slept and woke while ping 1 was being written
			go func() { time.Sleep(time.Millisecond); activity.notePong(1) }() // … and ping 1's pong comes back
		case 3:
			go func() { time.Sleep(time.Millisecond); activity.notePong(3) }()
		}
		return nil
	})
	broadcastHostWake()
	got := sent.waitFor(t, 3) // pong 1 answered nothing: the probe went on asking until seq 3 was echoed
	time.Sleep(60 * time.Millisecond)
	noError(t, errs)
	if got[0] != 1 || got[1] != 2 {
		t.Errorf("pings %v, want a fresh ping 2 right after the wake crossed ping 1's write", got)
	}
}

// Their build 427: wake upon wake across three writes leaves the fresh ping
// OWED — no verdict while it is, and it goes out after a second's pause.
func TestAnOwedPingIsPaidAndAnswersTheProbe(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		if seq <= 3 {
			broadcastHostWake() // a wake crosses each of the first three writes
		} else {
			go func() { time.Sleep(time.Millisecond); activity.notePong(seq) }()
		}
		return nil
	})
	broadcastHostWake()
	got := sent.waitFor(t, 4)
	time.Sleep(60 * time.Millisecond)
	noError(t, errs)
	if got[3] != 4 {
		t.Errorf("pings %v, want the owed ping 4 paid after the pause", got)
	}
}

// A write that fails inside the probe (the radio coming up drops outbound
// datagrams) is asked again a second later, not handed to the detector.
func TestASendErrorInsideTheProbeIsRetried(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		switch seq {
		case 2:
			return errors.New("write udp: network is unreachable")
		case 3:
			go func() { time.Sleep(time.Millisecond); activity.notePong(3) }()
		}
		return nil
	})
	broadcastHostWake()
	got := sent.waitFor(t, 3)
	time.Sleep(60 * time.Millisecond)
	noError(t, errs)
	if got[1] != 2 || got[2] != 3 {
		t.Errorf("pings %v, want 2 (failed) then 3", got)
	}
}

// An echo names a ping that was sent; a foreign 20-byte STUN message from the
// relay peer, or a seq beyond the probe's, moves the mark nowhere.
func TestAForeignStunDoesNotMoveTheMark(t *testing.T) {
	a := newStreamActivity(time.Now(), 0)
	a.probeSent.Store(2)
	a.notePong(5)
	if a.pongMark() != 0 {
		t.Fatalf("a seq beyond what was sent moved the mark to %d", a.pongMark())
	}
	foreign := stunProbe(2)
	foreign[9] = 0x7f // a transaction ID of somebody else's making
	a.noteProbeEcho(foreign)
	if a.pongMark() != 0 {
		t.Fatalf("a STUN message of another shape moved the mark to %d", a.pongMark())
	}
	a.noteProbeEcho(stunProbe(2))
	if a.pongMark() != 2 {
		t.Fatalf("our own echo did not move the mark: %d", a.pongMark())
	}
}

// A relay heard after the probe's ping — data, an unsequenced echo — proves
// the path even where the sequenced echo never comes: a server that does not
// echo our seq must not cost a working stream.
func TestTrafficHeardAfterThePingKeepsTheStream(t *testing.T) {
	shrinkWakeProbe(t)
	var sent sentPings
	var activity *streamActivity
	activity, errs, _ := probeLoop(t, time.Minute, func(seq uint64) error {
		sent.add(seq)
		if seq == 1 {
			go func() { time.Sleep(5 * time.Millisecond); activity.noteRx(time.Now()) }()
		}
		return nil
	})
	broadcastHostWake()
	time.Sleep(500 * time.Millisecond) // past the (shrunk) window
	noError(t, errs)
}

// The spread is a random share of wakeProbeJitter, and ends at once when the
// stream's context does.
func TestWakeProbeSpreadIsBoundedAndCancellable(t *testing.T) {
	shrinkWakeProbe(t)
	wakeProbeJitter = 20 * time.Millisecond
	t0 := time.Now()
	if !wakeProbeSpread(context.Background()) {
		t.Fatal("a live context reported cancelled")
	}
	if el := time.Since(t0); el > 200*time.Millisecond {
		t.Errorf("spread took %s, want a share of 20ms", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wakeProbeJitter = time.Second
	t0 = time.Now()
	if wakeProbeSpread(ctx) {
		t.Fatal("a cancelled context reported live")
	}
	if el := time.Since(t0); el > 200*time.Millisecond {
		t.Errorf("a cancelled context waited %s", el)
	}
	wakeProbeJitter = 0
	if !wakeProbeSpread(context.Background()) {
		t.Fatal("no jitter must mean no wait, not cancelled")
	}
}
