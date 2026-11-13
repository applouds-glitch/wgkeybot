/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"time"
)

// The probe under load: a UDP stream found silent under load (silent_under_load.go)
// asks its relay once a second whether it is still there, and is ended after
// thirty seconds of listening in which the path was heard elsewhere — about
// 35 s after its last packet instead of the detector's 90.
//
// WHY. The verdict of silence under load takes the stream out of the rotation
// within ~4 s, on both sides, and that was all: the stream itself stayed up,
// carrying nothing, until deadStreamTimeout. Bench of 2026-11-10 (Pixel 6a, UDP,
// ten streams on three relays, one relay with three of them muted 30 s into a
// download; info/bench/mute-20261109). On Rostelecom LTE the seven streams left
// reached the radio's ceiling and the 35-90 s window cost nothing. On a faster
// link (an iPhone hotspot, peaks of 16-22 Mbit/s) it did: seven streams ran at
// their own ceiling, 104-141 packets a second each and ~8 Mbit/s together, and
// the tunnel made 6.5 and 7.2 Mbit/s in that window with the detector at 90 s
// against 9.3 and 13.8 with it at 35 — three streams' worth of a link that had
// room for them, for 55 s per relay gone deaf.
//
// Not by lowering deadStreamTimeout. Two cells of that bench ran by mistake
// with a 10 s timeout on an IDLE tunnel: in three minutes the detector closed
// streams 80 times ("no RX for 10s" — the keepalive echo comes once in 25) and
// the deaf-relay judge rested eight healthy relays, each with a witness. An
// idle stream hears nothing but its echo, and its silence proves nothing
// sooner than three missed echoes; that stays the detector's, at 90 s. And at
// 35 s of wall clock an idle stream has missed two keepalive exchanges, which
// the field log of 2026-10-18/20 has 75 times in 30 hours with the stream back
// by itself (keepaliveEchoRetry).
//
// HOW. Under load there is more to go by than a missed echo:
//
//   - the verdict behind the probe: two siblings were each handed three chunks
//     while the server's round-robin passed this stream's slot at least twice,
//     and nothing came out of it;
//   - then a ping a second (stunProbe, the post-wake probe's, which the server
//     echoes verbatim): thirty of them, each with its second to be answered;
//   - and each of those seconds counts only if another ready UDP stream heard
//     its relay within silentUnderLoadEcho of it — the path, the server and the
//     process were all there to carry an answer. A second without such a
//     witness is not listening: a whole path gone dark adds nothing to the
//     count, however long it lasts.
//
// Anything heard — an echo, a data packet — ends the probe and the verdict with
// it (noteRx): a stream that lost an echo is back within a ping or two.
//
// The stream's own keepalive goes out first, and again at each grid point that
// passes inside the probe, as the loop would have sent it: it carries the
// session header, by which a server that has forgotten this stream alone takes
// it back, and that must stay the first thing tried.
//
// The probe gives the stream back to the detector, unended:
//
//   - when no witness has been heard for underLoadProbeQuiet in a row: the load
//     is gone, and without it this is an idle stream, the detector's;
//   - when the detector's own time has come (deadStreamTimeout since the last
//     packet): witnessed seconds may come slowly, and 90 s stays the ceiling;
//   - when the pings cannot be written (wakeProbeSendRetries in a row).
//
// A poll step far longer than its timer is a host freeze. A freeze is the
// post-wake probe's (wake_probe.go): the liveness clock is reset, as at any
// thaw, and that probe asks the relay from there.
//
// One probe per verdict, hence per silence. The judge wakes the stream's
// keepalive loop when it gives the verdict (streamActivity.underLoad) and the
// loop runs the probe in its own turn, as it runs the post-wake probe; a probe
// that gave the stream back is not started again for the same silence, so a
// tunnel gone idle is not pinged.
//
// The end is a deadStreamError through reportErr, as the detector's, so the
// session is graded and re-dialled the same way and counts toward resting a
// deaf relay (relay_deaf.go) under that judge's own conditions — a stream on
// ANOTHER relay heard through the silence, no freeze in it, no dark spell of
// the path. Not `probe`: that marks the post-wake probe's finding, a socket the
// relay may no longer know (sessionOutOfReach), which is not what was found
// here.
//
// UDP only. Over TCP the kernel gives a flow up when its segments go
// unacknowledged for relayTCPUserTimeout (30 s), the deaf-relay judge does not
// count TCP sessions at all, and the bench measured UDP alone.
//
// What it costs. A stream that would have come back by itself between the 36th
// and the 89th second is now re-dialled, and may be counted against its relay.
// In the field log of 2026-10-20 stream 6 came back twice from past 35 s
// (relay_deaf.go) — with one keepalive in 25 s and nothing else asked of the
// relay; here thirty pings stand between such a stream and its end. The bench
// logs hold 22 verdicts of silence under load and no return after one. And a
// stream alone on a relay that goes deaf under load time after time reaches
// the deaf judge's third session ~55 s a cycle sooner; relayDeafWindow held
// those three cycles already.

// Vars so that a test can shrink them; nothing else writes them.
var (
	// underLoadProbeWindow is the witnessed listening without an answer before
	// the stream is ended: the post-wake probe's thirty seconds, and with the
	// ~4 s the verdict took, dispatchStaleAfter — the age at which an idle
	// stream is first doubted is the age at which a loaded one is given up.
	underLoadProbeWindow = 30 * time.Second
	// underLoadProbeQuiet: this long without a witness in a row and the load is
	// gone. Above a pause in a download and the gap between two bursts of a
	// video; below keepaliveInterval, so that the echoes of an idle tunnel —
	// two seconds of witnesses in every twenty-five — do not keep a probe going.
	underLoadProbeQuiet = 10 * time.Second
)

type underLoadProbeVerdict int

const (
	underLoadProbeWait   underLoadProbeVerdict = iota // keep listening
	underLoadProbeResend                              // ask again now
	underLoadProbeHeard                               // the relay was heard: the stream lives
	underLoadProbeDead                                // the window listened through with witnesses, asked to the last, nothing heard
	underLoadProbeIdle                                // no witness for underLoadProbeQuiet: the load is gone
	underLoadProbeThawed                              // a freeze has just ended: the post-wake probe's
)

// underLoadProbeState is the probe's whole memory, added to step by step where
// it is observed, as wakeProbeState is.
type underLoadProbeState struct {
	listened  time.Duration // awake time waiting for an answer while a witness vouched for the path
	quiet     time.Duration // awake time in a row with no witness
	sinceSend time.Duration // awake time since the latest ping was written, or failed to be
	owed      bool          // the latest ping could not be written: nothing that may be answered is out
	pings     int
}

// step takes one poll step — how long it lasted, whether the stream's relay has
// been heard, and whether another stream vouches for the path as the step ends
// — and says what to do. The freeze is checked first, then the answer: no
// verdict is reached past a packet that is already in, and none on a step no
// witness vouches for.
func (s *underLoadProbeState) step(took time.Duration, heard, witnessed bool) underLoadProbeVerdict {
	if took > wakeProbeFreezeStep {
		return underLoadProbeThawed
	}
	if heard {
		return underLoadProbeHeard
	}
	s.sinceSend += took
	if witnessed {
		s.quiet = 0
		if !s.owed {
			s.listened += took
		}
	} else {
		s.quiet += took
		if s.quiet >= underLoadProbeQuiet {
			return underLoadProbeIdle
		}
	}
	if s.sinceSend < wakeProbeResendEvery {
		return underLoadProbeWait
	}
	// The latest ping has had its second.
	if witnessed && !s.owed && s.listened >= underLoadProbeWindow {
		return underLoadProbeDead
	}
	s.sinceSend = 0
	return underLoadProbeResend
}

// underLoadWitness reports whether a ready UDP stream other than self has heard
// its relay within silentUnderLoadEcho: the path carries answers now. Any
// relay's stream does, self's own included — a sibling heard on the same relay
// says the more plainly that it is this stream that is gone.
func underLoadWitness(self *stream, streams []*stream, now time.Time) bool {
	for _, w := range streams {
		if w == self || !w.ready.Load() || w.overTCP.Load() {
			continue
		}
		if a := w.activity.Load(); a != nil && a.heardAge(now) < silentUnderLoadEcho {
			return true
		}
	}
	return false
}

// underLoadProbeDue: is the stream the judge has just woken to be probed? Only
// while the verdict stands (a packet since has lifted it), only over UDP, and
// not with a freeze in the silence — the judge gives no verdict across one,
// and one that came after it is the post-wake probe's.
func (s *stream) underLoadProbeDue(activity *streamActivity) bool {
	return !s.overTCP.Load() && activity.foundSilentUnderLoad() && !activity.frozeSinceHeard()
}

type underLoadProbeEnd int

const (
	underLoadEndHeard   underLoadProbeEnd = iota // the relay was heard
	underLoadEndIdle                             // the load is gone: the detector's
	underLoadEndCeiling                          // deadStreamTimeout has come: the detector's
	underLoadEndThawed                           // a freeze inside the probe: the post-wake probe's
	underLoadEndDead                             // the stream is to be ended
)

// runUnderLoadProbe is the probe, run by the keepalive loop in its own turn
// once the judge has woken it. seq is the loop's ping counter and ping writes
// one sequenced ping (stunProbe); keepalive sends the stream's own keepalive as
// the loop does. It returns how the probe ended and the witnessed listening it
// took, or an error when the pings could not be written or ctx is done.
func (s *stream) runUnderLoadProbe(ctx context.Context, activity *streamActivity, seq *uint64, ping func(seq uint64) error, keepalive func() error) (end underLoadProbeEnd, listened time.Duration, err error) {
	var st underLoadProbeState
	sendFails := 0
	// A ping is sent when its write is over, and the step — its second, the
	// listening — starts there (runWakeProbe).
	var stepStart time.Time
	send := func() error {
		*seq++
		activity.probeSent.Store(*seq)
		err := ping(*seq)
		stepStart = wakeProbeClock()
		if err != nil {
			sendFails++
			st.owed = true
			if sendFails >= wakeProbeSendRetries {
				return err
			}
			turnLog("[STREAM %d] probe under load: ping send error: %v — asking again in %v", s.id, err, wakeProbeResendEvery)
			return nil
		}
		sendFails = 0
		st.owed = false
		st.pings++
		return nil
	}
	// The stream's own keepalive first, session header and all, and again at
	// each grid point: what the loop would have sent had it not been here. A
	// failed write of it is the pings' to notice.
	gridAt := nextKeepaliveGrid(time.Now(), activity.phase)
	if kErr := keepalive(); kErr != nil {
		turnLog("[STREAM %d] keepalive send error: %v", s.id, kErr)
	}
	if err := send(); err != nil {
		return 0, 0, err
	}
	timer := time.NewTimer(wakeProbePoll)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return 0, st.listened, ctx.Err()
		}
		now := wakeProbeClock()
		took := now.Sub(stepStart)
		stepStart = now
		switch st.step(took, !activity.foundSilentUnderLoad(), underLoadWitness(s, activeStreamSet(), now)) {
		case underLoadProbeHeard:
			turnLog("[STREAM %d] probe under load: the relay was heard after %v of listening (%d pings) — keeping the stream",
				s.id, st.listened.Round(100*time.Millisecond), st.pings)
			return underLoadEndHeard, st.listened, nil
		case underLoadProbeThawed:
			turnLog("[STREAM %d] probe under load: a step of %v, a freeze — left to the post-wake probe (%v listened, %d pings)",
				s.id, took.Round(100*time.Millisecond), st.listened.Round(time.Second), st.pings)
			return underLoadEndThawed, st.listened, nil
		case underLoadProbeIdle:
			turnLog("[STREAM %d] probe under load: no other stream heard for %v, the load is gone — left to the %v detector (%v listened, %d pings)",
				s.id, underLoadProbeQuiet, deadStreamAfter(now), st.listened.Round(time.Second), st.pings)
			return underLoadEndIdle, st.listened, nil
		case underLoadProbeDead:
			turnLog("[STREAM %d] probe under load: no answer to %d pings in %v of listening while other streams heard their relays, relay silent for %v — closing",
				s.id, st.pings, st.listened.Round(time.Second), activity.heardAge(now).Round(time.Second))
			return underLoadEndDead, st.listened, nil
		case underLoadProbeResend:
			// The detector's time: it ends the stream at the loop's next turn,
			// in its own words, as it always has.
			if activity.rxAge(now) >= deadStreamAfter(now) {
				return underLoadEndCeiling, st.listened, nil
			}
			if real := time.Now(); !real.Before(gridAt) {
				gridAt = nextKeepaliveGrid(real, activity.phase)
				sendWireGuardKeepaliveOnSharedGrid(real)
				if kErr := keepalive(); kErr != nil {
					turnLog("[STREAM %d] keepalive send error: %v", s.id, kErr)
				}
			}
			if err := send(); err != nil {
				return 0, st.listened, err
			}
		}
		timer.Reset(wakeProbePoll)
	}
}
