/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// The post-wake probe — a port of anton48/vk-turn-proxy-ios wakeprobe.go
// (builds 422–427, HEAD 001caf2), run by runKeepalive rather than by a probe
// goroutine of its own.
//
// iOS freezes its extension for minutes at a time; the iOS journal of 2026-09-28
// has freezes of 2m24s and 3m57s on Wi-Fi, and their field logs a night when
// the process ran two seconds per wake. Across such a silence a home router
// forgets the UDP flow, the socket comes back under a new mapping, and the
// relay — which still holds the allocation under the OLD 5-tuple — answers
// this socket as one that has no allocation (their outofreach.go, stand-measured
// 2026-09-21): the stream is dead at the relay from the first packet after the
// thaw, while its liveness clock, just reset by the thaw (resetLiveness), says
// nothing is wrong for another 90 s, and the dispatcher trusts it for 35.
//
// So at every thaw the keepalive loop has seen, and at every wake() Swift
// announces, each stream asks its relay whether it is still there, and judges
// the answer by what the running process could HEAR, never by the clock:
//
//   - one ping now; asked again after every second of listening;
//   - a poll step that took far longer than its timer is a freeze: none of it
//     is listening, an answer already in is from before the freeze and counts
//     for nothing, and a fresh ping goes out at once;
//   - any echo of a ping sent since the probe (re)started answers it — the
//     first ping's too, however many were sent after: the STUN Binding
//     Indication carries the ping's seq in its transaction ID and the server
//     echoes the 20 bytes verbatim, so an echo names the ping it answers;
//   - the verdict — dead — takes thirty seconds of listening and comes only
//     once the latest ping has had its second and the mark has been read;
//   - a wake that crosses a ping's write voids whatever was heard before it;
//     wake upon wake across three writes leaves the fresh ping OWED, and until
//     it has gone out and had its second there is no verdict to reach.
//
// A stream found dead is ended with deadStreamError, as by the periodic
// detector, and re-dialled by runWithCreds — thirty seconds of listening after
// the thaw instead of ninety of wall clock, and the dispatcher stops trusting
// it the moment its siblings echo (dispatchStale reads the real echo).
//
// Android: the process is not frozen by the system the way an iOS extension
// is, but Doze without the battery-optimization exemption and the OEM app
// freezers (MIUI/HyperOS, Huawei) stop it all the same, and the loop's own
// freeze detection (runKeepalive, freezeSlack) then runs the probe. A freeze
// shorter than that slack is invisible to the loop, so the unlock of the device
// broadcasts a wake as well (wgTurnProxyWake ← ACTION_USER_PRESENT): the moment
// the user expects the tunnel to work, and the moment the radio is up anyway.

// Vars so that a test can shrink them; nothing else writes them.
var (
	wakeProbeWindow      = 30 * time.Second       // LISTENING without an answer before the verdict
	wakeProbeResendEvery = time.Second            // listening between two pings of one probe
	wakeProbePoll        = 100 * time.Millisecond // how often the mark is looked at
	wakeProbeFreezeStep  = time.Second            // a poll step longer than this was a freeze, not listening
	wakeProbeJitter      = 300 * time.Millisecond // a thaw's or a wake's burst of every stream is spread over this much
	wakeProbeThrottle    = 30 * time.Second       // a stream probed this recently is not probed again for a wake()
	wakeProbeRecentEcho  = 5 * time.Second        // a stream that heard its relay this recently needs no probe
	wakeProbeClock       = time.Now
)

// hostWake is Swift's wake(), fanned out to every keepalive loop. The channel
// wakes a loop parked in its wait; the epoch — bumped under the lock before the
// swap — is for a loop that was elsewhere at that instant (sending, probing):
// it compares the epoch it has served at the top of every turn. A level, not
// an edge (their build 424: two wakes of twelve went unprobed on all thirty
// connections when the signal was the channel alone).
var hostWake = struct {
	mu    sync.Mutex
	epoch atomic.Uint64
	ch    chan struct{}
}{ch: make(chan struct{})}

// broadcastHostWake fans a wake out to every keepalive loop (iOS: Swift's
// wake(); Android: the device unlock, wgTurnProxyWake).
func broadcastHostWake() {
	hostWake.mu.Lock()
	hostWake.epoch.Add(1)
	close(hostWake.ch)
	hostWake.ch = make(chan struct{})
	hostWake.mu.Unlock()
}

// hostWakeChannel is the channel the next broadcast closes. Read once per turn
// of the loop, before the epoch is compared.
func hostWakeChannel() <-chan struct{} {
	hostWake.mu.Lock()
	ch := hostWake.ch
	hostWake.mu.Unlock()
	return ch
}

func hostWakeEpoch() uint64 { return hostWake.epoch.Load() }

// wakeWatch is one keepalive loop's view of the wake signal: the epoch it has
// served. A wake that came before the session existed is not its to serve.
type wakeWatch struct{ served uint64 }

func newWakeWatch() wakeWatch { return wakeWatch{served: hostWakeEpoch()} }

func (w *wakeWatch) pending() bool { return hostWakeEpoch() != w.served }

// stunProbe is a STUN Binding Indication whose transaction ID carries the
// ping's seq in its last eight bytes. Bytes 8–12 stay zero: the WGH1 control
// frames are told apart by a tag there (feedback_wire.go), and the server's
// echo path takes any other 20-byte STUN message and writes it back as it came
// (vk-turn-proxy server/main.go, both the WRAP and the DTLS loop).
func stunProbe(seq uint64) []byte {
	b := make([]byte, len(stunBindingIndication))
	copy(b, stunBindingIndication)
	binary.BigEndian.PutUint64(b[12:20], seq)
	return b
}

// stunProbeSeq is the seq an echoed keepalive names; 0 for the plain keepalive
// (isStunKeepalive has checked the shape).
func stunProbeSeq(b []byte) uint64 { return binary.BigEndian.Uint64(b[12:20]) }

// isStunProbeEcho is a 20-byte STUN keepalive of OUR shape — bytes 8–12 zero —
// as the server echoes it. Any other 20-byte STUN message from the relay peer
// carries a transaction ID of its own, and that must not read as a seq.
func isStunProbeEcho(b []byte) bool {
	return isStunKeepalive(b) && b[8]|b[9]|b[10]|b[11] == 0
}

// wakeProbeSendRetries bounds the consecutive failed writes a probe rides out
// (a second apart, as re-sends are) before it gives the loop back its turn.
const wakeProbeSendRetries = 5

type wakeProbeVerdict int

const (
	wakeProbeWait   wakeProbeVerdict = iota // keep listening
	wakeProbeResend                         // ask again now
	wakeProbeThawed                         // a freeze has just ended: ask again now, and only a pong of a ping sent from here on answers the probe
	wakeProbeEchoed                         // a pong of one of the probe's pings has arrived
	wakeProbeDead                           // thirty seconds of listening, asked to the last, nothing heard
)

// wakeProbeState is the probe's whole memory. `first` and `owed` are facts;
// `listened` and `sinceSend` are listening, added step by step where it is
// observed.
type wakeProbeState struct {
	first     uint64        // seq of the probe's first ping: a pong at or above it answers the probe
	owed      bool          // a fresh ping is OWED: nothing sent so far may answer, and the ping that may has not gone out yet
	listened  time.Duration // awake time spent waiting for an answer
	sinceSend time.Duration // awake time since the latest ping was written
	resends   int
	freezes   int
}

// step takes one poll step — how long it lasted and the pong mark read AFTER
// it — and says what to do. After the freeze check the mark is looked at
// before anything is counted, so no verdict is ever reached past an answer
// that is already in.
func (s *wakeProbeState) step(took time.Duration, pongMark uint64) wakeProbeVerdict {
	if took > wakeProbeFreezeStep {
		// The process did not run for most of this step: it heard nothing
		// because it could not. None of it counts — and an answer that is
		// already in counts least of all: it is from BEFORE the freeze (the
		// ping it answers was sent before it), and a sleep is exactly when the
		// relay reaps a session or a mapping goes. The caller pings again and
		// re-bases `first` on that ping.
		s.freezes++
		s.resends++
		s.sinceSend = 0
		return wakeProbeThawed
	}
	if s.owed {
		// Wake upon wake crossed the last three writes: nothing sent so far may
		// answer, and the ping that may has not gone out. There is no echo to
		// find and NO VERDICT to reach. Only the pause between writes is
		// counted, and it is not listening: nothing that could be heard is out.
		s.sinceSend += took
		if s.sinceSend < wakeProbeResendEvery {
			return wakeProbeWait
		}
		s.resends++
		s.sinceSend = 0
		return wakeProbeResend
	}
	if pongMark >= s.first {
		return wakeProbeEchoed
	}
	s.listened += took
	s.sinceSend += took
	if s.sinceSend < wakeProbeResendEvery {
		return wakeProbeWait
	}
	// The latest ping has had its second.
	if s.listened >= wakeProbeWindow {
		return wakeProbeDead
	}
	s.resends++
	s.sinceSend = 0
	return wakeProbeResend
}

// echoAfter is the listening an echo line reports, INCLUDING the step that saw
// the pong; a frozen step is not listening and is not added.
func echoAfter(listened, took time.Duration) time.Duration {
	if took > wakeProbeFreezeStep {
		return listened
	}
	return listened + took
}

func wakeProbeDetail(st *wakeProbeState) string {
	if st.resends == 0 && st.freezes == 0 {
		return ""
	}
	return fmt.Sprintf(" — first ping seq %d, sent again %d×, %d freeze(s) inside the wait", st.first, st.resends, st.freezes)
}

// wakeProbeSpread parks the caller for a random share of wakeProbeJitter.
// Every stream's loop fires in the same instant at a thaw and at a wake, and
// what follows on each — the WireGuard keepalive, the stream's keepalive with
// its cover and session header, the probe's ping — would otherwise be written
// and encrypted on every relay at once: anton48 saw forty such bursts push the
// extension over its memory limit (2026-05-25), and the first instant after a
// thaw is where the radio drops outbound datagrams anyway. false when ctx
// ended in the meantime.
func wakeProbeSpread(ctx context.Context) bool {
	if wakeProbeJitter <= 0 {
		return true
	}
	jitter := time.Duration(mathrand.Int63n(int64(wakeProbeJitter)))
	if jitter <= 0 {
		return true
	}
	select {
	case <-time.After(jitter):
		return true
	case <-ctx.Done():
		return false
	}
}

// wakeProbeDue: is a wake() to be probed on this stream at all? Not one probed
// less than wakeProbeThrottle ago (wake() comes in bursts, >100 an hour has
// been seen), and not one that heard its relay within wakeProbeRecentEcho —
// there is nothing to ask. A thaw the loop saw itself is probed regardless: a
// freeze is a fact, and the mapping may have gone in it.
func wakeProbeDue(activity *streamActivity, lastProbeAt, now time.Time) bool {
	if !lastProbeAt.IsZero() && now.Sub(lastProbeAt) < wakeProbeThrottle {
		return false
	}
	return activity.heardAge(now) >= wakeProbeRecentEcho
}

// runWakeProbe asks the relay whether this stream is still there, from the
// moment the loop has decided to ask. seq is the loop's ping counter, send
// writes one sequenced ping (stunProbe). It returns alive = false when the
// stream is to be ended, an error when a write failed or ctx is done — and the
// wake epoch its verdict COVERS: read together with the pong mark, before it.
// A wake broadcast after that reading was looked at by nobody and stays
// pending for the loop.
func (s *stream) runWakeProbe(ctx context.Context, activity *streamActivity, seq *uint64, send func(seq uint64) error, why string) (alive bool, covered uint64, err error) {
	// The caller has spread the streams over wakeProbeJitter already
	// (wakeProbeSpread): at a thaw the whole burst — keepalive, cover, session
	// header, this ping — is what is spread, not the ping alone.
	var st wakeProbeState
	// stepStart is where the current poll step began. A ping is SENT when its
	// write is over: the step — the ping's second and the listening — starts
	// THERE, so the time a write takes is never part of a step.
	stepStart := wakeProbeClock()
	// rebasedAt is when the ping the probe is currently based on went out. A
	// packet heard after it — data, an unsequenced echo — says the path is
	// alive even where the sequenced echo is missing (a server that does not
	// echo our seq must not cost a working stream); one read out of the
	// socket's buffer at a thaw is from before it and says nothing.
	var rebasedAt time.Time
	sendFails := 0
	ping := func() (wokeInside bool, err error) {
		*seq++
		activity.probeSent.Store(*seq) // an echo names a ping that was sent, never one beyond
		epoch := hostWakeEpoch()
		if err := send(*seq); err != nil {
			return false, err
		}
		stepStart = wakeProbeClock()
		return hostWakeEpoch() != epoch, nil
	}
	// pingFresh sends a ping — and another if the phone slept and WOKE while
	// the first was being written: a wake that crossed the write voids whatever
	// was heard before it, that ping included. Three writes at most; wake upon
	// wake across all three leaves the fresh ping OWED. A write that fails
	// leaves the ping owed as well: nothing that could be heard is out, the
	// rule reaches no verdict, and the next second's re-send tries again — up
	// to wakeProbeSendRetries in a row, then the loop takes its retry path.
	pingFresh := func() (crossed bool, err error) {
		for tries := 0; tries < 3; tries++ {
			wokeInside, err := ping()
			if err != nil {
				sendFails++
				st.owed = true
				if sendFails >= wakeProbeSendRetries {
					return crossed, err
				}
				turnLog("[STREAM %d] post-wake probe (%s): ping send error: %v — asking again in %v", s.id, why, err, wakeProbeResendEvery)
				return crossed, nil
			}
			sendFails = 0
			if !wokeInside {
				st.owed = false // a ping that may answer is out
				return crossed, nil
			}
			crossed = true
			st.freezes++
		}
		st.owed = true
		return true, nil
	}
	if _, err := pingFresh(); err != nil {
		return true, 0, err
	}
	st.first = *seq
	rebasedAt = stepStart
	timer := time.NewTimer(wakeProbePoll)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-ctx.Done():
			return true, 0, ctx.Err()
		}
		now := wakeProbeClock()
		took := now.Sub(stepStart)
		stepStart = now
		covered = hostWakeEpoch() // BEFORE the mark: a wake broadcast after this line is not this verdict's
		switch v := st.step(took, activity.pongMark()); v {
		case wakeProbeEchoed:
			turnLog("[STREAM %d] post-wake probe (%s): echo after %v of listening (seq %d)%s",
				s.id, why, echoAfter(st.listened, took).Round(10*time.Millisecond), *seq, wakeProbeDetail(&st))
			return true, covered, nil
		case wakeProbeResend, wakeProbeThawed:
			if v == wakeProbeThawed {
				// A freeze inside the probe is a freeze the loop never saw: the
				// detector's clock would otherwise count it as silence the moment
				// the probe hands the turn back.
				activity.resetLiveness(now)
			}
			wasOwed := st.owed
			crossed, err := pingFresh()
			if err != nil {
				return true, 0, err
			}
			if v == wakeProbeThawed || crossed || wasOwed {
				st.first = *seq // what was heard before the freeze — or sent before the debt was paid — answers nothing after it
				rebasedAt = stepStart
			}
		case wakeProbeDead:
			if heard := atomicTimestamp(&activity.lastHeard); heard.After(rebasedAt) {
				turnLog("[STREAM %d] post-wake probe (%s): no echo to seq %d in %v of listening, but the relay was heard %v ago — keeping the stream",
					s.id, why, *seq, wakeProbeWindow, now.Sub(heard).Round(time.Second))
				return true, covered, nil
			}
			turnLog("[STREAM %d] post-wake probe (%s): no echo in %v of listening (seq %d, last echo seq %d%s) — closing",
				s.id, why, wakeProbeWindow, *seq, activity.pongMark(), wakeProbeDetail(&st))
			return false, covered, nil
		}
		timer.Reset(wakeProbePoll)
	}
}
