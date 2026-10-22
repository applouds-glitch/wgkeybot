/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Resting a relay that goes deaf under our sessions time after time while
// another relay is heard (UDP).
//
// Field log of 2026-10-21 (POCO 2602BPC18G, HyperOS 3, v2.2.0; a cellular
// network, MegaFon by the user's word, over UDP), 06:28-06:36: one link, nine
// streams over its two relays, five on 193.203.43.37 and four on
// 95.163.34.166. Only the five went deaf. Each of their allocations carried for
// one to two and a half minutes, then nothing came back; 90 s later the
// dead-stream detector closed the session and its worker redialed the stream's
// own relay (assignRelays) — the same one, nine times in four minutes, with
// nothing against it. The four on 95.163.34.166 were heard throughout,
// WireGuard's handshakes went through every two minutes, and the handshake
// watchdog had nothing to see. What the user saw was the internet working,
// then cutting out: every deafness costs its stream ~35 s of packets before
// the dispatcher and the server's skip list (WGH1) route around it, and the
// next one is never far. On 2026-10-20 (16:08-16:19, the same SIM, UDP)
// 95.163.34.166 did the same — nine deaf sessions in eight minutes, its
// control plane failing beside them — and the streams left it only by chance:
// at 16:18 the orphans rule (orphaned_allocations.go) found our orphaned
// allocations still held there and dialed 193.203.43.37 first, where they ran
// for the 17 minutes left of the session without a deaf one.
//
// Nothing else rules on such a relay. A deaf session is no verdict for the
// health accounting (sessionOutcome), and the loss judge (relay_judge.go)
// weighs a relay only once it has carried 200 packets in a window — one that
// carries nothing is never weighed.
//
// What tells the relay from the path is a witness on ANOTHER relay: a stream
// that was there before the deaf session fell silent and hears its own relay
// now. The phone's UDP path was up all along, then — a path silent as a whole
// (relay_silence.go) has no such stream — and it is this relay, or the way to
// it, that ate the session. This is not the witness dropped on 2026-09-21
// (sessionOutcome): that one was a neighbour on the SAME relay — over UDP there
// was no other then — asked to excuse a death. This one convicts, and only
// a stream that has lived through the whole silence counts, so streams that
// reconnect in turn cannot vouch for one another with their handshakes.
//
// relayDeafStrikes such sessions within relayDeafWindow rest the relay
// (relay_rest.go) and move the sessions on it, as a verdict of the loss judge
// does: the relay comes back by itself, and one that does it again soon after
// rests twice as long. The mark is per relay and server and outlives a move to
// another network, although here the fault may as well be the phone network's
// way to the relay; a relay that is fine from the next network costs only the
// spread there until its rest is over, the first rest being the shortest. The
// count itself is per network: what a relay did to the sessions of one says
// nothing about the next.
//
// Not counted:
//
//   - Anything over TCP. There a flow has a fate of its own and dies beside
//     neighbours to the very same address that carry on, on both relays alike
//     (relay_heard_by_others.go, field log 19.09): three of them on one relay,
//     with a witness on the other, would come by chance and rest working
//     relays. The Rostelecom sessions of the same log ran over TCP for up to
//     3.5 h without a deaf session.
//   - A session whose link has no other usable relay: resting the only relay it
//     can go to moves nothing (assignRelays hands the whole list back).
//   - A session whose silence has a host freeze in it (deadStreamError.froze):
//     across a freeze a NAT forgets flows (wake_probe.go), and which one it
//     forgets says nothing about the relay behind it. Otherwise the post-wake
//     probe's verdict counts like the detector's: at an unlock on 2026-10-20
//     (16:12:10) it found stream 3 deaf on 95.163.34.166 again, 52 s into the
//     kind of silence the detector had closed on that relay a minute before.
//   - A session that the phone's own network failed under (relayNotToBlame) or
//     that we ended.
//   - A stream that is only stale — silent for dispatchStaleAfter and skipped by
//     the dispatcher. That ends with the next echo as often as not: in the
//     episode of 2026-10-20 stream 6 went stale on 95.163.34.166 twice and came
//     back both times (16:11:08, 16:12:27) before it went deaf at 16:16. The
//     dispatcher and the server's skip list already route around a stale
//     stream; what the stream cannot get past is a dead allocation, and only
//     the session's end says it is one. Counting staleness would gain under a
//     minute on a verdict that takes three sessions.

const (
	// relayDeafStrikes and relayDeafWindow: three deaf sessions on one relay in
	// ten minutes, each with a witness. In both field logs three came quickly
	// — within 41 s on 2026-10-21 with five streams on the relay, within 11 s
	// on 2026-10-20 — so the third costs nothing there. Where a relay has only
	// a stream or two, as once #@wgt:ExtraRelays spreads ten streams over five
	// or six relays, the third is a redial that has died again: deaf time after
	// time, not once. A relay that drops every session on it in one go while
	// its neighbour carries on is rested as well; if that was a single outage,
	// it costs the spread for half an hour, not the tunnel. Ten minutes hold
	// two cycles of a stream alone on such a relay — on 2026-10-21 a session
	// there lasted 2.5-4 min from its dial to the detector — and no more:
	// outside its two episodes the log has not one deaf session, and a longer
	// count would only give chance ones the time to add up.
	relayDeafStrikes = 3
	relayDeafWindow  = 10 * time.Minute
)

// deafSession is a session that ended deaf, with what the verdict weighs.
type deafSession struct {
	relay   string
	network int64     // the physical network the session ran on
	at      time.Time // when it was found deaf
	overTCP bool
	froze   bool // a host freeze inside its silence
	// elsewhere: its link has another usable relay to move to.
	elsewhere bool
	// witness is another relay that a stream there since before the silence
	// hears now; empty if there is none.
	witness string
}

// relayDeafVerdict is a relay to rest: how many deaf sessions stood against
// it, over what span, and the witness of the last.
type relayDeafVerdict struct {
	relay   string
	deaths  int
	span    time.Duration
	witness string
}

// relayDeafJudge counts, per relay and for the network in use, the sessions
// that went deaf on it while a stream on another relay was heard.
type relayDeafJudge struct {
	network int64
	deaths  map[string][]time.Time
}

// note weighs one deaf session. It returns how many deaf sessions stand against
// its relay with this one — 0 if this one does not count — and the verdict once
// they are enough, which starts the count over.
func (j *relayDeafJudge) note(d deafSession) (counted int, verdict *relayDeafVerdict) {
	if j.deaths == nil || d.network != j.network {
		j.deaths = map[string][]time.Time{}
		j.network = d.network
	}
	if d.overTCP || d.froze || !d.elsewhere || d.witness == "" || d.witness == d.relay {
		return 0, nil
	}
	var kept []time.Time
	for _, at := range j.deaths[d.relay] {
		if d.at.Sub(at) < relayDeafWindow {
			kept = append(kept, at)
		}
	}
	kept = append(kept, d.at)
	if len(kept) < relayDeafStrikes {
		j.deaths[d.relay] = kept
		return len(kept), nil
	}
	delete(j.deaths, d.relay)
	return len(kept), &relayDeafVerdict{relay: d.relay, deaths: len(kept), span: d.at.Sub(kept[0]), witness: d.witness}
}

var relayDeaf struct {
	sync.Mutex
	judge relayDeafJudge
}

// resetRelayDeaf forgets every count; for the tests.
func resetRelayDeaf() {
	relayDeaf.Lock()
	relayDeaf.judge = relayDeafJudge{}
	relayDeaf.Unlock()
}

// noteDeafSession weighs the session of s on addr that began at started and has
// just ended in err, cancelled if we ended it; if it is the verdict, the relay
// rests and the sessions on it move.
func noteDeafSession(s *stream, addr string, cancelled bool, err error, started, now time.Time) {
	var dead *deadStreamError
	if cancelled || !errors.As(err, &dead) || relayNotToBlame(err, started) {
		return
	}
	attempt, relays := s.attempt.Load(), s.relays.Load()
	if attempt == nil || relays == nil {
		return
	}
	d := deafSession{
		relay:     addr,
		network:   attempt.network,
		at:        now,
		overTCP:   s.overTCP.Load(),
		froze:     dead.froze,
		elsewhere: hasOtherUsableRelay(*relays, addr, now),
	}
	var by int
	if !d.overTCP {
		d.witness, by = deafWitness(addr, now.Add(-dead.silent), now)
	}
	relayDeaf.Lock()
	counted, v := relayDeaf.judge.note(d)
	relayDeaf.Unlock()
	if counted == 0 {
		return
	}
	how := "the detector"
	if dead.probe {
		how = "the post-wake probe"
	}
	turnLog("[RELAY DEAF] stream %d found deaf on %s by %s after %v of silence, while stream %d kept hearing %s — %d of %d in %v",
		s.id, addr, how, dead.silent.Round(time.Second), by, d.witness, counted, relayDeafStrikes, relayDeafWindow)
	if v == nil {
		return
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	restDeafRelay(ctx, *v, by, now)
}

// restDeafRelay rests the relay of a verdict and moves the sessions off it, as
// restJudgedRelays does for the loss judge's. The session that has just gone
// deaf is among those moved — it is booked on the relay until it returns — so
// its worker, too, reconnects at once, elsewhere and without counting a
// failure.
func restDeafRelay(ctx context.Context, v relayDeafVerdict, by int, now time.Time) {
	if relayResting(v.relay, now) {
		return // what still runs there has nowhere else to go
	}
	rest := noteRelayResting(v.relay, now)
	out := recycleRelaySessions(ctx, v.relay, now, nil)
	turnLog("[RELAY DEAF] %s went deaf under %d sessions in %v while stream %d kept hearing %s — resting it for %v, %d session(s) moved off, %d left on it with no other relay of their link to go to%s",
		v.relay, v.deaths, v.span.Round(time.Second), by, v.witness, rest, out.moved, out.stayed, out.note())
}

// deafWitness finds a stream on a relay other than addr that is up over UDP, has
// run since before silentSince — when the deaf session last heard its relay —
// and has heard its own within dispatchStaleAfter, the dispatcher's measure,
// and since silentSince: it returns that relay and the stream's id, or "" if
// there is none.
func deafWitness(addr string, silentSince, now time.Time) (string, int) {
	liveSessions.Lock()
	defer liveSessions.Unlock()
	for relay, set := range liveSessions.byRelay {
		if relay == addr {
			continue
		}
		for s := range set {
			if !s.ready.Load() || s.overTCP.Load() {
				continue
			}
			a := s.activity.Load()
			if a == nil || !a.start.Before(silentSince) {
				continue
			}
			if heard := a.heardAge(now); heard <= dispatchStaleAfter && now.Add(-heard).After(silentSince) {
				return relay, s.id
			}
		}
	}
	return "", 0
}
