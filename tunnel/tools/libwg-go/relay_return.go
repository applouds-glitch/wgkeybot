/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Back to the extras: a session that fell to the link's own relays goes back
// to an extra once one is free again (#@wgt:ExtraRelays, relay_extra.go).
//
// The link's own are the reserve behind the extras (relayTier), but a session
// that lands on the reserve stays there: a healthy session is never moved, but
// off a rested relay. Field run of 2026-11-07 (Pixel on an iPhone hotspot): the
// hotspot reconnected twice in a minute, each network left orphaned the
// credential's allocations on the three extras — 6, 6 and 8 ghosts — the extras
// went crowded (orphaned_allocations.go) and behind the reserve, and all ten
// sessions came up on the link's own: 95.163.34.166 and 193.203.43.37, the weak
// relay the extras are there to keep the streams off. The ghosts were gone ten
// minutes later; the sessions were not.
//
// So the loss judge, every relayReturnEvery, may start one return: a session
// ready on the reserve for relayReturnSettle is moved, as a move off a rested
// relay is, with an extra of the clean tier as its head (moveHead), and the
// next return waits for its outcome (Codex's review of the plan, 2026-11-07):
// it is back once it has run ready on an extra for relayReturnConfirm, and has
// failed if it is seen on the reserve again before that, or has not been seen
// ready anywhere for relayReturnGiveUp — an extra that is free by the books is
// not one proven to carry, and the staged race (runWithCreds) hands the session
// back to the reserve when it does not. A failure pauses the returns, the pause
// doubling to relayReturnPauseMax; a success ends the pause. One session at a
// time, and never the last one ready: a return closes the session before the
// new one is up. A move of the network or the transport cancels a return
// without counting it either way, and a move already given to a stream (a
// rested relay's) is left to run first.
//
// A closed session redials through fetchCreds, so only a session whose
// credential its group's slot still serves is returned (credsServeFor): from a
// slot gone empty — a sibling's 486 or 401 force-expired it, which is just what
// the network drops this pass is for bring about — the redial is a trip to VK,
// and with VK giving no credential (the captcha ladder, a lockout, the call
// closed) the session stays down. And a returned stream that has not come up
// anywhere since holds the returns until it is up again, whatever the pause:
// each next return would close another healthy session the same way. Audit of
// 2026-11-10: with workers that never came back, the passes took down four
// sessions of five in 17 minutes.

const (
	relayReturnEvery    = 30 * time.Second
	relayReturnSettle   = time.Minute
	relayReturnConfirm  = time.Minute
	relayReturnGiveUp   = 3 * time.Minute
	relayReturnPauseMin = time.Minute
	relayReturnPauseMax = 16 * time.Minute
)

// relayReturns is the return pass's state, owned by the loss judge's loop.
type relayReturns struct {
	last       time.Time                   // the last pass
	onReserve  map[*stream]reserveSighting // each stream carrying on the reserve, in one session, since
	pending    *relayReturn                // the return in flight, if any
	pauseUntil time.Time
	pause      time.Duration // the pause the next failure doubles
	down       *stream       // a returned stream that has not come up since: no return till it is ready
}

// reserveSighting is a session carrying on the reserve since: of one attempt,
// so that the time one session sat there is not added to the next's (Codex,
// 2026-11-07).
type reserveSighting struct {
	attempt *networkAttempt
	since   time.Time
}

// relayReturn is one return in flight.
type relayReturn struct {
	stream     *stream
	move       *relayMove // the move it gave the stream: the outcome is the session of the attempt that takes it
	from, head string
	started    time.Time
	network    relayNetworkMark
	onExtra    *networkAttempt // the session ready on an extra since readySince, nil while none
	readySince time.Time
	seenAt     time.Time // last seen ready anywhere
}

// relayNetworkMark is the network the dials bind to — and whether it was lost
// or left meanwhile, even if the same one came back — and the transport moves
// so far: a return begun under another is called off, not failed.
type relayNetworkMark struct {
	network networkStamp
	moves   uint64
}

func currentNetworkMark() relayNetworkMark {
	stamp := currentNetworkStamp()
	moves, _ := relayTransportState()
	return relayNetworkMark{network: stamp, moves: moves}
}

// carrying reports whether s carries the tunnel's traffic now: ready, its
// session not gone stale for the dispatcher, its socket not stalled, its
// attempt the one it runs (Codex, 2026-11-07).
func carrying(s liveSession, now time.Time) bool {
	return s.stream.ready.Load() && !s.stream.dispatchStale(now) && !s.stream.sendStalled.Load() &&
		s.attempt != nil && !s.attempt.stale.Load() && s.stream.attempt.Load() == s.attempt
}

// liveSession is a session the pass weighs: its stream, the relay it runs on,
// its attempt, the relays it dials, its credential and the group whose slot
// the credential comes from.
type liveSession struct {
	stream  *stream
	relay   string
	attempt *networkAttempt
	relays  []string
	user    string
	group   int
}

// liveSessionList is every session running now, in stream order.
func liveSessionList() []liveSession {
	liveSessions.Lock()
	var out []liveSession
	for relay, set := range liveSessions.byRelay {
		for s, attempt := range set {
			var relays []string
			if p := s.relays.Load(); p != nil {
				relays = *p
			}
			var user string
			if u := s.user.Load(); u != nil {
				user = *u
			}
			out = append(out, liveSession{stream: s, relay: relay, attempt: attempt, relays: relays, user: user,
				group: int(s.credGroup.Load())})
		}
	}
	liveSessions.Unlock()
	slices.SortFunc(out, func(a, b liveSession) int { return a.stream.id - b.stream.id })
	return out
}

// returnPass is one turn of the return pass: it weighs the return in flight,
// and may start one. It reads the sessions, network and quota now; it waits on
// nothing, the session's recycle included.
// sessions and pathSilent are asked only when the pass is due.
func (r *relayReturns) returnPass(ctx context.Context, now time.Time, listSessions func() []liveSession, pathIsSilent func() bool) {
	if now.Sub(r.last) < relayReturnEvery {
		return
	}
	r.last = now
	extras := configuredExtraRelays()
	if len(extras) == 0 || ctx.Err() != nil {
		return
	}
	sessions := listSessions()
	if r.onReserve == nil {
		r.onReserve = map[*stream]reserveSighting{}
	}
	seen := map[*stream]bool{}
	for _, s := range sessions {
		seen[s.stream] = true
		if reserveRelays(s.relays, extras)[s.relay] && carrying(s, now) {
			if was, ok := r.onReserve[s.stream]; !ok || was.attempt != s.attempt {
				r.onReserve[s.stream] = reserveSighting{attempt: s.attempt, since: now}
			}
		} else {
			delete(r.onReserve, s.stream)
		}
	}
	for s := range r.onReserve {
		if !seen[s] {
			delete(r.onReserve, s)
		}
	}

	if r.pending != nil {
		if calledOff := r.weighPending(now, sessions, extras); calledOff {
			// The sessions are moving with the network: they settle afresh.
			clear(r.onReserve)
			return
		}
		if r.pending != nil {
			return
		}
	}
	if d := r.down; d != nil {
		if !d.ready.Load() {
			return
		}
		turnLog("[RELAY RETURN] stream %d is up again — the returns may go on", d.id)
		r.down = nil
	}
	if now.Before(r.pauseUntil) || !isNetworkAvailable() || pathIsSilent() {
		return
	}
	r.start(ctx, now, sessions, extras)
}

// weighPending settles the return in flight, if its outcome is known, and
// reports whether a move of the network or the transport called it off.
func (r *relayReturns) weighPending(now time.Time, sessions []liveSession, extras []string) (calledOff bool) {
	p := r.pending
	if currentNetworkMark() != p.network {
		turnLog("[RELAY RETURN] stream %d: the network or the transport moved — the return to %s is off, held against nothing", p.stream.id, p.head)
		r.pending = nil
		return true
	}
	// Whose session is the outcome: the attempt that took the return's move
	// (stream.tookMove), or one of the stream's begun after it — its session
	// ended, the worker reconnected; not one begun before (Codex, 2026-11-07).
	// Not yet taken, it waits; another move in its place, given or taken,
	// calls the return off.
	var taker *networkAttempt
	switch queued, took := p.stream.moveState(); {
	case queued == p.move:
		if now.Sub(p.started) >= relayReturnGiveUp {
			r.fail(now, p, "has not taken its move", true)
		}
		return false
	case queued != nil || took == nil || took.move != p.move:
		turnLog("[RELAY RETURN] stream %d: another move took it — the return to %s is off, held against nothing", p.stream.id, p.head)
		r.pending = nil
		return true
	default:
		taker = took.attempt
	}
	var on *liveSession
	for i := range sessions {
		if a := sessions[i].attempt; sessions[i].stream == p.stream && a != nil && taker != nil && a.seq >= taker.seq {
			on = &sessions[i]
			break
		}
	}
	switch {
	case on != nil && reserveRelays(on.relays, extras)[on.relay]:
		r.fail(now, p, "is on the link's own "+on.relay+" again", false)
		return false
	case on != nil && carrying(*on, now):
		p.seenAt = now
		if p.onExtra != on.attempt {
			p.onExtra, p.readySince = on.attempt, now // a session of its own: its minute starts now
		}
		if now.Sub(p.readySince) >= relayReturnConfirm {
			turnLog("[RELAY RETURN] stream %d is back on the extra %s, carrying for %v — the returns go on",
				p.stream.id, on.relay, now.Sub(p.readySince).Round(time.Second))
			r.pending, r.pause, r.pauseUntil = nil, 0, time.Time{}
		}
		return false
	default:
		p.onExtra, p.readySince = nil, time.Time{}
	}
	if now.Sub(p.seenAt) >= relayReturnGiveUp {
		r.fail(now, p, "has not come up ready since", true)
	}
	return false
}

// fail settles the return in flight as failed and pauses the returns; down,
// the stream has not come up anywhere since, and the returns wait for it too.
func (r *relayReturns) fail(now time.Time, p *relayReturn, why string, down bool) {
	r.pause = min(max(2*r.pause, relayReturnPauseMin), relayReturnPauseMax)
	r.pauseUntil = now.Add(r.pause)
	held := ""
	if down {
		r.down = p.stream
		held = ", and till it is up again"
	}
	turnLog("[RELAY RETURN] stream %d %s — the return from %s to %s failed; returns paused for %v%s",
		p.stream.id, why, p.from, p.head, r.pause, held)
	r.pending = nil
}

// start begins one return, if a session is due one and an extra is free for it.
func (r *relayReturns) start(ctx context.Context, now time.Time, sessions []liveSession, extras []string) {
	carriers := 0
	for _, s := range sessions {
		if carrying(s, now) {
			carriers++
		}
		if m := s.stream.move.Load(); m != nil && now.Sub(m.at) <= relayMoveLossyFresh {
			return // a move given already (a rested relay's) runs first
		}
	}
	if carriers < 2 {
		return // a return closes the session before the next is up: never the last carrying
	}
	lossy := lossyRelaysAt(now)
	for _, s := range sessions {
		sighting, onReserve := r.onReserve[s.stream]
		if !onReserve || sighting.attempt != s.attempt || now.Sub(sighting.since) < relayReturnSettle || !carrying(s, now) {
			continue
		}
		// Only a session whose redial its slot serves, for as long as the
		// return may take to settle: closed, the session fetches its
		// credential anew (see above).
		if !credsServeFor(s.group, s.user, now.Add(relayReturnGiveUp)) {
			continue
		}
		reserve := reserveRelays(s.relays, extras)
		// Not the last place in the credential's quota on the extra, counting
		// the Allocates still running there — a race's losers run on after
		// it was won: the reconnects of the other streams may want it, and a
		// 486 costs the session. Left out before the pick, so that an extra
		// short of room does not stand in for one that has it (Codex,
		// 2026-11-07).
		// The running first, then the held: an Allocate leaves the one count
		// only once booked in the other, so read in this order it is in one
		// of them at least.
		inFlight := map[string]int{}
		for _, relay := range s.relays {
			inFlight[relay] = allocatingOn(s.user, relay)
		}
		held := credsHeldOn(s.user, s.relays, now)
		relays := slices.DeleteFunc(slices.Clone(s.relays), func(relay string) bool {
			return !reserve[relay] && relay != s.relay && held[relay]+inFlight[relay]+2 > relayMoveQuota
		})
		// On a load of its own: a pick the return does not take is charged to
		// nothing (Codex, 2026-11-07).
		head, full := moveHead(relays, s.relay, s.stream.id, s.user, lossy, reserve, liveRelayLoad(), now)
		// Nor to an extra crowded with the credential's ghosts, a seat left on
		// it by the count or not (seatedRelays): an attempt that finds the seat
		// taken goes on to the next relay, a return has closed a session that
		// was carrying for it.
		if head == "" || reserve[head] || lossy[head] || full[head] || crowdedRelays(s.user, []string{head}, now)[head] {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		// Only over no move of another's, and only while the stream still runs
		// the attempt weighed here (offerMove): whichever attempt takes the
		// move is the return's, and it is never the one ended (Codex,
		// 2026-11-07).
		move := &relayMove{lossy: lossy, head: head, user: s.user, full: full, at: now}
		if !s.stream.offerMove(move, s.attempt) {
			continue
		}
		r.pending = &relayReturn{stream: s.stream, move: move, from: s.relay, head: head,
			started: now, network: currentNetworkMark(), seenAt: now}
		delete(r.onReserve, s.stream)
		turnLog("[RELAY RETURN] stream %d: carrying on the link's own %s for %v with %s free — starting its return there",
			s.stream.id, s.relay, now.Sub(sighting.since).Round(time.Second), head)
		// The attempt weighed, which has not taken the move; if it has ended
		// meanwhile, the next has taken the move and runs on.
		recycleAttempt(s.attempt)
		return
	}
}

// allocating counts the Allocates running, by credential and relay: a race's
// losers run on after it is won, and a reconnect's is in no other count till
// it ends (relayReturns.start).
var allocating = struct {
	sync.Mutex
	n map[relayIdentity]int
}{n: map[relayIdentity]int{}}

// noteAllocating books an Allocate of user's on relay until the returned func.
func noteAllocating(user, relay string) (done func()) {
	key := relayIdentity{user: user, relay: relay}
	allocating.Lock()
	allocating.n[key]++
	allocating.Unlock()
	return func() {
		allocating.Lock()
		if allocating.n[key]--; allocating.n[key] <= 0 {
			delete(allocating.n, key)
		}
		allocating.Unlock()
	}
}

func allocatingOn(user, relay string) int {
	allocating.Lock()
	defer allocating.Unlock()
	return allocating.n[relayIdentity{user: user, relay: relay}]
}
