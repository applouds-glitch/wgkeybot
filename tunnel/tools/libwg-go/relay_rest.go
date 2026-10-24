/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Resting a relay whose downlink has gone bad (relay_loss.go, relay_judge.go).
//
// What brought a bad pair back on the bench of 2026-10-10 was rest: about forty
// minutes without our traffic through it. So a verdict takes the relay out of
// this client's rotation for relayRestFor and moves the sessions that are on it
// now; the streams spread over the other relays (assignRelays) and the relay
// comes back by itself when the time is up — to be judged again if it still
// loses.
//
// Not every bad relay is tired, though. On 2026-10-11 the relay rested the day
// before still lost 3-4% after eight hours without our traffic, and a relay we
// had never used lost 4-9% from its first second. Such a relay comes back from
// every rest to cost a minute or two of a crawling download before the judge
// moves its sessions off again. So a relay judged bad again within
// relayRestRelapse of its return rests twice as long as last time, up to
// relayRestMax; one that stays out of trouble that long starts over.
//
// The mark belongs to the path from OUR SERVER to that relay. The phone's own
// leg was clean while the downlink was failing (the TCP transport counted 0-1%
// retransmits on it, RTT 7 ms), the uplink through the same relay was fine, and
// a different server port did not help (56010 against 56004, both bad). So it is
// kept per relay and server, and unlike the session's server health it is not
// wiped by a reconnect or by a move to another network — neither changes that
// path.
//
// Nor by the process dying. On a Lenovo TB-X705L (Android 9, field log of
// 2026-10-20) Android killed the app 40-95 s after almost every disconnect, and
// every connect then put five of nine streams back on 90.156.234.252, which lost
// 3-13% of the downlink until the judge rested it again — 40 s to 10.5 min
// later, and always for 30 minutes: the relapse rule never saw the verdict
// before. So the marks are kept on disk as well (relay_rest_store.go).
//
// A relay with nothing to compare it with — the only one left, or pinned — is
// not rested; when its downlink collapses under the sessions on it, that is
// logged (relay_collapse.go).
//
// A session moves off a rested relay only if its own link has another relay to
// go to. The judge weighs every relay of every link together, but a session can
// only redial its own link's relays (assignRelays); with both of them out it
// would land right back on the rested one, be judged again and moved again.
// What runs there stays, and the verdict on a relay already resting is not
// repeated.

const (
	relayRestFor     = 30 * time.Minute
	relayRestMax     = 4 * time.Hour
	relayRestRelapse = 2 * time.Hour
	relayJudgeEvery  = 10 * time.Second
	// relayLossLogEvery: one routine line per this many windows while there is
	// traffic over two relays or more; a window with a relay above
	// relayLossLogAbove is logged every time.
	relayLossLogEvery = 6
	relayLossLogAbove = 0.03
	// relayRecycleGap spaces the sessions moved off a rested relay, so ten
	// streams do not all redial the same second.
	relayRecycleGap = 300 * time.Millisecond
	// relayCollapseLogEvery: a relay that stays collapsed is logged this often.
	relayCollapseLogEvery = 5 * time.Minute
)

type relayRestMark struct {
	until    time.Time
	rest     time.Duration // the length of the rest that ends at until
	returned bool          // its return has been logged
}

var relayRest = struct {
	sync.Mutex
	peer  string                   // the server of the running proxy
	marks map[string]relayRestMark // relay+"→"+peer
}{marks: map[string]relayRestMark{}}

// setRelayRestPeer names the server the marks are read against from now on.
func setRelayRestPeer(peer string) {
	relayRest.Lock()
	relayRest.peer = peer
	relayRest.Unlock()
}

func relayRestKeyLocked(addr string) string { return addr + "→" + relayRest.peer }

// relayResting reports whether addr is resting from the current server's traffic.
func relayResting(addr string, now time.Time) bool {
	relayRest.Lock()
	key := relayRestKeyLocked(addr)
	m, ok := relayRest.marks[key]
	var resting, returned bool
	switch {
	case !ok:
	case now.Before(m.until):
		resting = true
	case !m.returned:
		m.returned = true
		relayRest.marks[key] = m
		returned = true
	case now.Sub(m.until) >= relayRestRelapse:
		delete(relayRest.marks, key) // out of trouble: the next verdict starts over
	}
	relayRest.Unlock()
	if returned {
		turnLog("[RELAY LOSS] %s has rested %v — back in rotation", addr, m.rest)
		saveRelayRest(now)
	}
	return resting
}

// noteRelayResting rests addr and returns for how long.
func noteRelayResting(addr string, now time.Time) time.Duration {
	rest, _ := noteRelayRestingFor(context.Background(), addr, now)
	return rest
}

// noteRelayRestingFor is noteRelayResting for a judge of the proxy ctx belongs
// to: once ctx has ended it rests nothing, and says so. Checked under
// relayRest's lock, which setRelayRestPeer takes too — and a start ends the last
// proxy before it names its own server (StartTunnelGroups), so a judge that
// finds ctx alive there writes the mark under its own server. Checked at the
// judge's entry alone, a verdict that had waited on the disk (saveRelayRest,
// relayResting's as well) came back after the next start had named another
// server and rested the relay for that one (Codex review, 23.10).
func noteRelayRestingFor(ctx context.Context, addr string, now time.Time) (time.Duration, bool) {
	relayRest.Lock()
	if ctx.Err() != nil {
		relayRest.Unlock()
		return 0, false
	}
	key := relayRestKeyLocked(addr)
	rest := relayRestFor
	if m, ok := relayRest.marks[key]; ok && now.Sub(m.until) < relayRestRelapse {
		rest = min(2*m.rest, relayRestMax)
	}
	relayRest.marks[key] = relayRestMark{until: now.Add(rest), rest: rest}
	relayRest.Unlock()
	saveRelayRest(now)
	return rest, true
}

// runRelayLossJudge reads the downlink loss per relay every relayJudgeEvery for
// the life of the proxy. A relay that loses alone rests and its sessions move
// to the others (relay_judge.go); a relay whose downlink collapsed is logged
// (relay_collapse.go). Every relayLossLogEvery windows it logs the order the
// downlink came in (relay_order.go).
func runRelayLossJudge(ctx context.Context) {
	downlinkRelayLoss.reset()
	downlinkRelayOrder.reset(time.Now())
	noteLossyRelays(nil, time.Time{})
	var judge relayJudge
	var collapse relayCollapseJudge
	collapseLogged := map[string]time.Time{}
	tick := time.NewTicker(relayJudgeEvery)
	defer tick.Stop()
	for n := 0; ; n++ {
		var now time.Time
		select {
		case <-ctx.Done():
			return
		case now = <-tick.C:
		}
		samples, unplaced := downlinkRelayLoss.take(now)
		streams := liveSessionCounts()
		if len(samples) > 0 && (n%relayLossLogEvery == 0 || anyRelayLossAbove(samples, relayLossLogAbove)) {
			turnLog("[RELAY LOSS] last %v: %s; %d lost on no relay in particular",
				relayJudgeEvery, formatRelayLoss(samples, streams), unplaced)
		}
		if n%relayLossLogEvery == 0 {
			if order := downlinkRelayOrder.take(now); order.got > 0 {
				turnLog("[RELAY ORDER] %s", order)
			}
		}
		// Before the verdicts: the sessions they move dial the relays losing in
		// this same window last (relay_move.go).
		noteLossyRelays(lossyRelays(samples), now)
		restJudgedRelays(ctx, judge.step(samples), now)
		for _, relay := range collapse.step(samples, streams, relayJudgeEvery) {
			if now.Sub(collapseLogged[relay]) < relayCollapseLogEvery {
				continue
			}
			collapseLogged[relay] = now
			s := sampleFor(samples, relay)
			turnLog("[RELAY LOSS] %s looks collapsed: %.1f%% lost at %.0f packets/s per stream, %d windows running — logged only",
				relay, 100*s.rate(), perStreamRate(s, streams[relay]), relayCollapseStrikes)
		}
	}
}

// restJudgedRelays rests the relays of one window's verdicts and moves the
// sessions off them. Every relay is rested before any session moves: a session
// moves only if its link has another usable relay, and a relay judged in the
// same window is none — rested one by one, the sessions on the first went to
// the second, which was rested next, and redialed straight back onto a resting
// relay (iOS review, 2026-10-11: two relays of one link judged against a third
// of another link, or an extra relay).
func restJudgedRelays(ctx context.Context, verdicts []relayVerdict, now time.Time) {
	if ctx.Err() != nil {
		return // the proxy has stopped: its verdicts with it
	}
	type rested struct {
		relayVerdict
		rest time.Duration
	}
	var resting []rested
	for _, v := range verdicts {
		if relayResting(v.relay, now) {
			continue // what still runs there has nowhere else to go
		}
		rest, ok := noteRelayRestingFor(ctx, v.relay, now)
		if !ok {
			return // the proxy stopped while the verdict before waited on the disk
		}
		resting = append(resting, rested{v, rest})
	}
	// One load for every relay rested in this turn: the sessions moved off the
	// first are charged to where they go before those of the second pick
	// theirs (relay_move.go).
	load := liveRelayLoad()
	for _, r := range resting {
		out := recycleRelaySessions(ctx, r.relay, now, load)
		turnLog("[RELAY LOSS] %s lost %.1f%% of the downlink against %.1f%% through the best relay, %d windows running — resting it for %v, %d session(s) moved off, %d left on it with no other relay of their link to go to%s",
			r.relay, 100*r.rate, 100*r.best, relayJudgeStrikes, r.rest, out.moved, out.stayed, out.note())
	}
}

func sampleFor(samples []relayLossSample, relay string) relayLossSample {
	for _, s := range samples {
		if s.relay == relay {
			return s
		}
	}
	return relayLossSample{relay: relay}
}

// perStreamRate is the packets per second each stream on the relay delivered
// in one window.
func perStreamRate(s relayLossSample, streams int) float64 {
	if streams <= 0 {
		return 0
	}
	return float64(s.rx) / relayJudgeEvery.Seconds() / float64(streams)
}

// liveSessionCounts is how many sessions run on each relay now.
func liveSessionCounts() map[string]int {
	liveSessions.Lock()
	defer liveSessions.Unlock()
	out := make(map[string]int, len(liveSessions.byRelay))
	for relay, set := range liveSessions.byRelay {
		out[relay] = len(set)
	}
	return out
}

func anyRelayLossAbove(samples []relayLossSample, limit float64) bool {
	for _, s := range samples {
		if s.rx+s.lost >= relayJudgeMinPackets && s.rate() > limit {
			return true
		}
	}
	return false
}

func formatRelayLoss(samples []relayLossSample, streams map[string]int) string {
	parts := make([]string, 0, len(samples))
	for _, s := range samples {
		parts = append(parts, fmt.Sprintf("%s %.1f%% of %d (%d streams, %.0f/s each)",
			s.relay, 100*s.rate(), s.rx+s.lost, streams[s.relay], perStreamRate(s, streams[s.relay])))
	}
	return strings.Join(parts, ", ")
}

// recycleRelaySessions moves the sessions now running on addr whose link has
// another usable relay: each attempt is recycled the way a network move
// recycles it (network_switch.go), so its worker reconnects at once and without
// counting a failure — and, the relay resting, onto another one: each to the
// least loaded of its link's relays first, the relays losing in the latest
// window last (relay_move.go). load is the sessions on each relay, charged
// with every pick; nil, it is taken now. It returns how many it moves, how
// many stay, where the moved ones go first and the relays they dial last.
func recycleRelaySessions(ctx context.Context, addr string, now time.Time, load *relayLoad) relayMoveOut {
	// A judge whose proxy has stopped moves nothing: the sessions booked on
	// addr by now may be the next proxy's (liveSessions outlives a proxy), and
	// a verdict that waited on the disk (saveRelayRest) can come after the
	// stop (Codex review of the iOS port, 22.10).
	if ctx.Err() != nil {
		return relayMoveOut{}
	}
	type session struct {
		stream  *stream
		attempt *networkAttempt
		relays  *[]string
		user    string
	}
	liveSessions.Lock()
	// Again under the lock sessions are booked under: a start ends the last
	// proxy before any session of its own is booked, so a judge that finds ctx
	// alive here reads its own proxy's sessions only. The check above alone
	// left the moment before this lock, in which the next proxy's sessions
	// were read, given a move and recycled (Codex review, 23.10).
	if ctx.Err() != nil {
		liveSessions.Unlock()
		return relayMoveOut{}
	}
	var sessions []session
	for s := range liveSessions.byRelay[addr] {
		if a := s.attempt.Load(); a != nil {
			var user string
			if u := s.user.Load(); u != nil {
				user = *u
			}
			sessions = append(sessions, session{s, a, s.relays.Load(), user})
		}
	}
	liveSessions.Unlock()
	if load == nil {
		load = liveRelayLoad()
	}
	// In stream order, so that the picks do not hang on the map's.
	slices.SortFunc(sessions, func(a, b session) int { return a.stream.id - b.stream.id })
	lossy := lossyRelaysAt(now)
	var out relayMoveOut
	var attempts []*networkAttempt
	for _, s := range sessions {
		if s.relays != nil && hasOtherUsableRelay(*s.relays, addr, now) {
			head := moveHead(*s.relays, addr, s.stream.id, s.user, lossy, load, now)
			s.stream.move.Store(&relayMove{lossy: lossy, head: head, at: now})
			out.heads = append(out.heads, movedHead{id: s.stream.id, relay: head})
			attempts = append(attempts, s.attempt)
		} else {
			out.stayed++
		}
	}
	go func() {
		for i, a := range attempts {
			if i > 0 {
				select {
				case <-time.After(relayRecycleGap):
				case <-ctx.Done():
					return
				}
			} else if ctx.Err() != nil {
				return // the first as well
			}
			recycleAttempt(a)
		}
	}()
	out.moved, out.last = len(attempts), dialedLast(lossy, addr, now)
	return out
}
