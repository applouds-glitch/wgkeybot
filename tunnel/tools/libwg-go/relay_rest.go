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
	// relayLossLogEvery (relay_loss_log_release.go, _debug.go): one routine
	// line per this many windows while there is traffic over two relays or
	// more, if it booked relayLossLogMinPackets (_release.go: an idle tunnel's
	// window is not worth a line); a window with a relay above relayLossLogAbove
	// is logged every time.
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
	// gen counts the rests begun, every relay's, every server's; restGen is
	// the gen each relay's latest rest began at (relay+"→"+peer). For the loss
	// judge's runs (relayJudge.forgetRested): unlike a mark, which goes once
	// the relay is out of trouble, they stay.
	gen     uint64
	restGen map[string]uint64
}{marks: map[string]relayRestMark{}, restGen: map[string]uint64{}}

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
	relayRest.gen++
	relayRest.restGen[key] = relayRest.gen
	relayRest.Unlock()
	saveRelayRest(now)
	return rest, true
}

// relayRestGen is the count of rests begun so far: a moment to ask
// relayRestedAfter about later, mark or no mark by then.
func relayRestGen() uint64 {
	relayRest.Lock()
	defer relayRest.Unlock()
	return relayRest.gen
}

// relayRestedAfter reports whether addr has begun a rest from the current
// server's traffic since gen was read (relayRestGen).
func relayRestedAfter(addr string, gen uint64) bool {
	relayRest.Lock()
	defer relayRest.Unlock()
	return relayRest.restGen[relayRestKeyLocked(addr)] > gen
}

// runRelayLossJudge reads the downlink loss per relay every relayJudgeEvery for
// the life of the proxy. A relay that loses alone — two windows in a row, or
// twenty packets over the minute (relay_judge.go) — rests and its sessions move
// to the others; a relay whose downlink collapsed is logged
// (relay_collapse.go). Every relayLossLogEvery windows it logs the order the
// downlink came in (relay_order.go).
func runRelayLossJudge(ctx context.Context) {
	// The rests begun as the window being booked began, read before it opens:
	// a run that begins in it is a run since then (judgeLossTurn).
	moves, _ := relayTransportState()
	windows := relayLossWindows{gen: relayRestGen(), moves: moves}
	downlinkRelayLoss.reset()
	downlinkRelayOrder.reset(time.Now())
	noteLossyRelays(nil, time.Time{})
	var judge relayJudge
	var ledger relayLedger
	var returns relayReturns
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
		window := windows.next(downlinkRelayLoss, now, relayRestGen, relayTransportState)
		samples, unplaced := window.samples, window.unplaced
		streams := liveSessionCounts()
		if len(samples) > 0 && (n%relayLossLogEvery == 0 && relayLossPackets(samples) >= relayLossLogMinPackets ||
			anyRelayLossAbove(samples, relayLossLogAbove)) {
			// Over the time the numbers cover, which is not always the window
			// (relayLoss.take).
			span, over := relayLossLineSpan(window.span)
			turnLog("[RELAY LOSS] last %s: %s; %d lost on no relay in particular",
				span, formatRelayLoss(samples, streams, over), unplaced)
		}
		if n%relayLossLogEvery == 0 {
			if order := downlinkRelayOrder.take(now); order.got >= relayLossLogMinPackets {
				if !relayOrderLogPairs {
					order.pairs = nil
				}
				turnLog("[RELAY ORDER] %s", order)
			}
		}
		// Before the verdicts: the sessions they move dial the relays losing in
		// this same window last (relay_move.go).
		noteLossyRelays(lossyRelays(samples), now)
		verdicts := judgeLossTurn(&judge, &ledger, samples, window.overTCP, window.moved, window.began, relayRestedAfter)
		restJudgedRelays(ctx, verdicts, now)
		// After the verdicts: a session they move is not one to return (relay_return.go).
		if set := activeStreams.Load(); set != nil {
			returns.returnPass(ctx, now, liveSessionList, func() bool { return pathSilence(*set, window.overTCP, now) > 0 })
		}
		for _, relay := range collapse.step(samples, streams, relayJudgeEvery) {
			if now.Sub(collapseLogged[relay]) < relayCollapseLogEvery {
				continue
			}
			collapseLogged[relay] = now
			s := sampleFor(samples, relay)
			turnLog("[RELAY LOSS] %s looks collapsed: %.1f%% lost at %.0f packets/s per stream, %d windows running — logged only",
				relay, 100*s.rate(), perStreamRate(s, streams[relay], relayJudgeEvery), relayCollapseStrikes)
		}
	}
}

// relayLossWindows hands the loss judge its windows (take), each with the rests
// begun as it began (relayRestGen), the transport as it closed and whether the
// transport moved while it was booked (relayTransportState). What the next
// window begins at is read before the take that opens it: read after, a rest
// begun in between — the window open, booking traffic from before the rest —
// would count as before the window, and a strike from that traffic outlive the
// rest (Codex, 2026-11-06). Whether the transport moved is read after the take
// that closes the window as well, with the transport it closed on: read before
// only, a move in the gap went to the next window, and the one it was booked in
// passed under the transport moved to (Codex, the same day). A window it moved
// in takes the tail not yet final with it (dropTail).
type relayLossWindows struct {
	gen, moves uint64
}

// relayLossWindow is one window for the loss judge.
type relayLossWindow struct {
	samples  []relayLossSample
	unplaced int
	span     relayLossSpan // the time the samples cover (relayLoss.take)
	began    uint64        // the rests begun as it began (relayRestGen)
	overTCP  bool          // the transport as it closed
	moved    bool          // the transport moved while it was booked
}

func (w *relayLossWindows) next(loss *relayLoss, now time.Time, restGen func() uint64, transport func() (uint64, bool)) relayLossWindow {
	out := relayLossWindow{began: w.gen}
	startMoves := w.moves
	w.gen = restGen()
	w.moves, _ = transport()
	out.samples, out.unplaced, out.span = loss.take(now)
	endMoves, overTCP := transport()
	out.overTCP, out.moved = overTCP, endMoves != startMoves
	if out.moved {
		loss.dropTail()
		w.moves = endMoves // the move is this window's; the next begins after it
	}
	return out
}

// judgeLossTurn weighs one window by both loss judges and returns their
// verdicts. A relay rested starts its counts over in both: by either judge in
// this turn — the ledger forgot its windows, and the windows' judge kept a
// strike through the rest the ledger gave, so that one bad window half an hour
// later came out as two running and a rest doubled for a relapse (audit,
// 2026-11-06) — or by anything else since its run began, the deaf judge
// included (restedAfter, relayRestedAfter). A run begins with the window it was
// first counted in, and that window began at samplesGen — the rests begun as it
// did: a rest that began while it was being booked is after the run's first
// window began, and the loss before the rest no window running after it
// (Codex, 2026-11-06). By the count of rests begun, not by the mark: a judge
// that did not tick through a rest — the process frozen — found the mark gone
// and the strike standing (Codex, the same day).
//
// A window the transport moved in is not booked: its traffic came over both,
// and booked under the one now in use it passed the softer bars of TCP with
// loss taken over UDP (Codex, 2026-11-06). The book starts over with the next.
// The windows' judge weighs it as it is — its bars are the same either way,
// and its relays were weighed against each other in the same window.
func judgeLossTurn(judge *relayJudge, ledger *relayLedger, samples []relayLossSample, overTCP, transportMoved bool, samplesGen uint64, restedAfter func(string, uint64) bool) []relayVerdict {
	judge.forgetRested(restedAfter)
	verdicts := judge.step(samples)
	judge.noteRuns(samplesGen)
	if transportMoved {
		*ledger = relayLedger{}
	} else {
		verdicts = append(verdicts, ledger.step(samples, overTCP)...)
	}
	for _, v := range verdicts {
		ledger.forget(v.relay)
		judge.forget(v.relay)
	}
	return verdicts
}

// restJudgedRelays rests the relays of one turn's verdicts — the windows' and
// the ledger's (relay_judge.go) — and moves the sessions off them. Every relay
// is rested before any session moves: a session moves only if its link has
// another usable relay, and a relay judged in the same window is none — rested
// one by one, the sessions on the first went to the second, which was rested
// next, and redialed straight back onto a resting relay (iOS review,
// 2026-10-11: two relays of one link judged against a third of another link, or
// an extra relay).
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
		turnLog("[RELAY LOSS] %s lost %.1f%% of the downlink against %.1f%% %s — resting it for %v, %d session(s) moved off, %d left on it with no other relay of their link to go to%s",
			r.relay, 100*r.rate, 100*r.best, r.evidence, r.rest, out.moved, out.stayed, out.note())
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
// over the time the sample covers.
func perStreamRate(s relayLossSample, streams int, over time.Duration) float64 {
	if streams <= 0 || over <= 0 {
		return 0
	}
	return float64(s.rx) / over.Seconds() / float64(streams)
}

// relayLossLagWorthSaying is how far behind the take a loss line's numbers have
// to end for the line to say so. Under a second or so is the horizon at speed —
// 1024 packets are 0.7 s of a 16 Mbit/s download — and the window is still the
// last ten seconds to anyone reading it.
const relayLossLagWorthSaying = 2 * time.Second

// relayLossLineSpan words the time a loss line's numbers cover, after "last",
// and returns it for the rates: to the second — the judge's ticks do not land
// on one — and a second at the least.
func relayLossLineSpan(span relayLossSpan) (string, time.Duration) {
	over := max(span.over.Round(time.Second), time.Second)
	if span.ago < relayLossLagWorthSaying {
		return over.String(), over
	}
	return fmt.Sprintf("%v (ending %v ago)", over, span.ago.Round(time.Second)), over
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

// relayLossPackets is how many downlink packets the window booked over all relays.
func relayLossPackets(samples []relayLossSample) int {
	n := 0
	for _, s := range samples {
		n += s.rx + s.lost
	}
	return n
}

func anyRelayLossAbove(samples []relayLossSample, limit float64) bool {
	for _, s := range samples {
		if s.rx+s.lost >= relayJudgeMinPackets && s.rate() > limit {
			return true
		}
	}
	return false
}

func formatRelayLoss(samples []relayLossSample, streams map[string]int, over time.Duration) string {
	parts := make([]string, 0, len(samples))
	for _, s := range samples {
		parts = append(parts, fmt.Sprintf("%s %.1f%% of %d (%d streams, %.0f/s each%s)",
			s.relay, 100*s.rate(), s.rx+s.lost, streams[s.relay], perStreamRate(s, streams[s.relay], over), relayLossHolesNote(s)))
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
			head, full := moveHead(*s.relays, addr, s.stream.id, s.user, lossy, reserveRelays(*s.relays, configuredExtraRelays()), load, now)
			s.stream.giveMove(&relayMove{lossy: lossy, head: head, user: s.user, full: full, at: now})
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
