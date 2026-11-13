/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"cmp"
	"fmt"
	"math"
	"slices"
)

// The verdict on relay_loss.go's windows: which relay's downlink has gone bad.
//
// Loss alone does not say it. A healthy relay loses too once TCP probes past its
// per-allocation ceiling — the bench saw 5-11% retransmits at 16 Mbit/s on the
// good relay with eight flows pushing — and then every relay of the session loses
// alike. What the bad relay of 2026-10-10 did was lose 10-20% while its neighbour
// lost 1-2%, at a fraction of the rate. So the rule is relative: a relay is
// judged only against another relay of the same session in the same window,
// and only when it is clearly worse — by a factor and by an absolute margin both,
// so neither two clean relays (0.2% against 0.8%) nor two saturated ones (6%
// against 9%) trip it.
//
// The margin is the whole floor. A separate 5% one let a tired relay through on
// 2026-10-10: it lost 4.2%, 5.2% and 4.8% against 0% on its neighbour while a
// four-flow download through the pair crawled at 2.5 Mbit/s, and the windows
// under 5% kept restarting the count. A 4-point margin did the same on
// 2026-10-11, twice: relays losing a steady 3.3-5% against 0-0.5% beside them
// held the download at 2-3 Mbit/s for 1.5-2 minutes until two windows happened
// to clear it. At a 200 ms round trip, 4% lost on a third of the streams is
// all TCP needs to stall, so the margin is 2 points.
//
// A single window can be a burst on one stream; the verdict takes
// relayJudgeStrikes windows in a row against the same relay. Each relay keeps
// its own count against the best one: with the relays of several links in the
// pool, a count kept only for the worst let two bad relays taking turns at the
// top restart each other's (review, 2026-10-11).

// And not by chance (audit, 2026-11-06). Set against the best of several
// relays, a relay of a few hundred packets clears the ratio and the margin at
// a common loss more often than it would seem: the least of the others' counts
// falls far below the rest, and ten lost against one is a third of a common
// 3% of 283. A simulation of five equal relays at 283 packets a window and a
// common 3% made 7 verdicts an hour, eight relays 28, three 1.2 — each a rest
// of thirty minutes, doubling on a relapse. So each window counts against the
// relay only if, against some other relay of the window it stands against, of
// the two relays' losses equal rates would have dealt it its part less than
// once in 1/relayJudgeChance — the bar shared among the relays it could have
// been set against (lossChanceAtMost, as the ledger asks it), the clearest of
// them taken: the cleanest relay alone, if thin, could leave to chance a loss
// a busier one beside it shows plainly (Codex). At 1e-3 the same simulation,
// 3000 hours of it over two to eight relays and 1-8% of common loss, rested
// nothing; the verdicts of the tests come at the same windows, the tired relay
// of 2026-10-10 at 300 packets a window — 13 and 16 lost against none — at the
// second. At 1e-4 it waited a window more.
//
// What it costs is the thin and the close. Ten lost of 200 against clean
// neighbours is a chance of 2^-10: a window against one neighbour, none
// against two or more, where the ledger takes it over TCP a window later and
// over UDP two. On a common 1% a relay three points worse waits longer, and
// over TCP the ledger is there for it. Over UDP a relay losing 3.9% against
// 1.1% at 283 packets — eleven against three, a chance of 0.03 in each window
// (the bound the gate reads, 0.09) — is rested by neither judge any more, the
// ledger asking five times the rate there: the old verdict on it rested on two
// such windows, each one in 35 by chance. Getting it back would take evidence
// carried from window to window, or a looser gate — a change of its own.

const (
	// relayJudgeMinPackets is the least a relay must have carried in a window
	// for its rate to count. The bad relay of 2026-10-10 still carried a few
	// hundred packets per ten seconds at 0.5 Mbit/s for the whole tunnel.
	relayJudgeMinPackets = 200
	// relayJudgeMinLost is the least a relay must have lost in a window to be
	// judged by its rate: at a few hundred packets, seven lost against one is
	// chance, and with the gaps that could be either relay's left out
	// (relay_loss.go) a lossy phone network made one such pair twice in a row
	// about once an hour in simulation. The verdicts seen in the field rested
	// on 22-42 packets a window.
	relayJudgeMinLost = 10
	relayJudgeRatio   = 3.0
	relayJudgeMargin  = 0.02
	relayJudgeStrikes = 2
	// relayJudgeChance is how rarely equal rates may have dealt a relay its
	// part of its and the best relay's losses in a window for the window to
	// count against it, shared among the relays it could have been set
	// against (see the comment above).
	relayJudgeChance = 1e-3
)

type relayJudge struct {
	strikes map[string]int
	// since is, for each relay with a run, the rests begun as the run's first
	// window began (relayRestGen): rested after, it starts over (forgetRested).
	since map[string]uint64
}

// windowChance bounds the chance that, of the losses of relays s and best in a
// window, s took as many as it did at equal rates (lossChanceAtMost).
func windowChance(s, best relayLossSample) float64 {
	n, m := s.rx+s.lost, best.rx+best.lost
	return lossChanceAtMost(s.lost, []lossShare{{lost: s.lost + best.lost, share: float64(n) / float64(n+m)}})
}

// relayVerdict is a relay judged bad, with the two rates the verdict rests on —
// its own, and the one it is held against: the best relay's in the window, or
// the other relays' over the minute as the relay was exposed to it
// (relayLedger) — and, for the log, what that rate is and what else the
// verdict rests on: the windows in a row, or the minute's totals.
type relayVerdict struct {
	relay      string
	rate, best float64
	evidence   string
}

// forget drops relay's count: rested, it starts over.
func (j *relayJudge) forget(relay string) {
	delete(j.strikes, relay)
	delete(j.since, relay)
}

// forgetRested drops the run of each relay that has begun a rest since its run
// began (restedAfter): what it lost before the rest is no window running after
// it. A relay that rests and still carries — sessions with no other relay of
// their link to go to — starts a run of its own again from its next window.
func (j *relayJudge) forgetRested(restedAfter func(string, uint64) bool) {
	for relay := range j.strikes {
		if restedAfter(relay, j.since[relay]) {
			j.forget(relay)
		}
	}
}

// noteRuns records for each run begun in the window just weighed the rests
// begun as that window began (windowGen), and lets go of those of the runs
// that ended.
func (j *relayJudge) noteRuns(windowGen uint64) {
	if j.since == nil {
		j.since = map[string]uint64{}
	}
	for relay := range j.since {
		if _, ok := j.strikes[relay]; !ok {
			delete(j.since, relay)
		}
	}
	for relay := range j.strikes {
		if _, ok := j.since[relay]; !ok {
			j.since[relay] = windowGen
		}
	}
}

// step weighs one window and returns the relays to rest.
func (j *relayJudge) step(samples []relayLossSample) []relayVerdict {
	if j.strikes == nil {
		j.strikes = map[string]int{}
	}
	var counted []relayLossSample
	for _, s := range samples {
		if s.rx+s.lost >= relayJudgeMinPackets {
			counted = append(counted, s)
		}
	}
	if len(counted) < 2 {
		// Nothing to compare against: one relay, or a quiet window. A quiet
		// window is no evidence either way, so the counts stand; a session
		// left with one relay has nothing to move to, so they start over.
		if len(counted) == 1 {
			clear(j.strikes)
		}
		return nil
	}
	bar := relayJudgeChance / float64(len(counted)-1)
	var out []relayVerdict
	for _, s := range counted {
		r := s.rate()
		// Against each other relay of the window it stands against, and the
		// clearest of them: the cleanest one alone, thin, could leave a
		// relay's loss to chance that a busier one beside it shows plainly
		// (Codex, 2026-11-06).
		var against relayLossSample
		clearest := 2.0
		if s.lost >= relayJudgeMinLost {
			for _, o := range counted {
				if o.relay == s.relay || r < relayJudgeRatio*o.rate() || r-o.rate() < relayJudgeMargin {
					continue
				}
				if c := windowChance(s, o); c <= bar && c < clearest {
					against, clearest = o, c
				}
			}
		}
		if clearest > bar {
			delete(j.strikes, s.relay)
			continue
		}
		best := against.rate()
		j.strikes[s.relay]++
		if j.strikes[s.relay] >= relayJudgeStrikes {
			delete(j.strikes, s.relay)
			out = append(out, relayVerdict{relay: s.relay, rate: r, best: best,
				evidence: fmt.Sprintf("through %s, %d windows running", against.relay, relayJudgeStrikes)})
		}
	}
	return out
}

// A second verdict, over the minute: a relay that loses a little, but alone,
// for long.
//
// The windows above catch a relay losing 3-20% against a clean neighbour. The
// bench of 2026-11-04 (Pixel on RTK LTE, berlin3, TCP to the relays, ten
// streams, one TCP flow inside the tunnel) found a relay that never got there
// and still cost the tunnel a factor of three: with 193.203.43.37 among the
// five relays the download ran at 2.0 Mbit/s, with it rested 6.7, and the
// other layouts of healthy relays — five of 95.163.34.x, a pin on one — were
// within noise of each other. In the windows .37 lost 3.6% of 280 packets
// once and 0% the next time, its neighbours 0% throughout, every stream at
// the same 14 packets/s: the server deals the downlink in equal shares, chunk
// by chunk, loss or no loss (vk-turn-proxy, server/downstream_queue.go), so
// the one TCP flow inside runs at the pace of the share that loses. Six
// sessions of about a minute each, and not one verdict: ten lost in two
// windows in a row is more than such a relay loses.
//
// So the ledger adds the windows up. Over the last relayLedgerWindows windows
// a relay that lost relayLedgerMinLost packets or more, relayJudgeRatio times
// what it would have lost at a neighbour's rate and relayLedgerMargin above
// it, rests as one judged by the windows does (restJudgedRelays). The verdict
// stays relative, and in the same windows: a relay is weighed against a
// neighbour over the windows both were booked in — a relay that carried alone
// for most of the minute, losing to its own ceiling, is not held against a
// neighbour's clean ten seconds — and over relayLedgerMinWindows such windows
// at least, since the windows above take two in a row before they call a loss
// more than a burst. The margin is half a point, a quarter of the windows':
// spread over a minute, a relay like .37 is a 1-2% one. The expected loss is
// taken window by window, the relay's packets at the neighbour's rate in that
// window, rather than from the minute's sums: the streams move between
// relays, and two relays losing 7% alike, one carrying three times the other
// while the loss lasted and a third of it once it was over, came out 2.6%
// against 0.44% in the sums (Codex, audit of 2026-11-06).
//
// Weighed on the ratio and the margin alone, the book rested healthy relays.
// At a common 1% each of five relays loses some seventeen packets a minute,
// and the least of the four neighbours a relay is set against falls to a third
// of that often enough that a simulation of the book on five equal relays over
// TCP (audit, 2026-11-06; 280 packets a relay a window) made 8 verdicts an
// hour, and with the rested relays dropping out rested one in 99% of the
// hours, ten minutes in on average, and a second in 93% — rests of thirty
// minutes, doubling on a relapse, kept on disk. A pair: 0.9 an hour. A common
// loss over TCP is no exception: once the inner TCP probes past the relays'
// ceiling, every relay loses alike (above). What a lucky neighbour cannot hide
// from is chance itself, so every verdict now also asks it (below). Pooling
// the neighbours instead was tried and set aside, twice, on Codex's review:
// against every other relay together, two relays losing 10% beside a clean one
// each stood at twice the rate of the pool, the other bad one in it, and
// neither was ever rested; against those that lost less over the minute, the
// pool was picked by the very numbers it was then tested on — thin neighbours
// that lost a packet fell out of it, leaving it cleaner than chance — a
// slightly bad relay could shield a worse one for good, and a relay's windows
// alone decided which neighbours it met.
//
// What the test costs is the small difference on top of a common loss.
// Against clean neighbours — .37's of 2026-11-04 were clean — the verdicts
// come at the same windows as before, over either transport, but for a thin
// one (below). On a common 1% over TCP a relay two points worse than the rest
// waits 8-11 windows instead of 3-7, and one point worse is rarely rested at
// all — a difference the book made no better than its own false verdicts on
// equal relays.
//
// The book's floor is the minute's, not the window's. The windows above count
// a relay only at relayJudgeMinPackets a window, and the same bench, the same
// evening, showed how a relay hides under that floor: .37 losing 5-15% kept
// the one TCP flow inside at 0.3-0.6 Mbit/s, and at that pace each of the
// five relays carried 120-140 packets a window — the floor was set when two
// relays shared a tunnel at 0.5 Mbit/s and still carried a few hundred each
// — so no window was counted, by either judge, and the tunnel sat there for
// the whole two minutes (06_W5; the pair .37+.166 the same for 115 s, 04_OWN).
// The worse a relay loses, the better it hides. So a window is booked from
// relayLedgerMinWindowPackets, which keeps out a window the relay barely took
// part in (one of 20% of 5 packets was logged), and the weight comes from the
// sums instead: relayJudgeMinPackets over the shared windows on each side —
// the relay's own, and the other relays' together.
//
// Two more gates, from the review of that change (Codex, 2026-11-04). The
// clean neighbours are evidence only if they carried enough to have shown the
// loss: a neighbour of 240 packets is clean by chance at a common 1% once in
// eleven times, and would have rested an equally good relay of 4000. And the
// loss has to be in relayLedgerMinLossyWindows of the shared windows: three
// shared windows are not three windows of loss, and twenty lost in one window
// with nothing before or after is what a stream's TCP connection to the relay
// being re-dialed looks like — not a relay to rest for half an hour.
//
// The first of them is now a test of chance (audit, 2026-11-06). Twenty lost
// at three times a neighbour's rate is a bar chance clears at a common 1%; so
// the relay's part of the two relays' losses, window by window, must be one
// that equal rates would deal it less than once in 1/relayLedgerChance — each
// window's losses falling on it each at its share of the window's packets, the
// chance bounded from above (lossChanceAtMost) — and that bar is shared among
// the neighbours it is weighed against, so that five tries at it are not five
// times the chance. That is the neighbour gate's question asked whole: a thin
// clean neighbour leaves the relay most of the packets, so most of the losses
// are its by right (the 240 against 4000 above: one in ten); and under equal
// rates a pair's twenty-to-six comes once in a few hundred times. Window by
// window, since a share is a window's: ten of a thousand beside a clean fifty,
// twice, then fifty beside a clean ten thousand, is a chance of 0.38 by the
// windows and was 3.5e-16 by the minute's sums (Codex). At 1e-5 the simulation
// rested nothing in 1500 hours of two or five equal relays over either
// transport, of three or eight over UDP; once in 1500 hours of three over TCP,
// three times of eight. At 1e-6 a relay losing 1.3% beside a clean neighbour
// of a third of its load would never be rested — 0.75^48 is 1.0e-6 — where at
// 1e-5 it is, at the sixth window (the old book: the third). The verdicts of
// 2026-11-04 come with room: .37's minute at 22 lost of 1680 against none of
// 1680 on each of four neighbours is a chance of 2.4e-7, the stuck tunnel's
// 50 against none 8.9e-16.
//
// Over UDP the book asks for more: twice the windows' judge's lost, five times
// the neighbour's rate, and the windows' judge's margin of two points. Over
// TCP a loss on the phone's leg is a retransmission, not a hole, so a loss
// placed on a relay there is the leg from our server to it, or the relay's
// own; over UDP the phone's own loss lands on the relays — a counter the radio
// dropped inside a chunk is charged to the chunk's relay like any other — and
// twenty over a minute at half a point is a bar such chance clears: a
// simulation of a lossy phone network (2026-10-10) made a pair of seven lost
// against one, two windows in a row, about once an hour, and each false
// verdict is thirty minutes of rest, doubling on a relapse (relay_rest.go). So
// the book was TCP-only at first. But the server deals the downlink in chunks
// of eight, round-robin over the streams, so a burst the radio drops spans
// several chunks and lands on every relay — a common loss, which a relative
// verdict never rests — and what is left to chance is the unevenness: at a
// common 1-3% over 1700 packets a relay a minute, forty lost on one against a
// fifth of that on another is a chance in millions. Bench of 2026-11-04 over
// UDP (LTE, the transport forced): with .37 losing 3-12% among five relays the
// one TCP flow inside sat at 0.4-0.7 Mbit/s for the whole 90 s cell — the
// windows' judge under its floor, the book switched off — while the same
// relay over TCP was rested in 25-55 s. So over UDP the book asks for
// relayLedgerMinLostUDP lost at relayLedgerRatioUDP times the neighbour's
// rate and relayLedgerMarginUDP above it: a relay losing 6% and up, which is
// what the stuck tunnel is; the 1-2% relay stays the UDP's blind spot. A
// change of transport empties the book: the windows on either side of it are
// not the same path.

const (
	relayLedgerWindows    = 6 // a minute of relayJudgeEvery
	relayLedgerMinLost    = 20
	relayLedgerMinWindows = 3
	relayLedgerMargin     = 0.005
	// relayLedgerMinWindowPackets is the least a relay must have carried in a
	// window for the window to be booked: a quarter of the windows' floor,
	// under the 120-140 a window of the stuck tunnel of 2026-11-04 and over an
	// idle relay's 20-40 (keepalives of four or five streams).
	relayLedgerMinWindowPackets = 50
	// relayLedgerMinLossyWindows is how many of the shared windows the relay
	// must have lost in: one is a burst, not a relay.
	relayLedgerMinLossyWindows = 2
	// relayLedgerChance is how rarely equal rates may have dealt the relay its
	// part of a neighbour's and its losses for a verdict to stand, shared among
	// the neighbours it is weighed against.
	relayLedgerChance = 1e-5
	// Over UDP: twice the windows' judge's lost over the minute
	// (relayJudgeMinLost a window, two windows), five times the neighbour's
	// rate, and the windows' judge's margin.
	relayLedgerMinLostUDP = 40
	relayLedgerRatioUDP   = 5.0
	relayLedgerMarginUDP  = 0.02
)

// relayLedger is the minute's book: the booked samples of the last
// relayLedgerWindows windows, oldest overwritten first.
type relayLedger struct {
	windows [relayLedgerWindows][]relayLossSample
	n       int  // windows booked so far
	tcp     bool // the transport the windows were taken over
}

// step books one window and returns the relays to rest. overTCP says whether
// the dials go over TCP now (relayTransportInUse); a change of transport
// empties the book.
func (l *relayLedger) step(samples []relayLossSample, overTCP bool) []relayVerdict {
	if l.n > 0 && l.tcp != overTCP {
		*l = relayLedger{}
	}
	l.tcp = overTCP
	var booked []relayLossSample
	for _, s := range samples {
		if s.rx+s.lost >= relayLedgerMinWindowPackets {
			booked = append(booked, s)
		}
	}
	l.windows[l.n%relayLedgerWindows] = booked
	l.n++
	var out []relayVerdict
	relays := l.relays()
	against := map[string][]ledgerCase{}
	for _, r := range relays {
		if cases := l.judge(r, relays); len(cases) > 0 {
			against[r] = cases
		}
	}
	// A case stands unless its neighbour leads back to the relay by a chain of
	// cases. Weighed pair by pair, window by window, three relays each losing
	// alone in a window the next one carried clean were each judged against
	// the next, and the turn rested them all (Codex, 2026-11-06): a ring of
	// "worse than" is evidence against none of them. A chain is not a ring — a
	// relay worse than one rested for its loss is worse still — and a relay
	// worse than every relay of a ring is rested against it. The cases with
	// their rings left out lead somewhere, so some relay with no case left
	// against it stands, and the book never empties the pool.
	reaches := func(from, to string) bool {
		seen := map[string]bool{from: true}
		next := []string{from}
		for len(next) > 0 {
			at := next[len(next)-1]
			next = next[:len(next)-1]
			for _, c := range against[at] {
				if c.neighbour == to {
					return true
				}
				if !seen[c.neighbour] {
					seen[c.neighbour] = true
					next = append(next, c.neighbour)
				}
			}
		}
		return false
	}
	for _, r := range relays {
		// The clearest case that stands: they come clearest first.
		for _, c := range against[r] {
			if !reaches(c.neighbour, r) {
				out = append(out, c.verdict)
				break
			}
		}
	}
	for _, v := range out {
		l.forget(v.relay)
	}
	return out
}

// relays is every relay in the book, oldest window first.
func (l *relayLedger) relays() []string {
	var out []string
	seen := map[string]bool{}
	for i := range l.windows {
		for _, s := range l.windows[(l.n+i)%relayLedgerWindows] {
			if !seen[s.relay] {
				seen[s.relay] = true
				out = append(out, s.relay)
			}
		}
	}
	return out
}

// ledgerCase is a verdict the book can give against a relay, and the
// neighbour it rests on.
type ledgerCase struct {
	neighbour string
	verdict   relayVerdict
	chance    float64
}

// judge weighs relay r against each of the others over the windows they
// shared: what r lost, against what it would have lost at the neighbour's
// rate, window by window, and how likely equal rates were to deal it its part
// of the two relays' losses (see the comment above). The bar for chance is
// shared among the neighbours it is weighed against. It returns a case for
// each neighbour r stands against, the clearest first.
func (l *relayLedger) judge(r string, relays []string) []ledgerCase {
	type pair struct {
		s                                  string
		shared, lossy, rLost, rTotal, sTot int
		expected                           float64
		parts                              []lossShare
	}
	var pairs []pair
	for _, s := range relays {
		if s == r {
			continue
		}
		p := pair{s: s}
		for _, w := range l.windows {
			rs, okR := sampleIn(w, r)
			ss, okS := sampleIn(w, s)
			if !okR || !okS {
				continue
			}
			p.shared++
			if rs.lost > 0 {
				p.lossy++
			}
			n, m := rs.rx+rs.lost, ss.rx+ss.lost
			p.rLost, p.rTotal, p.sTot = p.rLost+rs.lost, p.rTotal+n, p.sTot+m
			p.expected += float64(n) * float64(ss.lost) / float64(m)
			p.parts = append(p.parts, lossShare{lost: rs.lost + ss.lost, share: float64(n) / float64(n+m)})
		}
		if p.shared >= relayLedgerMinWindows {
			pairs = append(pairs, p)
		}
	}
	minLost, ratio, margin, over := relayLedgerMinLost, float64(relayJudgeRatio), float64(relayLedgerMargin), "TCP"
	if !l.tcp {
		minLost, ratio, margin, over = relayLedgerMinLostUDP, relayLedgerRatioUDP, relayLedgerMarginUDP, "UDP"
	}
	bar := relayLedgerChance / float64(max(len(pairs), 1))
	var out []ledgerCase
	for _, p := range pairs {
		if p.lossy < relayLedgerMinLossyWindows || p.rLost < minLost ||
			p.rTotal < relayJudgeMinPackets || p.sTot < relayJudgeMinPackets {
			continue
		}
		// best is the neighbour's rate as r was exposed to it.
		rate, best := float64(p.rLost)/float64(p.rTotal), p.expected/float64(p.rTotal)
		if rate < ratio*best || rate-best < margin {
			continue
		}
		// And not a part of the two relays' losses that equal rates would deal
		// it by chance: the neighbour carried enough to have shown the loss.
		chance := lossChanceAtMost(p.rLost, p.parts)
		if chance > bar {
			continue
		}
		out = append(out, ledgerCase{neighbour: p.s, chance: chance, verdict: relayVerdict{relay: r, rate: rate, best: best,
			evidence: fmt.Sprintf("through %s in the same windows, %d lost over %d windows where %.1f were due — by chance at most %.0e, over %s",
				p.s, p.rLost, p.shared, p.expected, chance, over)}})
	}
	slices.SortStableFunc(out, func(a, b ledgerCase) int { return cmp.Compare(a.chance, b.chance) })
	return out
}

// forget drops relay from the book: rested, its minute starts over.
func (l *relayLedger) forget(relay string) {
	for i, w := range l.windows {
		for j, s := range w {
			if s.relay == relay {
				l.windows[i] = append(w[:j:j], w[j+1:]...)
				break
			}
		}
	}
}

func sampleIn(w []relayLossSample, relay string) (relayLossSample, bool) {
	for _, s := range w {
		if s.relay == relay {
			return s, true
		}
	}
	return relayLossSample{}, false
}

// lossShare is one window of a relay weighed against others: the losses of
// the window, the relay's and theirs together, and the relay's share of the
// window's packets.
type lossShare struct {
	lost  int
	share float64
}

// lossChanceAtMost bounds the chance that x or more of the losses fall on the
// relay, each window's losses falling on it each at its share and the windows
// apart (Chernoff): for every θ ≥ 0 the chance is at most
// exp(Σ lost·log(1−share+share·e^θ) − θx), and the bound is taken at the θ
// that makes it least. An upper bound errs to no verdict. Every loss on the
// relay is the chance itself: the product of the shares.
func lossChanceAtMost(x int, parts []lossShare) float64 {
	var mean float64
	reach := 0 // the losses that can fall on the relay
	for _, p := range parts {
		if p.share > 0 {
			mean += float64(p.lost) * min(p.share, 1)
			reach += p.lost
		}
	}
	switch {
	case x <= 0 || float64(x) <= mean:
		return 1
	case x > reach:
		return 0
	case x == reach:
		var logChance float64
		for _, p := range parts {
			if p.share > 0 && p.share < 1 {
				logChance += float64(p.lost) * math.Log(p.share)
			}
		}
		return math.Exp(logChance)
	}
	// With e^θ written as 1/(e^-θ), so that no θ overflows: the log of the
	// bound, and its slope in θ.
	bound := func(theta float64) float64 {
		sum := -theta * float64(x)
		for _, p := range parts {
			switch {
			case p.share <= 0:
			case p.share >= 1:
				sum += float64(p.lost) * theta
			default:
				sum += float64(p.lost) * (theta + math.Log(p.share+(1-p.share)*math.Exp(-theta)))
			}
		}
		return sum
	}
	slope := func(theta float64) float64 {
		d := -float64(x)
		for _, p := range parts {
			if p.share > 0 {
				d += float64(p.lost) * p.share / (p.share + (1-p.share)*math.Exp(-theta))
			}
		}
		return d
	}
	// The slope rises from mean−x < 0 towards reach−x > 0: find where it
	// crosses. Any θ gives a bound; the one past the crossing is as good.
	lo, hi := 0.0, 1.0
	for i := 0; slope(hi) < 0; i++ {
		if i == 64 {
			return 1 // counts too large for the floats to find it: no verdict
		}
		lo, hi = hi, 2*hi
	}
	for range 60 {
		if mid := (lo + hi) / 2; slope(mid) < 0 {
			lo = mid
		} else {
			hi = mid
		}
	}
	return min(math.Exp(bound(hi)), 1)
}
