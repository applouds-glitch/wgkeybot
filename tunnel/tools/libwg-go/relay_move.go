/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Where a session moved off a rested relay goes: not onto a relay that is
// losing the downlink in the same window.
//
// WHY. Bench of 2026-10-22 (Pixel 6a on home Wi-Fi, berlin3, TCP, ten streams
// over 193.203.43.21, 193.203.43.42, 90.156.234.252, 90.156.236.92 and four
// relays of 95.163.34.0/24): for twenty seconds from 07:48:35 every relay
// outside 95.163.34.0/24 lost downlink — .42 3.6% then 3.3%, .252 1.9% then
// 2.3%, .92 0.8% then 1.7%, .21 1.3% then 0.6% — while the four 95.163.34.x
// lost nothing. The judge rested .42 and moved its two sessions onto .252 and
// .92: the spread's picks for streams 1 and 9 among the seven relays left
// (assignRelays), both losing in the very window of the verdict, with four
// clean relays beside them. The relays outside 95.163.34.0/24 went bad
// together there, as they were all bad together in the survey of 2026-10-11
// from berlin3 while every 95.163.34.x was good: the relay the spread hands a
// rested relay's session to may well be losing too.
//
// HOW. Every window it weighs, the loss judge also notes which relays are
// losing in it (lossyRelays). A session moved off a rested relay — by the loss
// judge or by the deaf-relay rule (relay_deaf.go) — carries the latest such set
// into the attempt that follows, and that attempt dials the losing relays after
// the clean ones (assignRelaysAround): the spread is kept among the relays that
// are not losing, the losing ones stay its failover. Only that one attempt: a
// stream that reconnects for any other reason spreads as before, and a set
// older than relayMoveLossyFresh says nothing about the window it would be used
// in.
//
// And not all onto one relay. The attempt after a move spread by the stream's
// id over the relays of its tier (assignRelaysAround), whatever already ran
// there: on the bench, with .42 resting and the four 95.163.34.x clean, streams
// 1 and 9 both went to .179 (1 % 4 = 9 % 4), where stream 5 already was —
// three sessions on one clean relay, one on each of the other three (review
// 2026-10-22). So the move picks each session's head itself (moveHead): the
// least loaded of its link's usable relays by the sessions running there now
// (liveSessions), among those not losing when any is not, each pick charged to
// its relay before the next session's — the sessions moved together, and those
// of two relays rested in one judge turn, see one another's. Behind them all go
// the relays full for the session's credential: crowded with its ghosts
// (crowdedRelays), as the attempt would put them, or holding relayMoveQuota of
// its allocations, live and ghosts, with the picks of the turn — balancing
// load, two streams of one credential must not be sent where only one fits
// (codex review 2026-10-22). The attempt dials that head first while it is
// still in its first tier (headFirst): not crowded, resting or demoted since.
// Ties go round by the stream's id, as the spread does.
//
// Losing here is a lower bar than a verdict: a relay weighed in the window
// (relayJudgeMinPackets) that lost relayJudgeRatio times the best relay's rate
// and relayMoveLossyMargin above it. It only orders a redial. The relays it
// would have put behind in the bench lost 0.6-2.3% of 349-676 packets — under
// the verdict's ten packets and two points — where the clean relays of the
// same runs lost 0-0.2% in their ordinary windows. A relay the window did not
// weigh — no stream on it, or a quiet one — is not losing: it may be the best
// place to go.

const (
	// relayMoveQuota is VK's quota of about ten allocations a credential holds
	// on a relay (orphanSteerAt is half of it): a move does not pick a relay
	// where the credential has as many already.
	relayMoveQuota = 2 * orphanSteerAt
	// relayMoveLossyMargin: half a point above the best relay. The bench's
	// losing relays were at 0.6% and up, its clean ones at 0.2% and under.
	relayMoveLossyMargin = 0.005
	// relayMoveLossyFresh: a set is the window's for two judge turns — the
	// sessions moved off a relay redial within relayRecycleGap of each other,
	// and a deaf verdict falls anywhere between two turns.
	relayMoveLossyFresh = 2 * relayJudgeEvery
)

// lossyRelays is the set of relays losing downlink in one window against the
// best relay weighed in it, nil if none is. With fewer than two relays weighed
// there is nothing to compare against, and no relay stands out.
func lossyRelays(samples []relayLossSample) map[string]bool {
	var counted []relayLossSample
	for _, s := range samples {
		if s.rx+s.lost >= relayJudgeMinPackets {
			counted = append(counted, s)
		}
	}
	if len(counted) < 2 {
		return nil
	}
	best := counted[0].rate()
	for _, s := range counted[1:] {
		best = min(best, s.rate())
	}
	var out map[string]bool
	for _, s := range counted {
		r := s.rate()
		if s.lost == 0 || r < relayJudgeRatio*best || r-best < relayMoveLossyMargin {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[s.relay] = true
	}
	return out
}

// relayLossyNow is the latest window's set of losing relays and when the judge
// weighed it. The set is never changed once published.
var relayLossyNow struct {
	sync.Mutex
	at  time.Time
	set map[string]bool
}

// noteLossyRelays publishes the set of relays losing in the window weighed at now.
func noteLossyRelays(set map[string]bool, now time.Time) {
	relayLossyNow.Lock()
	relayLossyNow.at, relayLossyNow.set = now, set
	relayLossyNow.Unlock()
}

// lossyRelaysAt is the set of relays losing in the latest window, if that
// window is no older than relayMoveLossyFresh at now.
func lossyRelaysAt(now time.Time) map[string]bool {
	relayLossyNow.Lock()
	defer relayLossyNow.Unlock()
	if relayLossyNow.set == nil || now.Sub(relayLossyNow.at) > relayMoveLossyFresh {
		return nil
	}
	return relayLossyNow.set
}

// relayMove is what a stream moved off a rested relay carries into its next
// attempt: the relays losing at the time, to be dialed last, and the relay to
// dial first (moveHead).
type relayMove struct {
	lossy map[string]bool
	head  string
	at    time.Time
}

// takeMove returns, once, what the attempt after a move off a rested relay
// dials by, unless the move is older than relayMoveLossyFresh; nil without one.
func (s *stream) takeMove(now time.Time) *relayMove {
	m := s.move.Swap(nil)
	if m == nil || now.Sub(m.at) > relayMoveLossyFresh {
		return nil
	}
	return m
}

// relayLoad is what the moves of a judge turn weigh, charged with each pick:
// the sessions on each relay, and the picks of each credential on each.
type relayLoad struct {
	sessions map[string]int
	picked   map[relayIdentity]int
}

// liveRelayLoad is the sessions running on each relay now (liveSessions), with
// no pick yet.
func liveRelayLoad() *relayLoad {
	liveSessions.Lock()
	defer liveSessions.Unlock()
	load := &relayLoad{sessions: make(map[string]int, len(liveSessions.byRelay)), picked: map[relayIdentity]int{}}
	for relay, set := range liveSessions.byRelay {
		load.sessions[relay] = len(set)
	}
	return load
}

// credsHeldOn is, for each of relays, how many allocations of user's are held
// there: live, and ghosts under a mark in force (orphaned_allocations.go) — an
// allocation its network left is both until its session closes, and counted
// once.
func credsHeldOn(user string, relays []string, now time.Time) map[string]int {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	held := make(map[string]int, len(relays))
	for _, relay := range relays {
		key := relayIdentity{user: user, relay: relay}
		n := allocationBook.live[key]
		if till, ok := allocationBook.orphanedTill[key]; ok && now.Before(till) {
			n += allocationBook.orphans[key]
		}
		held[relay] = n
	}
	for r := range allocationBook.tracked {
		if _, ok := held[r.key.relay]; ok && r.key.user == user && countedLocked(r.key, r, now) {
			held[r.key.relay]--
		}
	}
	return held
}

// moveHead is the relay a session of stream id on user's credential, moved off
// left and dialing relays, goes to first: the least loaded by load of its
// usable relays other than left — among those not full for the credential and
// not losing in the window (lossy) when any is, then those not full, then the
// rest — ties going round by id. load is charged with the pick. "" if there is
// nowhere to go.
func moveHead(relays []string, left string, id int, user string, lossy map[string]bool, load *relayLoad, now time.Time) string {
	sorted := append([]string(nil), relays...)
	sort.Strings(sorted)
	sorted = slices.Compact(sorted)
	crowded := crowdedRelays(user, sorted, now)
	held := credsHeldOn(user, sorted, now)
	var clean, losing, full []string
	for _, relay := range sorted {
		switch {
		case relay == left || !relayUsable(relay, now):
		case crowded[relay] || held[relay]+load.picked[relayIdentity{user: user, relay: relay}] >= relayMoveQuota:
			full = append(full, relay)
		case lossy[relay]:
			losing = append(losing, relay)
		default:
			clean = append(clean, relay)
		}
	}
	var tier []string
	for _, t := range [][]string{clean, losing, full} {
		if len(t) > 0 {
			tier = t
			break
		}
	}
	if len(tier) == 0 {
		return ""
	}
	least := load.sessions[tier[0]]
	for _, relay := range tier[1:] {
		least = min(least, load.sessions[relay])
	}
	var ties []string
	for _, relay := range tier {
		if load.sessions[relay] == least {
			ties = append(ties, relay)
		}
	}
	head := ties[id%len(ties)]
	load.sessions[head]++
	load.picked[relayIdentity{user: user, relay: head}]++
	return head
}

// headFirst is order with head moved to its front, if head is still in its
// first tier — usable, crowded as the relay in front is or not, losing as it
// is or not (assignRelaysAround) — and order otherwise.
func headFirst(order []string, head string, crowded, lossy map[string]bool, now time.Time) []string {
	if head == "" || len(order) == 0 || !relayUsable(head, now) ||
		crowded[head] != crowded[order[0]] || lossy[head] != lossy[order[0]] {
		return order
	}
	i := slices.Index(order, head)
	if i <= 0 {
		return order
	}
	copy(order[1:i+1], order[:i])
	order[0] = head
	return order
}

// movedHead is where one moved session goes first.
type movedHead struct {
	id    int
	relay string
}

// relayMoveOut is what recycleRelaySessions did: how many sessions it moved
// and how many stay, where each moved one goes first, and the relays they dial
// last for losing in the window.
type relayMoveOut struct {
	moved, stayed int
	heads         []movedHead
	last          []string
}

// note is the tail of a verdict's line naming where the moved sessions go
// first and, if any, the relays they dial last.
func (o relayMoveOut) note() string {
	if o.moved == 0 {
		return ""
	}
	var b strings.Builder
	for i, h := range o.heads {
		if i == 0 {
			b.WriteString("; first to ")
		} else {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (stream %d)", h.relay, h.id)
	}
	if len(o.last) > 0 {
		fmt.Fprintf(&b, "; they dial %s last, losing in this window", strings.Join(o.last, ", "))
	}
	return b.String()
}

// dialedLast is the relays of lossy, other than the one being left and those
// resting, in canonical order: what the sessions moved off left will dial last.
func dialedLast(lossy map[string]bool, left string, now time.Time) []string {
	var out []string
	for relay := range lossy {
		if relay != left && relayUsable(relay, now) {
			out = append(out, relay)
		}
	}
	sort.Strings(out)
	return out
}
