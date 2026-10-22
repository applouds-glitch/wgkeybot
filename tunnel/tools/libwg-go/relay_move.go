/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sort"
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
// Losing here is a lower bar than a verdict: a relay weighed in the window
// (relayJudgeMinPackets) that lost relayJudgeRatio times the best relay's rate
// and relayMoveLossyMargin above it. It only orders a redial. The relays it
// would have put behind in the bench lost 0.6-2.3% of 349-676 packets — under
// the verdict's ten packets and two points — where the clean relays of the
// same runs lost 0-0.2% in their ordinary windows. A relay the window did not
// weigh — no stream on it, or a quiet one — is not losing: it may be the best
// place to go.

const (
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
// attempt: the relays losing at the time, to be dialed last.
type relayMove struct {
	lossy map[string]bool
	at    time.Time
}

// takeMoveLossy returns, once, the relays to dial last in the attempt after a
// move off a rested relay, unless the move is older than relayMoveLossyFresh.
func (s *stream) takeMoveLossy(now time.Time) map[string]bool {
	m := s.moveLossy.Swap(nil)
	if m == nil || now.Sub(m.at) > relayMoveLossyFresh {
		return nil
	}
	return m.lossy
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
