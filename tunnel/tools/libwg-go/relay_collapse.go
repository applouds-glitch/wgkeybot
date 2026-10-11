/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import "time"

// A relay's downlink collapsing under the sessions that run on it — told, and
// logged, but no longer acted on.
//
// relay_judge.go compares relays with each other and rests the one that loses
// alone. With a single relay — one in the list, the other resting, or TurnIP
// pinned — there is nothing to compare with, and the soaks of 2026-10-10 found
// the downlink collapsing exactly there: a session carrying 15-17 Mbit/s through
// ten streams fell within one 20-second chunk to 1-3 Mbit/s (after 3.0 GB in
// 36 min the first time, 4.8 GB in 64 min the second — no fixed volume), and
// stayed there. A new connection to the very same relay, same credentials,
// was back at 13-14 Mbit/s a couple of minutes later.
//
// What tells a collapse from a session that simply carries little: loss at a
// low rate. A healthy relay loses next to nothing until TCP probes its
// per-allocation ceiling, and there it loses plenty — 5-20% at ~140 packets/s
// per stream — which is no collapse at all. A collapsed one loses 2-30% at
// 10-35 packets/s per stream. So the verdict needs both, for
// relayCollapseStrikes windows in a row: delivery below relayCollapseMaxRate per
// stream on that relay, and loss of at least relayCollapseMinLoss. And the
// traffic has to be sustained — packets in relayCollapseMinActive seconds of
// the window: a page load is a burst that loses its slow-start overshoot and
// averages a low rate over the window, while a collapsed download keeps
// trickling every second.
//
// It used to move the relay's sessions onto fresh allocations on the same
// relay. The first time it fired in the field (2026-10-11) it did so three
// times in six minutes across both relays of a pair, and none of it helped: the
// fresh allocations lost as much, and some never got through their handshake.
// Nor did a fresh connection help on the pair that went bad on 2026-10-10. The
// one recovery seen after a reconnect, on the soak of that day, may as well
// have been the path recovering by itself. And the rate it goes by is the
// window's settled counters, which trail the live traffic by up to a horizon of
// packets — ten seconds at a hundred a second. So it only logs, for the field
// logs to say whether a cure is worth having.
//
// It speaks only when relay_judge.go cannot: while two relays carry the
// session, one losing alone is that judge's to rest, and both losing alike is
// the path they share — the phone's own network — which fresh allocations do
// not cure. Judged per relay regardless, a simulation of two clean relays behind
// a flaky link (2026-10-10) had both recycled within two minutes, and a real bad
// relay had its sessions recycled onto itself twenty seconds before the relative
// judge moved them off it.

const (
	// relayCollapseMaxRate is delivered packets per second per stream below
	// which loss means collapse. Healthy saturation ran at ~140, collapse at
	// 10-35.
	relayCollapseMaxRate = 50
	relayCollapseMinLoss = 0.03
	// relayCollapseMinPackets keeps a quiet window out of it: a handful of
	// packets says nothing about a rate.
	relayCollapseMinPackets = 200
	relayCollapseMinActive  = 8 // of the 10 seconds of a window
	relayCollapseStrikes    = 2
)

type relayCollapseJudge struct {
	strikes map[string]int
}

// step weighs one window of relayJudgeEvery. streams is how many sessions run
// on each relay now. It returns the relays whose downlink has collapsed.
func (j *relayCollapseJudge) step(samples []relayLossSample, streams map[string]int, window time.Duration) []string {
	if j.strikes == nil {
		j.strikes = map[string]int{}
	}
	carrying := 0
	for _, s := range samples {
		if s.rx+s.lost >= relayJudgeMinPackets {
			carrying++
		}
	}
	if carrying > 1 {
		clear(j.strikes) // relay_judge.go has relays to compare
		return nil
	}
	seen := map[string]bool{}
	var collapsed []string
	for _, s := range samples {
		seen[s.relay] = true
		n := streams[s.relay]
		if n <= 0 || s.rx+s.lost < relayCollapseMinPackets {
			// A quiet window is no evidence either way: the count stands.
			continue
		}
		if s.active < relayCollapseMinActive {
			delete(j.strikes, s.relay) // bursts: whatever this is, not a collapse
			continue
		}
		perStream := float64(s.rx) / window.Seconds() / float64(n)
		if perStream >= relayCollapseMaxRate || s.rate() < relayCollapseMinLoss {
			delete(j.strikes, s.relay)
			continue
		}
		j.strikes[s.relay]++
		if j.strikes[s.relay] >= relayCollapseStrikes {
			delete(j.strikes, s.relay)
			collapsed = append(collapsed, s.relay)
		}
	}
	for relay := range j.strikes {
		if !seen[relay] {
			delete(j.strikes, relay) // no traffic through it any more
		}
	}
	return collapsed
}
