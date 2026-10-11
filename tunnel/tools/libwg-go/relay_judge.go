/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

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
)

type relayJudge struct {
	strikes map[string]int
}

// relayVerdict is a relay judged bad, with the two rates the verdict rests on.
type relayVerdict struct {
	relay      string
	rate, best float64
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
	best := counted[0].rate()
	for _, s := range counted[1:] {
		best = min(best, s.rate())
	}
	var out []relayVerdict
	for _, s := range counted {
		r := s.rate()
		if s.lost < relayJudgeMinLost || r < relayJudgeRatio*best || r-best < relayJudgeMargin {
			delete(j.strikes, s.relay)
			continue
		}
		j.strikes[s.relay]++
		if j.strikes[s.relay] >= relayJudgeStrikes {
			delete(j.strikes, s.relay)
			out = append(out, relayVerdict{relay: s.relay, rate: r, best: best})
		}
	}
	return out
}
