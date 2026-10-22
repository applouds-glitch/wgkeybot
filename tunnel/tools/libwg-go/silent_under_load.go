/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"time"
)

// A stream that goes silent under load while its siblings hear their relays
// leaves the rotation at once, not after dispatchStaleAfter.
//
// WHY. Field log of 2026-10-20/21 (POCO 2602BPC18G, v2.2.0, a cellular
// network over UDP, nine streams on two relays): a relay went deaf under its
// streams time after time. Each deafness cost ~35 s — until dispatchStale
// (heardAge > dispatchStaleAfter) took the stream out of the rotation and the
// WGH1 report told the server to skip it — during which the dispatcher and the
// server went on sending a ninth of the traffic into a void: 14 such
// exclusions in eleven minutes (16:08-16:19) and 12 in eight (06:28-06:36),
// 508 and 431 stream-seconds of 1/9 of the downlink lost, which TCP inside
// the tunnel read as ~11% loss nearly all the time — the user saw the internet
// cutting out. The deaf-relay verdict (relay_deaf.go) rests the relay only
// after three deaf sessions in ten minutes; the first two are paid in full.
// 35 s is the keepalive echo's measure (keepaliveInterval plus the spread and
// a round trip) and cannot be shortened for an idle stream: the echo is all
// it hears.
//
// HOW. Under load the silence has witnesses. vk-turn-proxy hands the downlink
// to a session's streams in chunks of eight (-down-chunk) in strict
// round-robin order over a stable snapshot, falling back to the next stream
// only when the target's queue is full (server/downstream_queue.go): a
// rotation that has given two other streams three chunks each has visited
// this stream's slot at least twice in between, and a stream whose queue
// takes packets gets its chunk there. So a stream that has heard nothing for
// silentUnderLoadAfter, while silentUnderLoadWitnesses other ready streams
// have each heard their relay within silentUnderLoadEcho and received
// silentUnderLoadPackets packets since this stream's last one, is not waiting
// for traffic: what was sent into it is not coming out. Three chunks a
// witness, not one, so that a stream on its way back — heard again, with the
// report readmitting it still on its way to the server, up to a second — is
// not found silent again by the chunks its siblings got while the server was
// still skipping it. A witness may be on any relay: it vouches for the path,
// the deaf stream's relay is what the verdict is against.
//
// The verdict is the dispatcher's stale, reversible as before: the stream
// stays ready, keeps its keepalive, and the next packet it hears — the
// server's echo, at the latest — puts it back into the rotation and the WGH1
// mask. It is tied to the silence it was given for (streamActivity holds the
// lastHeard it judged), so a packet arriving lifts it without a turn of the
// judge; the judge's next turn reports the return, so that an episode shorter
// than the dispatcher's scan (staleWatch, a second) has both its lines.
//
// Not judged:
//
//   - a stream stale by age already: dispatchStaleAfter owns it;
//   - a stream whose silence has a host freeze in it (frozeSinceHeard): after
//     a thaw every stream is equally silent, the post-wake probe asks the relay
//     (wake_probe.go), and the first siblings to echo must not convict the
//     rest. A freeze the keepalive loop did not see (shorter than freezeSlack)
//     is caught by the judge's own clock: a turn late by silentUnderLoadFreeze
//     forgets what the siblings had before it, so chunks from before the
//     freeze count for nothing;
//   - light traffic: at 0-2 packets/s a stream — the field log's quiet
//     minutes — three chunks a witness take longer, and the verdict comes
//     later or not at all, never later than dispatchStaleAfter: no worse than
//     before.
//
// Over TCP the same: a flow whose downlink stalls for seconds while its
// neighbours flow is retransmitting or dead, and either way the packets are
// better placed elsewhere until it is heard again.

const (
	// silentUnderLoadAfter is the silence that calls for witnesses. It is
	// above the way back into the rotation for a stream heard again — the
	// reporter's tick (a second), a mobile round trip and the rotation
	// reaching its slot — at any load that can produce the witnesses in it.
	silentUnderLoadAfter = 4 * time.Second
	// silentUnderLoadEcho: a witness has heard its relay this recently — the
	// path is alive now, not only since the silence began.
	silentUnderLoadEcho = 2 * time.Second
	// silentUnderLoadPackets: three of the server's chunks (relayLossChunk,
	// vk-turn-proxy's -down-chunk) a witness.
	silentUnderLoadPackets = 3 * relayLossChunk
	// silentUnderLoadWitnesses: two streams, so that one stream's good fortune
	// — a chunk that fell back to it from a full queue — convicts nobody.
	silentUnderLoadWitnesses = 2
	// silentUnderLoadTick is how often the judge looks; the verdict comes
	// within a tick of the silence reaching silentUnderLoadAfter.
	silentUnderLoadTick = 500 * time.Millisecond
	// silentUnderLoadFreeze: a turn this much later than its tick was a host
	// freeze, not scheduler jitter.
	silentUnderLoadFreeze = time.Second
)

// silentUnderLoadJudge keeps, per stream, what every sibling had heard when
// the stream's present silence was first seen, and gives the verdict once the
// silence and the witnesses are enough. One goroutine's; nothing is shared.
type silentUnderLoadJudge struct {
	n    int
	last time.Time // the previous turn

	// Per stream i: the session (its activity) and the lastHeard its row was
	// taken for, and the row — per sibling j, the session and the packets it
	// had heard at the time. A sibling in a new session since has heard all of
	// its packets since.
	rowAct   []*streamActivity
	rowHeard []int64
	seenAct  []*streamActivity // n×n
	seen     []uint64          // n×n

	// Scratch for one turn: every stream's session, lastHeard and packets.
	act   []*streamActivity
	heard []int64
	count []uint64
}

// silentUnderLoadVerdict is one stream found silent under load.
type silentUnderLoadVerdict struct {
	index     int // in the judged streams
	id        int
	silent    time.Duration
	witnesses []int // stream ids
	packets   int   // what the witnesses heard since, together
}

// silentUnderLoadReturn is a stream heard again after a verdict, in the same
// session: the silence the verdict was given for, now over.
type silentUnderLoadReturn struct {
	id     int
	silent time.Duration
}

func newSilentUnderLoadJudge(n int) *silentUnderLoadJudge {
	return &silentUnderLoadJudge{
		n:        n,
		rowAct:   make([]*streamActivity, n),
		rowHeard: make([]int64, n),
		seenAct:  make([]*streamActivity, n*n),
		seen:     make([]uint64, n*n),
		act:      make([]*streamActivity, n),
		heard:    make([]int64, n),
		count:    make([]uint64, n),
	}
}

// judge takes one turn over streams at now and returns the verdicts it gave,
// each marked on its stream's session (markSilentUnderLoad), and the streams
// heard again since a verdict. len(streams) must be the n it was made for.
func (j *silentUnderLoadJudge) judge(streams []*stream, now time.Time) (verdicts []silentUnderLoadVerdict, back []silentUnderLoadReturn) {
	n := j.n
	// A turn that comes long after its tick is a freeze the process slept
	// through: what the siblings heard before it says nothing about a stream
	// silent across it. Every row is taken afresh.
	froze := !j.last.IsZero() && now.Sub(j.last) > silentUnderLoadTick+silentUnderLoadFreeze
	j.last = now

	for i, st := range streams {
		j.act[i] = nil
		if !st.ready.Load() {
			continue
		}
		if a := st.activity.Load(); a != nil {
			j.act[i] = a
			j.heard[i] = a.lastHeard.Load()
			j.count[i] = a.heardCount()
		}
	}

	for i, st := range streams {
		a := j.act[i]
		if a == nil {
			j.rowAct[i] = nil
			continue
		}
		if froze || j.rowAct[i] != a || j.rowHeard[i] != j.heard[i] {
			// A packet has arrived, or a new session has begun: the silence,
			// if any, starts here, and so does what the siblings hear in it.
			// A packet ending a silence judged in this session is the return.
			if j.rowAct[i] == a && j.rowHeard[i] != j.heard[i] && a.silentUnderLoad.Load() == j.rowHeard[i] {
				back = append(back, silentUnderLoadReturn{id: st.id, silent: time.Duration(j.heard[i] - j.rowHeard[i])})
			}
			j.rowAct[i], j.rowHeard[i] = a, j.heard[i]
			copy(j.seenAct[i*n:(i+1)*n], j.act)
			copy(j.seen[i*n:(i+1)*n], j.count)
			continue
		}
		if a.frozeSinceHeard() || a.silentUnderLoad.Load() == j.heard[i] {
			continue
		}
		silent := now.Sub(time.Unix(0, j.heard[i]))
		if silent < silentUnderLoadAfter || silent > dispatchStaleAfter {
			continue
		}
		var witnesses []int
		packets := 0
		for k, w := range streams {
			if k == i || j.act[k] == nil || now.Sub(time.Unix(0, j.heard[k])) > silentUnderLoadEcho {
				continue
			}
			since := j.count[k]
			if j.seenAct[i*n+k] == j.act[k] {
				since -= j.seen[i*n+k]
			}
			if since < silentUnderLoadPackets {
				continue
			}
			witnesses = append(witnesses, w.id)
			packets += int(since)
		}
		if len(witnesses) < silentUnderLoadWitnesses {
			continue
		}
		a.markSilentUnderLoad(j.heard[i])
		verdicts = append(verdicts, silentUnderLoadVerdict{index: i, id: st.id, silent: silent, witnesses: witnesses, packets: packets})
	}
	return verdicts, back
}

// line is the verdict for the log: the silence, the witnesses and what they
// got, and how much sooner than the age rule this came.
func (v silentUnderLoadVerdict) line() string {
	return fmt.Sprintf("[DISPATCH] stream %d silent %v while siblings %v got %d packets — skipped %v before the %v rule",
		v.id, v.silent.Round(100*time.Millisecond), v.witnesses, v.packets,
		(dispatchStaleAfter - v.silent).Round(time.Second), dispatchStaleAfter)
}

// runSilentUnderLoadJudge judges streams every silentUnderLoadTick until ctx
// ends and logs each verdict as it is given, and each return. The dispatcher
// and the WGH1 reporter read the verdict off the stream (dispatchStale); the
// watch of stale transitions (staleWatch) leaves both lines to this.
func runSilentUnderLoadJudge(ctx context.Context, streams []*stream) {
	j := newSilentUnderLoadJudge(len(streams))
	tick := time.NewTicker(silentUnderLoadTick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		// The clock, not the tick's stamp: a tick that waited out a freeze in
		// the channel carries the time it was due.
		verdicts, back := j.judge(streams, time.Now())
		for _, r := range back {
			turnLog("[DISPATCH] stream %d heard its relay again after %v — back in rotation", r.id, r.silent.Round(time.Second))
		}
		for _, v := range verdicts {
			turnLog("%s", v.line())
			// Over TCP, what the socket looked like at that moment (nothing over UDP).
			if line := relaySockets.silentSocketLine(streams[v.index]); line != "" {
				turnLog("%s", line)
			}
		}
	}
}
