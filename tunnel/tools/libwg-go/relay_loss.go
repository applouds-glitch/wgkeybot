/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/binary"
	"sync"
	"time"
)

// Downlink loss per relay, read off WireGuard's own counter.
//
// WHY. The bench of 2026-10-10 (info/bench) found the downlink of a relay going
// bad while the relay itself stayed up: berlin3 → 193.203.43.42 lost 10-20% of
// what the server sent while 95.163.34.129 beside it carried 16 Mbit/s clean, and
// the uplink through both stayed fine. Every stream kept its data-plane
// handshake and its keepalive echo, so nothing in the session's health
// accounting moved — the tunnel sat at 0.5 Mbit/s on the bad relay for as long
// as the session lasted. The pair recovered after ~40 minutes of rest. Nothing
// but the loss itself tells the two relays apart, so this measures it.
//
// HOW. A WireGuard transport message carries its 64-bit counter in the clear
// (it is the AEAD nonce), strictly increasing per keypair at the sender:
//
//	byte 0     : type, 4 = transport data
//	bytes 4-7  : receiver index (LE) — the index WE assigned; a new one per keypair
//	bytes 8-15 : counter (LE)
//
// vk-turn-proxy hands the downlink to a session's streams in chunks of
// consecutive packets (-down-chunk, 8 by default), so a counter that never
// arrives sat in the same chunk as its neighbour, on the same stream, through
// the same relay. A gap shorter than a chunk, between two counters delivered
// through the same relay, is charged to that relay.
//
// Any other gap is placed on no relay; take reports it apart as unplaced. A
// short gap between two relays is a chunk's tail or the next chunk's head, and
// nothing tells which. A longer gap spans chunks, and the server walks the
// streams in map order, so the chunk before it came through whichever relay;
// it is also what an outage on the phone's own link looks like — a run of
// consecutive counters lost through every relay at once. Charged whole to the
// relay before it, a few tenths of a second of such an outage made a clean
// relay lose 5-10% of a light window, and a simulation of two clean relays
// behind a flaky link (2026-10-10) had relay_judge.go rest one of them within
// minutes. Shared out by what each relay delivered, it blamed the relay still
// delivering for one that had gone dark altogether (review, 2026-10-11).
//
// A counter is final once relayLossHorizon newer ones have arrived: the streams
// run over relays of different latency, so the downlink arrives shuffled (the
// anton48 measurements put the uplink's displacement p99 below 200 packets).

const (
	relayLossRing    = 4096
	relayLossHorizon = 1024
	// relayLossIdleFlush finalizes the tail once the downlink pauses: nothing
	// newer is coming to push it past the horizon, and what is late by then is
	// lost for any purpose a reader of TCP cares about.
	relayLossIdleFlush = 500 * time.Millisecond
	// relayLossNewKeypair is how low the counter of an unknown receiver index
	// must be to read as a fresh keypair rather than a straggler from the old.
	relayLossNewKeypair = 256
	// relayLossChunk is vk-turn-proxy's default -down-chunk: a gap this long or
	// longer cannot be placed on one relay.
	relayLossChunk = 8
)

type relayLossSample struct {
	relay    string
	rx, lost int
	// active is how many distinct seconds of the window had a packet through
	// the relay: sustained traffic against a burst (relay_collapse.go).
	active int
}

func (s relayLossSample) rate() float64 {
	if s.rx+s.lost == 0 {
		return 0
	}
	return float64(s.lost) / float64(s.rx+s.lost)
}

type relayLoss struct {
	mu sync.Mutex

	receiver uint32
	have     bool
	// left is the receiver index of the keypair before this one, and hasLeft
	// whether there has been one since the reset: its stragglers are told by
	// the index, not the counter (see observe).
	left     uint32
	hasLeft  bool
	base     uint64 // next counter to finalize
	top      uint64 // one past the highest counter seen
	seen     [relayLossRing]uint64
	relayOf  [relayLossRing]uint16
	last     uint16 // relay of the last delivered counter finalized
	lastOK   bool   // there has been one since the reset
	gap      int    // counters finalized as lost since that one
	unplaced int    // lost in gaps placed on no relay, this window
	lastAt   time.Time

	relays  []string
	index   map[string]uint16
	rx      []int
	lost    []int
	active  []int
	lastSec []int64
}

var downlinkRelayLoss = newRelayLoss()

func newRelayLoss() *relayLoss {
	return &relayLoss{index: map[string]uint16{}}
}

// reset forgets everything: a new proxy, new relays. Field by field — the
// struct holds the mutex it is called under.
func (t *relayLoss) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.receiver, t.have, t.base, t.top, t.last = 0, false, 0, 0, 0
	t.left, t.hasLeft = 0, false
	t.lastOK, t.gap, t.unplaced = false, 0, 0
	t.seen = [relayLossRing]uint64{}
	t.lastAt = time.Time{}
	t.relays, t.index, t.rx, t.lost = nil, map[string]uint16{}, nil, nil
	t.active, t.lastSec = nil, nil
}

// observe books one downlink datagram that arrived through relay. Anything but
// a WireGuard transport message is ignored.
func (t *relayLoss) observe(pkt []byte, relay string, now time.Time) {
	if len(pkt) < 16 || pkt[0] != 4 || relay == "" {
		return
	}
	receiver := binary.LittleEndian.Uint32(pkt[4:8])
	ctr := binary.LittleEndian.Uint64(pkt[8:16])

	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastAt = now
	if !t.have || receiver != t.receiver {
		// A straggler of a keypair we have already left. The counter alone
		// does not tell one: a keypair that carried fewer than
		// relayLossNewKeypair packets — an idle tunnel's — has stragglers as
		// low as a new keypair's first packets. Taken for a new keypair, one
		// such straggler switched the book back to the old keypair, and every
		// packet of the current one after it read as a straggler until the
		// next rekey (iOS review, 2026-10-11).
		if t.have && (ctr >= relayLossNewKeypair || (t.hasLeft && receiver == t.left)) {
			return
		}
		// A new keypair: what the old one still owed is final now.
		t.finalizeLocked(t.top)
		if t.have {
			t.left, t.hasLeft = t.receiver, true
		}
		t.receiver, t.have = receiver, true
		t.base, t.top = 0, 0
		t.seen = [relayLossRing]uint64{}
	}
	switch {
	case ctr < t.base:
		return // later than the horizon; already counted as lost
	case ctr >= t.base+relayLossRing:
		// A jump past the whole window: count nothing across it rather than
		// charge a relay with a gap we cannot place.
		t.base = ctr + 1 - relayLossHorizon
		t.seen = [relayLossRing]uint64{}
		if t.top < t.base {
			t.top = t.base
		}
	}
	slot := ctr % relayLossRing
	idx := t.relayIndexLocked(relay)
	if sec := now.Unix(); t.lastSec[idx] != sec {
		t.lastSec[idx] = sec
		t.active[idx]++
	}
	t.seen[slot] = ctr + 1
	t.relayOf[slot] = idx
	if ctr+1 > t.top {
		t.top = ctr + 1
	}
	if t.top > relayLossHorizon {
		t.finalizeLocked(t.top - relayLossHorizon)
	}
}

func (t *relayLoss) relayIndexLocked(relay string) uint16 {
	if i, ok := t.index[relay]; ok {
		return i
	}
	i := uint16(len(t.relays))
	t.index[relay] = i
	t.relays = append(t.relays, relay)
	t.rx = append(t.rx, 0)
	t.lost = append(t.lost, 0)
	t.active = append(t.active, 0)
	t.lastSec = append(t.lastSec, 0)
	return i
}

// finalizeLocked settles every counter below upTo.
func (t *relayLoss) finalizeLocked(upTo uint64) {
	for ; t.base < upTo; t.base++ {
		slot := t.base % relayLossRing
		if t.seen[slot] == t.base+1 {
			t.placeGapLocked(t.relayOf[slot])
			t.last, t.lastOK = t.relayOf[slot], true
			t.rx[t.last]++
			t.seen[slot] = 0
			continue
		}
		t.gap++
	}
}

// placeGapLocked settles the gap that a counter delivered through relay next
// has just closed.
func (t *relayLoss) placeGapLocked(next uint16) {
	switch {
	case t.gap == 0:
	case t.lastOK && t.last == next && t.gap < relayLossChunk:
		t.lost[next] += t.gap
	default:
		t.unplaced += t.gap
	}
	t.gap = 0
}

// take returns what each relay delivered and lost since the previous take, and
// what was lost on no relay in particular, and starts the next window.
func (t *relayLoss) take(now time.Time) (samples []relayLossSample, unplaced int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.have && now.Sub(t.lastAt) >= relayLossIdleFlush {
		t.finalizeLocked(t.top)
	}
	unplaced, t.unplaced = t.unplaced, 0
	out := make([]relayLossSample, 0, len(t.relays))
	for i, relay := range t.relays {
		if t.rx[i]+t.lost[i] > 0 {
			out = append(out, relayLossSample{relay: relay, rx: t.rx[i], lost: t.lost[i], active: t.active[i]})
		}
		t.rx[i], t.lost[i], t.active[i] = 0, 0, 0
	}
	return out, unplaced
}
