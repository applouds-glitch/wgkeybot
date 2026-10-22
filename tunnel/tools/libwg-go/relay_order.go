/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"math"
	"math/bits"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// Downlink reordering, read off WireGuard's own counter (relay_loss.go) — for
// the log only.
//
// WHY. The A/B of 2026-10-21 (Pixel 6a, Rostelecom LTE, 100 MB downloads over
// UDP) had ten streams on one relay at 15.4 Mbit/s and the same ten spread over
// two relays or six at 12.9, with three to four times as many seconds below
// 8 Mbit/s — and no relay losing more than 0.7%. Over TCP the spread won. One
// explanation is the order the downlink arrives in: vk-turn-proxy deals it out
// to the streams in chunks of consecutive packets (relay_loss.go), streams over
// relays of different delay deliver the chunks shuffled, and the TCP reading
// the tunnel takes a segment that comes in behind three newer ones for lost. So
// this measures how shuffled the downlink is, apart from how much of it is
// lost.
//
// What it found the same day (Pixel 6a on an iPhone hotspot, 100 MB downloads):
// the downlink is shuffled on one relay already — ten streams on it delivered
// 52-55% of the packets behind a newer counter, by 15-17 counters at the
// median and ~150 at p95, since the chunks go out over ten allocations. Five
// and five over two relays made it 60%, the holes 8 ms at the median against
// 4-5: nearly every packet through the slower relay came in late. The speed
// did not tell the layouts apart (16.1 and 15.8 Mbit/s on one relay, 15.7-16.0
// over two, one download at 10.2), nor did the duplicate segments the phone's
// TCP saw — the sender's spurious retransmits.
//
// HOW. Per receiver index — the counter starts over with every keypair — a
// counter below the highest one seen arrives late: its lag is how far below,
// and it closes a hole that opened when the first counter past it arrived,
// through the relay that overtook it. A hole the window passes, or that stays
// open relayOrderHoleExpire, never came; a counter seen twice is a duplicate.
// The arrival time is taken before the lock (observeDownlink): ten RX
// goroutines queue on it, and the hole lifetimes are what a reorder buffer
// would have to wait. The order is the lock's, which is near enough the order
// the datagrams go on to WireGuard in.

const (
	relayOrderRing = 4096
	// relayOrderKeypairs is how many receiver indexes are tracked at once: the
	// current keypair and the stragglers of the ones before it.
	relayOrderKeypairs = 4
	// relayOrderHoleExpire writes a hole off: TCP has long given the segment up.
	relayOrderHoleExpire = 2 * time.Second
	// relayOrderDupAcks is the lag from which a late segment made the TCP
	// receiver send the duplicate ACKs a sender without RACK retransmits on.
	relayOrderDupAcks    = 3
	relayOrderPairsShown = 6
)

const (
	orderEmpty uint8 = iota // not tracked: the book started mid-keypair
	orderHole
	orderGot
	orderWrittenOff
)

// relayOrderBook is one receiver index's window of counters.
type relayOrderBook struct {
	receiver uint32
	top      uint64 // one past the highest counter seen
	used     time.Duration
	state    [relayOrderRing]uint8
	opened   [relayOrderRing]time.Duration // when the hole opened
	opener   [relayOrderRing]uint16        // the relay of the counter that opened it
}

type relayOrderPair struct {
	ahead, behind string // ahead's counter overtook behind's
	n             int
}

type relayOrderRelay struct {
	relay     string
	got, late int
}

// relayOrderSample is one window of the downlink's order.
type relayOrderSample struct {
	span time.Duration
	// got counts unique packets, late those of them below the highest counter
	// seen, lateDupAcks those late by relayOrderDupAcks or more.
	got, late, lateDupAcks int
	dup                    int
	// neverCame counts holes written off; afterWriteOff the counters that came
	// after all, or older than the window.
	neverCame, afterWriteOff int
	lag                      relayOrderHist // counters, over the late
	hole                     relayOrderHist // microseconds, over the late
	relays                   []relayOrderRelay
	pairs                    []relayOrderPair // most first
}

type relayOrder struct {
	mu *sync.Mutex // its own, or the downlink's, shared with the loss book (downlinkMu)

	epoch time.Time
	since time.Time // the window's start
	books []*relayOrderBook

	got, late, lateDupAcks, dup int
	neverCame, afterWriteOff    int
	lag, hole                   relayOrderHist

	relays    []string
	index     map[string]uint16
	relayN    []relayOrderRelay
	overtaken map[[2]uint16]int
}

// downlinkMu guards both books of the downlink, the loss (relay_loss.go) and
// the order, as one: the RX goroutines take it once a datagram
// (observeDownlink), where a lock a book was two in a row on every packet,
// each parsing the same header (review 2026-10-22).
var downlinkMu sync.Mutex

var downlinkRelayOrder = newRelayOrderUnder(&downlinkMu, time.Now())

func newRelayOrder(now time.Time) *relayOrder { return newRelayOrderUnder(new(sync.Mutex), now) }

// newRelayOrderUnder is a book guarded by mu, which may guard another book too.
func newRelayOrderUnder(mu *sync.Mutex, now time.Time) *relayOrder {
	return &relayOrder{mu: mu, epoch: now, since: now, index: map[string]uint16{}, overtaken: map[[2]uint16]int{}}
}

// observeDownlink books one downlink datagram that arrived through relay for
// its loss (relay_loss.go) and its order: one parse of the header, one lock.
func observeDownlink(pkt []byte, relay string) {
	receiver, ctr, ok := wgTransportHeader(pkt, relay)
	if !ok {
		return
	}
	now := time.Now()
	downlinkMu.Lock()
	downlinkRelayLoss.observeLocked(receiver, ctr, relay, now)
	downlinkRelayOrder.observeLocked(receiver, ctr, relay, now)
	downlinkMu.Unlock()
}

// reset forgets everything: a new proxy, new relays, new keypairs.
func (t *relayOrder) reset(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.epoch, t.since, t.books = now, now, nil
	t.clearWindowLocked()
	t.relays, t.index, t.relayN = nil, map[string]uint16{}, nil
}

func (t *relayOrder) clearWindowLocked() {
	t.got, t.late, t.lateDupAcks, t.dup = 0, 0, 0, 0
	t.neverCame, t.afterWriteOff = 0, 0
	t.lag, t.hole = relayOrderHist{}, relayOrderHist{}
	for i := range t.relayN {
		t.relayN[i].got, t.relayN[i].late = 0, 0
	}
	t.overtaken = map[[2]uint16]int{}
}

// observe books one downlink datagram that arrived through relay at now.
// Anything but a WireGuard transport message is ignored.
func (t *relayOrder) observe(pkt []byte, relay string, now time.Time) {
	if receiver, ctr, ok := wgTransportHeader(pkt, relay); ok {
		t.mu.Lock()
		t.observeLocked(receiver, ctr, relay, now)
		t.mu.Unlock()
	}
}

// observeLocked is observe with the header parsed, under mu.
func (t *relayOrder) observeLocked(receiver uint32, ctr uint64, relay string, now time.Time) {
	// This runs before wireguard-go has authenticated the packet, on the
	// transports that do not authenticate it themselves (wireguard without
	// WRAP), so the counter is whatever the bytes say. A peer never sends one
	// from RejectAfterMessages up — and advanceLocked walks the counters up to
	// and past ctr, which at the top of uint64 wraps to zero and never ends,
	// under the lock every RX goroutine takes (audit 2026-10-21).
	if ctr >= device.RejectAfterMessages {
		return
	}

	at := now.Sub(t.epoch)
	r := t.relayIndexLocked(relay)
	b := t.bookLocked(receiver, ctr, at)
	b.used = at
	switch {
	case ctr >= b.top:
		t.advanceLocked(b, ctr, r, at)
		t.gotLocked(r)
	case b.top-ctr > relayOrderRing:
		t.afterWriteOff++
	default:
		slot := ctr % relayOrderRing
		switch b.state[slot] {
		case orderHole:
			b.state[slot] = orderGot
			lag := b.top - 1 - ctr
			t.gotLocked(r)
			t.late++
			t.relayN[r].late++
			if lag >= relayOrderDupAcks {
				t.lateDupAcks++
			}
			t.lag.add(lag)
			// Below zero when it came off its socket before the counter that
			// opened the hole, and lost the race to the lock: the hole it
			// closes is the RX goroutines' own.
			t.hole.add(uint64(max(0, at-b.opened[slot]) / time.Microsecond))
			t.overtaken[[2]uint16{b.opener[slot], r}]++
		case orderGot:
			t.dup++
		case orderWrittenOff:
			t.afterWriteOff++
		}
	}
}

func (t *relayOrder) gotLocked(r uint16) {
	t.got++
	t.relayN[r].got++
}

// bookLocked finds receiver's book or starts one, in place of the one used
// longest ago. A keypair starts at counter 0, and the counters below the first
// to arrive are on their way through slower relays: they are holes. A book
// that starts higher has come in mid-keypair and tracks only what is newer.
func (t *relayOrder) bookLocked(receiver uint32, ctr uint64, at time.Duration) *relayOrderBook {
	for _, b := range t.books {
		if b.receiver == receiver {
			return b
		}
	}
	var b *relayOrderBook
	if len(t.books) < relayOrderKeypairs {
		b = &relayOrderBook{}
		t.books = append(t.books, b)
	} else {
		b = t.books[0]
		for _, o := range t.books[1:] {
			if o.used < b.used {
				b = o
			}
		}
		for i := range b.state {
			if b.state[i] == orderHole {
				t.neverCame++
			}
		}
		b.state = [relayOrderRing]uint8{}
	}
	b.receiver, b.top = receiver, 0
	if ctr >= relayLossNewKeypair {
		b.top = ctr
	}
	return b
}

// advanceLocked books ctr, the highest counter yet, through relay r: the
// counters it jumps over open holes, and what falls out of the window behind
// them is settled.
func (t *relayOrder) advanceLocked(b *relayOrderBook, ctr uint64, r uint16, at time.Duration) {
	from := b.top
	if ctr-from >= relayOrderRing {
		// The whole window falls out, and more holes open than it holds.
		for i := range b.state {
			if b.state[i] == orderHole {
				t.neverCame++
			}
		}
		b.state = [relayOrderRing]uint8{}
		from = ctr + 1 - relayOrderRing
		// Saturating: a jump of that order is no measure of anything, and on a
		// 32-bit phone int is 32 bits.
		t.neverCame += int(min(from-b.top, math.MaxInt32))
	}
	for c := from; c <= ctr; c++ {
		slot := c % relayOrderRing
		if b.state[slot] == orderHole {
			t.neverCame++
		}
		if c == ctr {
			b.state[slot] = orderGot
			continue
		}
		b.state[slot], b.opened[slot], b.opener[slot] = orderHole, at, r
	}
	b.top = ctr + 1
}

func (t *relayOrder) relayIndexLocked(relay string) uint16 {
	if i, ok := t.index[relay]; ok {
		return i
	}
	i := uint16(len(t.relays))
	t.index[relay] = i
	t.relays = append(t.relays, relay)
	t.relayN = append(t.relayN, relayOrderRelay{relay: relay})
	return i
}

// take returns the window since the previous take and starts the next. Holes
// open relayOrderHoleExpire by now are written off first.
func (t *relayOrder) take(now time.Time) relayOrderSample {
	t.mu.Lock()
	defer t.mu.Unlock()
	at := now.Sub(t.epoch)
	for _, b := range t.books {
		for i := range b.state {
			if b.state[i] == orderHole && at-b.opened[i] >= relayOrderHoleExpire {
				b.state[i] = orderWrittenOff
				t.neverCame++
			}
		}
	}
	s := relayOrderSample{
		span: now.Sub(t.since),
		got:  t.got, late: t.late, lateDupAcks: t.lateDupAcks, dup: t.dup,
		neverCame: t.neverCame, afterWriteOff: t.afterWriteOff,
		lag: t.lag, hole: t.hole,
	}
	for _, n := range t.relayN {
		if n.got > 0 {
			s.relays = append(s.relays, n)
		}
	}
	for k, n := range t.overtaken {
		s.pairs = append(s.pairs, relayOrderPair{ahead: t.relays[k[0]], behind: t.relays[k[1]], n: n})
	}
	slices.SortFunc(s.pairs, func(a, b relayOrderPair) int {
		if a.n != b.n {
			return b.n - a.n
		}
		return strings.Compare(a.ahead+" "+a.behind, b.ahead+" "+b.behind)
	})
	t.since = now
	t.clearWindowLocked()
	return s
}

func (s relayOrderSample) String() string {
	var w strings.Builder
	fmt.Fprintf(&w, "last %v: %d packets, %.2f%% late, %.2f%% by %d+",
		s.span.Round(time.Second), s.got, pct(s.late, s.got), pct(s.lateDupAcks, s.got), relayOrderDupAcks)
	if s.late > 0 {
		fmt.Fprintf(&w, "; lag p50 %d p95 %d p99 %d max %d; hole p50 %s p95 %s p99 %s max %s",
			s.lag.quantile(0.5), s.lag.quantile(0.95), s.lag.quantile(0.99), s.lag.max,
			holeTime(s.hole.quantile(0.5)), holeTime(s.hole.quantile(0.95)),
			holeTime(s.hole.quantile(0.99)), holeTime(s.hole.max))
	}
	fmt.Fprintf(&w, "; %d duplicated, %d never came, %d after written off", s.dup, s.neverCame, s.afterWriteOff)
	if len(s.relays) > 1 {
		parts := make([]string, 0, len(s.relays))
		for _, r := range s.relays {
			parts = append(parts, fmt.Sprintf("%s %.2f%% of %d", r.relay, pct(r.late, r.got), r.got))
		}
		fmt.Fprintf(&w, "; late through %s", strings.Join(parts, ", "))
	}
	if len(s.pairs) > 0 {
		parts := make([]string, 0, relayOrderPairsShown)
		for _, p := range s.pairs[:min(len(s.pairs), relayOrderPairsShown)] {
			parts = append(parts, fmt.Sprintf("%s by %s %d", p.behind, p.ahead, p.n))
		}
		fmt.Fprintf(&w, "; overtaken: %s", strings.Join(parts, ", "))
	}
	return w.String()
}

func pct(n, of int) float64 {
	if of == 0 {
		return 0
	}
	return 100 * float64(n) / float64(of)
}

func holeTime(us uint64) string {
	return fmt.Sprintf("%.1fms", float64(us)/1000)
}

// relayOrderHist counts values in buckets an eighth of an octave wide: exact
// below 16, 12.5% wide above.
type relayOrderHist struct {
	n   int
	max uint64
	b   [16 + 60*8]uint32
}

func (h *relayOrderHist) add(v uint64) {
	h.n++
	h.max = max(h.max, v)
	h.b[histBucket(v)]++
}

// quantile is the middle of the bucket holding the q-th value, within 6.25%
// of it.
func (h *relayOrderHist) quantile(q float64) uint64 {
	if h.n == 0 {
		return 0
	}
	rank := max(1, int(math.Ceil(q*float64(h.n))))
	seen := 0
	for i, c := range h.b {
		if seen += int(c); seen >= rank {
			return min(histFloor(i)+histWidth(i)/2, h.max)
		}
	}
	return h.max
}

func histBucket(v uint64) int {
	if v < 16 {
		return int(v)
	}
	e := bits.Len64(v) - 1
	return 16 + (e-4)*8 + int(v>>(e-3)&7)
}

func histFloor(i int) uint64 {
	if i < 16 {
		return uint64(i)
	}
	e := (i-16)/8 + 4
	return uint64(8+(i-16)%8) << (e - 3)
}

func histWidth(i int) uint64 {
	if i < 16 {
		return 1
	}
	return 1 << ((i-16)/8 + 1)
}
