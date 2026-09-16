/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"strings"
	"testing"
	"time"
)

// dispatchStream builds a ready-or-not stream whose liveness clock last saw a
// packet at lastRx (zero = no clock published yet), with a queue of the given
// depth so a test can pre-fill it.
func dispatchStream(id int, ready bool, lastRx time.Time, queue int) *stream {
	s := &stream{id: id, in: make(chan []byte, queue)}
	s.ready.Store(ready)
	if !lastRx.IsZero() {
		s.activity.Store(newStreamActivity(lastRx, 0))
	}
	return s
}

func queued(s *stream) int { return len(s.in) }

// The whole point: a stream whose relay went quiet is passed over while a
// sibling still hears echoes, even when the rotation lands on it first.
func TestDispatchSkipsStaleStream(t *testing.T) {
	now := time.Now()
	stale := dispatchStream(0, true, now.Add(-dispatchStaleAfter-time.Second), 8)
	fresh := dispatchStream(1, true, now.Add(-time.Second), 8)

	sent, anyReady := dispatchPacket([]*stream{stale, fresh}, 0, now, []byte{1})
	if !sent || !anyReady {
		t.Fatalf("sent=%v anyReady=%v, want true/true", sent, anyReady)
	}
	if queued(stale) != 0 || queued(fresh) != 1 {
		t.Fatalf("stale got %d, fresh got %d; want 0/1", queued(stale), queued(fresh))
	}
}

// Every stream silent means the uplink is down, not a relay: the rotation
// falls back to the ordinary round-robin instead of dropping.
func TestDispatchFallsBackWhenAllStale(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * dispatchStaleAfter)
	a := dispatchStream(0, true, old, 8)
	b := dispatchStream(1, true, old, 8)

	sent, anyReady := dispatchPacket([]*stream{a, b}, 1, now, []byte{1})
	if !sent || !anyReady {
		t.Fatalf("sent=%v anyReady=%v, want true/true", sent, anyReady)
	}
	if queued(b) != 1 || queued(a) != 0 {
		t.Fatalf("start=1 must keep the rotation's own slot: a=%d b=%d", queued(a), queued(b))
	}
}

// Readiness stays the gate: an unready stream is never a candidate, however
// fresh its clock, and with nothing ready both results are false.
func TestDispatchIgnoresUnreadyStreams(t *testing.T) {
	now := time.Now()
	down := dispatchStream(0, false, now, 8)
	up := dispatchStream(1, true, now, 8)

	if sent, anyReady := dispatchPacket([]*stream{down, up}, 0, now, []byte{1}); !sent || !anyReady {
		t.Fatalf("sent=%v anyReady=%v, want true/true", sent, anyReady)
	}
	if queued(down) != 0 || queued(up) != 1 {
		t.Fatalf("down=%d up=%d, want 0/1", queued(down), queued(up))
	}

	if sent, anyReady := dispatchPacket([]*stream{down}, 0, now, []byte{1}); sent || anyReady {
		t.Fatalf("sent=%v anyReady=%v with nothing ready, want false/false", sent, anyReady)
	}
}

// A full queue on a fresh stream spills to the next fresh one; only when every
// candidate refuses does the packet count as dropped, with anyReady still set
// so the log names the right cause.
func TestDispatchSpillsOverFullQueue(t *testing.T) {
	now := time.Now()
	full := dispatchStream(0, true, now, 1)
	full.in <- []byte{0}
	free := dispatchStream(1, true, now, 1)

	if sent, _ := dispatchPacket([]*stream{full, free}, 0, now, []byte{1}); !sent {
		t.Fatal("packet must spill to the sibling with room")
	}
	if queued(free) != 1 {
		t.Fatalf("free got %d, want 1", queued(free))
	}

	sent, anyReady := dispatchPacket([]*stream{full, free}, 0, now, []byte{2})
	if sent || !anyReady {
		t.Fatalf("saturated pool: sent=%v anyReady=%v, want false/true", sent, anyReady)
	}
}

// A ready stream that has not published a clock is not stale — the transports
// publish before flipping ready, but the dispatcher must not punish the gap.
func TestDispatchStaleNeedsAClock(t *testing.T) {
	now := time.Now()
	s := dispatchStream(0, true, time.Time{}, 8)
	if s.dispatchStale(now) {
		t.Fatal("stream without a liveness clock reported stale")
	}
}

// The threshold sits between "one echo late" and "the detector's verdict":
// above the longest healthy gap between echoes (interval plus phase spread),
// and well below deadStreamTimeout, so a quiet relay leaves the rotation long
// before it is torn down.
func TestDispatchStaleThreshold(t *testing.T) {
	if dispatchStaleAfter <= keepaliveInterval+keepaliveSpread {
		t.Fatalf("dispatchStaleAfter %v must exceed one keepalive window %v", dispatchStaleAfter, keepaliveInterval+keepaliveSpread)
	}
	if dispatchStaleAfter >= 2*keepaliveInterval {
		t.Fatalf("dispatchStaleAfter %v must fire on a single missed echo (< %v)", dispatchStaleAfter, 2*keepaliveInterval)
	}
	if dispatchStaleAfter >= deadStreamTimeout {
		t.Fatalf("dispatchStaleAfter %v must precede deadStreamTimeout %v", dispatchStaleAfter, deadStreamTimeout)
	}

	now := time.Now()
	s := dispatchStream(0, true, now.Add(-dispatchStaleAfter+time.Second), 1)
	if s.dispatchStale(now) {
		t.Fatal("stream inside the window reported stale")
	}
	s = dispatchStream(0, true, now.Add(-dispatchStaleAfter-time.Second), 1)
	if !s.dispatchStale(now) {
		t.Fatal("stream past the window reported fresh")
	}
}

// The handshake bound is what lets failover act inside TunnelManager's 25s
// connect budget on the DTLS peer types, and it must still leave pion/dtls its
// first few retransmits (flights at 0s, 1s, 3s, 7s).
func TestDataPlaneHandshakeTimeoutFitsConnectBudget(t *testing.T) {
	const connectBudget = 25 * time.Second
	if dataPlaneHandshakeTimeout >= connectBudget/2 {
		t.Fatalf("dataPlaneHandshakeTimeout %v leaves no room for a failover inside %v", dataPlaneHandshakeTimeout, connectBudget)
	}
	if dataPlaneHandshakeTimeout <= 7*time.Second {
		t.Fatalf("dataPlaneHandshakeTimeout %v cuts off the fourth DTLS flight at 7s", dataPlaneHandshakeTimeout)
	}
}

// Under load the chunk rotates by count: chunkSize packets on one stream, then
// the next, so a burst keeps its order.
func TestChunkRotorRotatesByCount(t *testing.T) {
	now := time.Now()
	r := newChunkRotor(3)
	for i := 0; i < chunkSize; i++ {
		if got := r.start(now); got != 0 {
			t.Fatalf("packet %d: start=%d, want 0 until the chunk fills", i, got)
		}
		r.sent(now)
	}
	if got := r.start(now); got != 1 {
		t.Fatalf("after %d packets start=%d, want 1", chunkSize, got)
	}
}

// At idle the count never fills, so the chunk closes by age instead: packets
// chunkMaxAge apart — a WireGuard handshake retry series — each start on a new
// stream rather than piling onto whichever one the last burst ended on.
func TestChunkRotorRotatesIdleChunkByAge(t *testing.T) {
	now := time.Now()
	r := newChunkRotor(3)
	r.sent(r.startAt(now))
	if got := r.start(now.Add(chunkMaxAge / 2)); got != 0 {
		t.Fatalf("young chunk rotated: start=%d, want 0", got)
	}
	if got := r.start(now.Add(chunkMaxAge)); got != 1 {
		t.Fatalf("idle chunk kept: start=%d, want 1", got)
	}
	// An empty chunk has no age: nothing to close, the slot stays.
	if got := r.start(now.Add(10 * chunkMaxAge)); got != 1 {
		t.Fatalf("empty chunk rotated: start=%d, want 1", got)
	}
}

// startAt is start followed by returning now, so a test can write
// r.sent(r.startAt(now)) for "dispatch one packet at now".
func (r *chunkRotor) startAt(now time.Time) time.Time {
	r.start(now)
	return now
}

// One stream going quiet is logged once, on the way in and on the way out —
// not on every packet in between.
func TestStaleWatchLogsTransitionsOnce(t *testing.T) {
	now := time.Now()
	quiet := dispatchStream(0, true, now, 8)
	fresh := dispatchStream(1, true, now, 8)
	streams := []*stream{quiet, fresh}
	w := newStaleWatch(len(streams))

	if lines := w.observe(streams, now); len(lines) != 0 {
		t.Fatalf("fresh streams produced %q", lines)
	}

	later := now.Add(dispatchStaleAfter + time.Second)
	fresh.activity.Load().noteRx(later)
	lines := w.observe(streams, later)
	if len(lines) != 1 || !strings.Contains(lines[0], "stream 0 silent") {
		t.Fatalf("stale transition: got %q", lines)
	}
	if lines := w.observe(streams, later.Add(staleWatchInterval)); len(lines) != 0 {
		t.Fatalf("steady stale state logged again: %q", lines)
	}

	back := later.Add(2 * staleWatchInterval)
	quiet.activity.Load().noteRx(back)
	fresh.activity.Load().noteRx(back)
	lines = w.observe(streams, back)
	if len(lines) != 1 || !strings.Contains(lines[0], "stream 0 heard its relay again") {
		t.Fatalf("recovery transition: got %q", lines)
	}
}

// Every ready stream silent at once is the uplink, and gets its own line so the
// log distinguishes it from one dead allocation.
func TestStaleWatchReportsWholeUplink(t *testing.T) {
	now := time.Now()
	a := dispatchStream(0, true, now, 8)
	b := dispatchStream(1, true, now, 8)
	down := dispatchStream(2, false, now, 8) // not ready: never counted
	streams := []*stream{a, b, down}
	w := newStaleWatch(len(streams))
	w.observe(streams, now)

	dark := now.Add(dispatchStaleAfter + time.Second)
	lines := w.observe(streams, dark)
	if len(lines) != 3 || !strings.Contains(lines[2], "every ready stream (2) is silent") {
		t.Fatalf("blackout: got %q", lines)
	}

	// One stream hearing echoes again ends the blackout verdict even though the
	// other is still stale.
	partial := dark.Add(staleWatchInterval)
	a.activity.Load().noteRx(partial)
	lines = w.observe(streams, partial)
	if len(lines) != 2 || !strings.Contains(lines[1], "echoes are back on 1 of 2") {
		t.Fatalf("partial recovery: got %q", lines)
	}
}

// Scans are rate-limited; a transition that lands between two scans is still
// reported on the next one, just not sooner.
func TestStaleWatchRateLimitsScans(t *testing.T) {
	now := time.Now()
	s := dispatchStream(0, true, now.Add(-dispatchStaleAfter-time.Second), 8)
	streams := []*stream{s}
	w := newStaleWatch(1)

	first := w.observe(streams, now)
	if len(first) != 2 {
		t.Fatalf("first scan: got %q", first)
	}
	s.activity.Load().noteRx(now)
	if lines := w.observe(streams, now.Add(staleWatchInterval/2)); len(lines) != 0 {
		t.Fatalf("scanned inside the interval: %q", lines)
	}
	if lines := w.observe(streams, now.Add(staleWatchInterval)); len(lines) != 2 {
		t.Fatalf("next scan missed the recovery: %q", lines)
	}
}
