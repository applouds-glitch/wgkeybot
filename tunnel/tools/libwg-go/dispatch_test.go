/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
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

// The handshake bound is what lets the election act inside TunnelManager's 25s
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
