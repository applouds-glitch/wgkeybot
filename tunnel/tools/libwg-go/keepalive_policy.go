/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// keepaliveInterval is the shared UDP/NAT keepalive cadence. Every ready
	// stream uses the same wall-clock grid, entering it at its own phase;
	// authenticated inbound traffic updates the independent liveness clock but
	// never shifts the keepalive phase.
	keepaliveInterval = 25 * time.Second

	// keepaliveSpread is the width of the window the per-stream keepalives are
	// staggered over within the shared grid (see keepalivePhase). It is far below
	// the radio tail timer (5-10s on LTE/5G), so the whole spread still lands in
	// a single radio-active window — the coalescing saving is kept — while no two
	// sibling streams transmit at the same instant.
	keepaliveSpread = 2 * time.Second

	// dispatchStaleAfter is how long a ready stream may go without a validated
	// inbound packet before the dispatcher stops handing it chunks (see
	// dispatchPacket in init_groups.go). A healthy stream hears the server's
	// keepalive echo once per keepaliveInterval, at its own phase inside
	// keepaliveSpread, so its longest silent gap is one interval plus the
	// spread plus a mobile round trip; this sits just past that. It is
	// deliberately far below deadStreamTimeout: that one tears the stream
	// down, and three missed windows were chosen there so aligned streams do
	// not mass-reconnect on one lost burst. Skipping is reversible and costs no
	// reconnect — the stream keeps probing and rejoins the rotation on its next
	// echo — so one missed echo is enough. Before this a relay that had gone
	// quiet kept receiving every Nth chunk for the whole 90s until the detector
	// fired, which for TCP inside the tunnel is a steady 1/N loss for a minute
	// and a half.
	dispatchStaleAfter = 35 * time.Second

	// A failed write retries quickly on that stream. A successful retry rejoins
	// the shared wall-clock grid on the following keepalive.
	keepaliveSendRetry = 5 * time.Second

	// A keepalive sleep that overruns the full interval by this much is a host
	// freeze (deep Doze, runtime suspend), not ordinary scheduler jitter: the
	// liveness clock is stale through no fault of the path. The stream resets
	// that clock and re-stimulates the path instead of tearing itself down —
	// otherwise every stream tears down on thaw and mass-reconnects on one
	// credential, tripping the TURN 486 quota → captcha.
	freezeSlack = 20 * time.Second
)

// deadStreamTimeout tolerates three missed 25s liveness windows plus jitter.
// Closing sooner caused correlated reconnect storms across aligned streams.
//
// A var for the host tests, which cannot wait 90s.
var deadStreamTimeout = 90 * time.Second

// wireGuardKeepaliveSender couples WireGuard's encrypted keepalive to the
// existing TURN keepalive grid. TURN still sends one STUN liveness probe per
// relay stream, while WireGuard sends one peer keepalive per grid window; both
// layers therefore use the same short radio-active window instead of running
// unrelated 25s timers.
//
// The mutex is intentionally held while send runs. Clearing the active sender
// during tunnel teardown then waits for an already-started send to finish
// before the WireGuard device is closed.
type wireGuardKeepaliveSender struct {
	mu       sync.Mutex
	send     func()
	lastGrid int64
}

var activeWireGuardKeepaliveSender atomic.Pointer[wireGuardKeepaliveSender]

func installWireGuardKeepaliveSender(send func()) *wireGuardKeepaliveSender {
	sender := &wireGuardKeepaliveSender{send: send}
	activeWireGuardKeepaliveSender.Store(sender)
	return sender
}

func clearWireGuardKeepaliveSender(sender *wireGuardKeepaliveSender) {
	if sender == nil {
		return
	}
	activeWireGuardKeepaliveSender.CompareAndSwap(sender, nil)
	sender.mu.Lock()
	sender.send = nil
	sender.mu.Unlock()
}

// sendWireGuardKeepaliveOnSharedGrid invokes the active WireGuard device at
// most once for the wall-clock bucket containing now. All TURN stream phases
// fall inside the first keepaliveSpread of that bucket, so whichever ready
// stream arrives first performs the WireGuard send and every sibling skips it.
func sendWireGuardKeepaliveOnSharedGrid(now time.Time) bool {
	sender := activeWireGuardKeepaliveSender.Load()
	if sender == nil {
		return false
	}
	grid := now.Truncate(keepaliveInterval).UnixNano()

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.send == nil || sender.lastGrid == grid {
		return false
	}
	sender.lastGrid = grid
	sender.send()
	return true
}

// keepalivePhase is the deterministic offset of a stream's keepalive within the
// shared grid window. Streams stay coalesced into one radio wake but no longer
// transmit — and therefore no longer expect their echo — at the same instant:
// a single lost burst used to starve every sibling's liveness clock together,
// tearing all streams down at once → mass reconnect on one credential → TURN 486
// → captcha → the handshake watchdog killing the whole tunnel.
//
// The window is divided by the actual stream count (links × streams-per-group,
// known at startup), so every stream gets a slot of its own at any configured
// fan-out rather than colliding once the count exceeds a fixed slot table. The
// last slot lands at keepaliveSpread*(n-1)/n, strictly inside the window.
func keepalivePhase(streamID, totalStreams int) time.Duration {
	if totalStreams <= 1 || streamID <= 0 {
		return 0
	}
	slot := streamID % totalStreams
	if slot < 0 {
		slot += totalStreams
	}
	// Scale first, divide once: a precomputed step would compound its truncation
	// error across slots.
	return time.Duration(int64(keepaliveSpread) * int64(slot) / int64(totalStreams))
}

// streamActivity tracks authenticated inbound liveness. A successful local
// write may refresh NAT but never proves that the remote path is alive; only
// noteRx can advance lastRx.
type streamActivity struct {
	lastRx atomic.Int64
	phase  time.Duration

	// lastHeard is lastRx without the freeze reset: the last packet that really
	// arrived, or the session's start if none has. It is for the health
	// accounting — how long the relay was silent — which the detector's clock
	// cannot answer once resetLiveness has moved it.
	lastHeard atomic.Int64
}

func newStreamActivity(now time.Time, phase time.Duration) *streamActivity {
	a := &streamActivity{phase: phase}
	a.lastRx.Store(now.UnixNano())
	a.lastHeard.Store(now.UnixNano())
	return a
}

func (a *streamActivity) noteRx(now time.Time) {
	a.lastRx.Store(now.UnixNano())
	a.lastHeard.Store(now.UnixNano())
}

// heardAge is how long ago the relay was last really heard — since the session
// began, if it never was.
func (a *streamActivity) heardAge(now time.Time) time.Duration {
	age := now.Sub(atomicTimestamp(&a.lastHeard))
	if age < 0 {
		return 0
	}
	return age
}

// resetLiveness restarts the liveness clock without inbound evidence. Only the
// freeze path may call it: after a host freeze the age of lastRx measures how
// long the process was suspended, not how long the relay path has been silent,
// so tearing the stream down on it would punish a healthy path.
func (a *streamActivity) resetLiveness(now time.Time) {
	a.lastRx.Store(now.UnixNano())
}

func atomicTimestamp(v *atomic.Int64) time.Time {
	return time.Unix(0, v.Load())
}

// nextKeepaliveGrid returns the next phase-offset point on the global wall-clock
// grid shared by every stream. Streams may connect with a safety stagger, but
// once ready their keepalives land in one short radio-active window every 25
// seconds, spread across that window by phase. The per-stream gap stays exactly
// keepaliveInterval — phase is constant — so the NAT-hold budget is unchanged.
func nextKeepaliveGrid(now time.Time, phase time.Duration) time.Time {
	next := now.Truncate(keepaliveInterval).Add(phase)
	if !next.After(now) {
		next = next.Add(keepaliveInterval)
	}
	return next
}

type keepaliveWakeReason uint8

const (
	keepaliveGridWake keepaliveWakeReason = iota
	keepaliveRetryWake
	keepaliveDeadCheckWake
)

func (a *streamActivity) nextDeadline(now, retryAt time.Time) (time.Time, keepaliveWakeReason) {
	next := nextKeepaliveGrid(now, a.phase)
	reason := keepaliveGridWake
	if !retryAt.IsZero() && retryAt.Before(next) {
		next = retryAt
		reason = keepaliveRetryWake
	}
	// Liveness checks must not be postponed by the normal probe cadence. This
	// keeps the advertised 90s dead-stream threshold exact even though normal
	// keepalives wait for the shared wall-clock grid.
	deadDeadline := atomicTimestamp(&a.lastRx).Add(deadStreamTimeout)
	if deadDeadline.Before(next) {
		next = deadDeadline
		reason = keepaliveDeadCheckWake
	}
	return next, reason
}

func (a *streamActivity) rxAge(now time.Time) time.Duration {
	age := now.Sub(atomicTimestamp(&a.lastRx))
	if age < 0 {
		return 0
	}
	return age
}

func waitUntil(ctx context.Context, deadline time.Time) bool {
	delay := time.Until(deadline)
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
