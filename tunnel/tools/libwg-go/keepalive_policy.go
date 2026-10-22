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
	//
	// This is the idle stream's measure — the echo is all it hears — and under
	// load the wait is shorter: a stream silent for silentUnderLoadAfter while
	// two siblings hear their relays and have each received three chunks since
	// is skipped at once (silent_under_load.go). In the field log of
	// 2026-10-20/21 (a cellular network over UDP, nine streams) a relay went
	// deaf under its streams 26 times in nineteen minutes, each paid at the 35 s
	// here: 939 stream-seconds of a ninth of the downlink sent into a void,
	// which TCP inside the tunnel read as ~11% loss nearly all the time.
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

// keepaliveEchoRetry: over UDP a ready stream sends its keepalive once more
// this long after one that nothing answered — no echo, no data.
//
// Field log of 2026-10-18/20 (Lenovo TB-X705L, Android 9, v2.2.0, home Wi-Fi):
// 75 times in ~30 h a single stream fell silent for 50 s — two keepalive
// intervals to the second — and came back by itself on the next echo; 49 of
// them on the relay that lost 3-13% of its downlink, 26 on the one that lost
// nothing. One keepalive or its echo had been lost, and the next chance to be
// heard was the grid, 25 s later; from the 35th second the dispatcher benched
// the stream and the server's skip list (WGH1) followed. Sent again a few
// seconds later, a lost one costs the stream 3 s of silence instead of 25, and
// at under 35 it is never benched. One packet of 20 bytes, inside the radio's
// tail timer (5-10 s) of the grid burst, so no extra wake of the radio.
//
// Once per keepalive: a second miss is the path, not the packet, and the grid
// comes round 22 s later anyway. Not over TCP, where the kernel retransmits a
// lost segment and a missing echo means the relay or the server did not
// answer. Not for the keepalive sent at a thaw, which the post-wake probe
// follows with pings of its own (wake_probe.go).
//
// A var for the host tests, which cannot wait 3 s.
var keepaliveEchoRetry = 3 * time.Second

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
	// cannot answer once resetLiveness has moved it — and for the dispatcher,
	// which trusts a stream on a real echo, not on a reset (dispatchStale).
	lastHeard atomic.Int64

	// lastPong is the highest seq the server has echoed back on this session
	// (stunProbeSeq): the post-wake probe's mark. It only moves forward — a late
	// or repeated echo never takes back what a newer one has shown — and starts
	// from zero with every session, as the probe's seq does (wake_probe.go).
	// probeSent is the highest seq the probe has written: an echo naming a seq
	// beyond it is not ours and moves nothing.
	lastPong  atomic.Uint64
	probeSent atomic.Uint64

	// start is when the session began: a stream on another relay vouches for
	// the path through a deaf session's silence only if it was there before
	// that silence began (relay_deaf.go).
	start time.Time

	// rxCount is how many packets have really been heard this session, for the
	// judge of silence under load (silent_under_load.go), which weighs what a
	// stream's siblings received while it heard nothing.
	rxCount atomic.Uint64
	// silentUnderLoad is the lastHeard that judge's verdict was given for: the
	// stream is stale (stale) for as long as lastHeard stays there, and the
	// next packet lifts the verdict without a turn of the judge. Zero: none.
	silentUnderLoad atomic.Int64
}

func newStreamActivity(now time.Time, phase time.Duration) *streamActivity {
	a := &streamActivity{phase: phase, start: now}
	a.lastRx.Store(now.UnixNano())
	a.lastHeard.Store(now.UnixNano())
	return a
}

// noteRx stores lastHeard ahead of lastRx, so that frozeSinceHeard, reading
// them the other way round, never takes a packet arriving as a freeze.
func (a *streamActivity) noteRx(now time.Time) {
	a.lastHeard.Store(now.UnixNano())
	a.lastRx.Store(now.UnixNano())
	a.rxCount.Add(1)
}

// heardCount is how many packets this session has really heard.
func (a *streamActivity) heardCount() uint64 { return a.rxCount.Load() }

// markSilentUnderLoad records the verdict of silence under load for the
// silence that began at heard (a lastHeard value).
func (a *streamActivity) markSilentUnderLoad(heard int64) { a.silentUnderLoad.Store(heard) }

// foundSilentUnderLoad reports whether that verdict stands: given for the
// present silence, and nothing heard since.
func (a *streamActivity) foundSilentUnderLoad() bool {
	return a.silentUnderLoad.Load() == a.lastHeard.Load()
}

// stale is the dispatcher's measure (dispatchStale): the relay silent for
// longer than dispatchStaleAfter, or the stream found silent under load and
// not heard since (silent_under_load.go). One read of lastHeard serves both,
// so a packet arriving between them cannot leave a lifted verdict in force.
func (a *streamActivity) stale(now time.Time) bool {
	heard := a.lastHeard.Load()
	return now.Sub(time.Unix(0, heard)) > dispatchStaleAfter || a.silentUnderLoad.Load() == heard
}

// frozeSinceHeard reports whether the liveness clock has been reset for a
// freeze (resetLiveness) since the relay was last really heard: the silence
// heardAge measures has a freeze in it.
func (a *streamActivity) frozeSinceHeard() bool {
	rx := a.lastRx.Load()
	return rx > a.lastHeard.Load()
}

// notePong records an echoed probe seq; forward only, and never beyond what
// the probe has sent.
func (a *streamActivity) notePong(seq uint64) {
	if seq > a.probeSent.Load() {
		return
	}
	for {
		old := a.lastPong.Load()
		if seq <= old || a.lastPong.CompareAndSwap(old, seq) {
			return
		}
	}
}

// noteProbeEcho is the RX path's call for an echoed STUN keepalive: only one
// of our probe's shape names a seq (isStunProbeEcho).
func (a *streamActivity) noteProbeEcho(b []byte) {
	if isStunProbeEcho(b) {
		a.notePong(stunProbeSeq(b))
	}
}

func (a *streamActivity) pongMark() uint64 { return a.lastPong.Load() }

// heardAge is how long ago the relay was last really heard — since the session
// began, if it never was.
func (a *streamActivity) heardAge(now time.Time) time.Duration {
	age := now.Sub(atomicTimestamp(&a.lastHeard))
	if age < 0 {
		return 0
	}
	return age
}

// echoMissed reports whether nothing has arrived since a keepalive went out at
// sentAt: not its echo, not data. Either answers it; a successful write
// answers nothing (noteRx), nor does a freeze reset (resetLiveness).
func (a *streamActivity) echoMissed(sentAt time.Time) bool {
	return atomicTimestamp(&a.lastHeard).Before(sentAt)
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
	keepaliveEchoRetryWake
)

// nextDeadline is when the keepalive loop wakes next and why: the grid, a
// retry of a failed write (retryAt), the repeat of a keepalive nothing has
// answered (echoAt, keepaliveEchoRetry) or the dead-stream check.
func (a *streamActivity) nextDeadline(now, retryAt, echoAt time.Time) (time.Time, keepaliveWakeReason) {
	next := nextKeepaliveGrid(now, a.phase)
	reason := keepaliveGridWake
	if !retryAt.IsZero() && retryAt.Before(next) {
		next = retryAt
		reason = keepaliveRetryWake
	}
	if !echoAt.IsZero() && echoAt.Before(next) {
		next = echoAt
		reason = keepaliveEchoRetryWake
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

// waitUntilOrWake is waitUntil that also returns, with woke = true, when a
// host wake is broadcast (hostWakeChannel). ok = false means ctx is done.
func waitUntilOrWake(ctx context.Context, deadline time.Time, wake <-chan struct{}) (woke, ok bool) {
	delay := time.Until(deadline)
	if delay <= 0 {
		return false, ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-timer.C:
		return false, true
	case <-wake:
		return true, true
	}
}
