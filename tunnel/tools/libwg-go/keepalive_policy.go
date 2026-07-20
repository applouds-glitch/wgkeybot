/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	// keepaliveInterval is the shared UDP/NAT keepalive cadence. Every ready
	// stream uses the same wall-clock grid; authenticated inbound traffic updates
	// the independent liveness clock but never shifts the keepalive phase.
	keepaliveInterval = 25 * time.Second

	// deadStreamTimeout tolerates three missed 25s liveness windows plus jitter.
	// Closing sooner caused correlated reconnect storms across aligned streams.
	deadStreamTimeout = 90 * time.Second

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

// streamActivity tracks authenticated inbound liveness. A successful local
// write may refresh NAT but never proves that the remote path is alive; only
// noteRx can advance lastRx.
type streamActivity struct {
	lastRx atomic.Int64
}

func newStreamActivity(now time.Time) *streamActivity {
	a := &streamActivity{}
	a.lastRx.Store(now.UnixNano())
	return a
}

func (a *streamActivity) noteRx(now time.Time) {
	a.lastRx.Store(now.UnixNano())
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

// nextKeepaliveGrid returns the next point on the global wall-clock grid shared
// by every stream. Streams may connect with a safety stagger, but once ready
// their keepalives land in one short radio-active window every 25 seconds.
func nextKeepaliveGrid(now time.Time) time.Time {
	return now.Truncate(keepaliveInterval).Add(keepaliveInterval)
}

type keepaliveWakeReason uint8

const (
	keepaliveGridWake keepaliveWakeReason = iota
	keepaliveRetryWake
	keepaliveDeadCheckWake
)

func (a *streamActivity) nextDeadline(now, retryAt time.Time) (time.Time, keepaliveWakeReason) {
	next := nextKeepaliveGrid(now)
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
