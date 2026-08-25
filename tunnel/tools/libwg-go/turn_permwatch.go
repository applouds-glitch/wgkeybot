/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"strings"
	"sync"
	"sync/atomic"
)

// pion never returns an error when a TURN allocation stops working underneath a
// live socket. A failed ChannelBind refresh, allocation refresh or permission
// refresh is only *logged* (internal/client/udp_conn.go:493,
// internal/client/allocation.go:157,168): the relay conn stays open, every
// WriteTo keeps returning success, and the relay silently stops forwarding.
// Until now the only thing that noticed was the 90s no-RX detector in
// runKeepalive — and only when the path went completely silent, which it does
// not have to: the stream keeps getting whatever the server round-robins at it
// through *other* code paths right up until it doesn't.
//
// permWatch turns those log lines into an explicit signal. pion/turn v5.0.13
// re-checks every channel binding on a 30s timer (defaultBindingCheckInterval,
// udp_conn.go:24) and re-binds one older than 5 minutes, so a server-side
// allocation that has been reaped emits "Failed to bind channel" every 30s.
// Two in a row is a confirmed blackhole in ~60s, measured on the TURN control
// plane and therefore independent of whether any WireGuard traffic is flowing.
//
// The markers are matched against pion's *literal* format strings, so a version
// bump that reworks the wording silently degrades this to "never fires" rather
// than misfiring — permwatch_test.go pins the markers against the vendored
// module so that degradation is caught at test time instead of in the field.
const (
	// permWatchScope is the only scope pion/turn's client logs under
	// (client.go:191). Guarding on it keeps the watcher from reacting to logs
	// from any other pion component that might share the factory later.
	permWatchScope = "turnc"

	bindFailMarker  = "Failed to bind channel"
	bindOKMarker    = "Channel binding successful"
	allocFailMarker = "Failed to refresh allocation"
	allocOKMarker   = "Updated lifetime"
	permFailMarker  = "Failed to refresh permissions"
	permOKMarker    = "Refresh permissions successful"

	// pion closes the relay itself when the server answers ChannelBind with 400
	// (closeAfterChannelBindBadRequest, udp_conn.go:538). Watching for it does
	// not change the outcome, but it lets the teardown carry a real reason
	// instead of surfacing as a bare "use of closed network connection".
	allocClosedMarker = "closing TURN allocation"
)

// Thresholds are per failure class because pion retries each class on a
// different cadence, and one missed refresh is not equally fatal in each.
const (
	// ChannelBind: re-checked every 30s, and PerformTransaction already
	// retransmits ~7 times (~7.8s) inside a single attempt. Two consecutive
	// failures ≈ 60s of a server that will not renew the binding.
	bindFailThreshold = 2

	// Allocation refresh: pion fires it at lifetime/2 — 300s for the 600s VK
	// grants. Waiting for a second failure is pointless because the allocation
	// expires before it happens, so one hard failure (already 7 retransmits
	// deep) recycles the stream ~5 minutes before it would have died anyway.
	allocFailThreshold = 1

	// Permission refresh: every 4 minutes (PermissionRefreshInterval, raised
	// from pion's 120s default in dialAndAllocate — see the rationale there).
	// Losing the permission is exactly the blackhole we are hunting — the relay
	// stops accepting peer data — but a single miss is cheap to ride out, and
	// the 60s of margin left under the 300s permission lifetime means one miss
	// does not yet cost anything. Two ≈ 8 minutes, which is why this stays the
	// slowest of the three classes and the other two carry the detection.
	permFailThreshold = 2
)

// permWatch accumulates pion's control-plane failures for one TURN session and
// closes dead once a failure class crosses its threshold. A nil *permWatch is
// valid and never fires, so callers that do not want the detector can pass nil.
type permWatch struct {
	streamID int

	mu         sync.Mutex // guards the counters below
	bindFails  int
	allocFails int
	permFails  int

	reason atomic.Pointer[string]
	dead   chan struct{}
	once   sync.Once
}

func newPermWatch(streamID int) *permWatch {
	return &permWatch{streamID: streamID, dead: make(chan struct{})}
}

// note inspects one pion log line. Callers pass Warn lines already formatted
// (they are rare and formatted for the log anyway) and Debug lines as their raw
// format string, which is enough because every marker lives in the literal part.
func (w *permWatch) note(msg string) {
	if w == nil {
		return
	}

	fire := false
	w.mu.Lock()
	switch {
	// Success markers first: a healthy refresh must clear its own counter
	// before any failure marker can match a substring of it.
	case strings.Contains(msg, bindOKMarker):
		w.bindFails = 0
	case strings.Contains(msg, allocOKMarker):
		w.allocFails = 0
	case strings.Contains(msg, permOKMarker):
		w.permFails = 0
	case strings.Contains(msg, allocClosedMarker):
		fire = true
	case strings.Contains(msg, bindFailMarker):
		w.bindFails++
		fire = w.bindFails >= bindFailThreshold
	case strings.Contains(msg, allocFailMarker):
		w.allocFails++
		fire = w.allocFails >= allocFailThreshold
	case strings.Contains(msg, permFailMarker):
		w.permFails++
		fire = w.permFails >= permFailThreshold
	}
	w.mu.Unlock()

	if fire {
		w.markDead(msg)
	}
}

// markDead latches the blackhole verdict. Idempotent: later failures on a
// session already declared dead keep the first (root cause) reason.
func (w *permWatch) markDead(reason string) {
	w.once.Do(func() {
		r := reason
		w.reason.Store(&r)
		close(w.dead)
		turnLog("[STREAM %d] TURN data-path blackhole: %s", w.streamID, reason)
	})
}

// deadCh returns the channel closed when the session is declared dead. A nil
// watcher yields a nil channel, which blocks forever in a select — the correct
// "detector disabled" behaviour.
func (w *permWatch) deadCh() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.dead
}

func (w *permWatch) fired() bool {
	if w == nil {
		return false
	}
	select {
	case <-w.dead:
		return true
	default:
		return false
	}
}

// why returns the pion log line that tripped the detector. It is folded into
// the error runWithCreds returns, so classifyCredError still sees pion's own
// wording ("allocation mismatch", "401", …) and can rotate the credential when
// the blackhole was really an auth/quota problem.
func (w *permWatch) why() string {
	if w == nil {
		return ""
	}
	if p := w.reason.Load(); p != nil {
		return *p
	}
	return ""
}
