/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync"
	"time"
)

// Per-server failure accounting for the static stream→server assignment.
//
// assignServers pins every stream to one of the TURN servers VK returned, round
// robin by stream ID, and the rest of the list acts as failover for a single
// attempt only. That is deliberate — a stream returns to its own server on the
// next reconnect instead of sticking to whichever host won a race — but it left
// no way out of a server that is simply down: the stream kept going back to it
// forever, and the only thing that grew was its reconnect backoff.
//
// A server that fails repeatedly now serves a penalty, during which assignServers
// hands its streams to the next healthy server in canonical order. The penalty is
// short and self-clearing: this is a "stop hammering the dead host for a few
// minutes" rule, not a reputation system.
const (
	// serverFailThreshold is the consecutive-failure count that stands a server
	// down. The first two are within the noise of a lost UDP packet or a brief
	// server-side race, both of which the ordinary reconnect path already handles;
	// the third says the host itself is the problem.
	serverFailThreshold = 3

	// serverFailCoalesce is the window inside which repeated failures against one
	// server count as a single strike.
	//
	// Every stream fails a dead host at the same moment: one lost uplink
	// blackholed twelve allocations at once and charged the same two servers six
	// times each, so a single network blip blew straight past a threshold meant
	// to describe a host that keeps failing over time — and stood down every
	// server VK had given us. One strike per window makes the count mean what its
	// name says: trouble that survives several windows, rather than one incident
	// seen from twelve sockets.
	//
	// Sized above the spread of a single blackhole burst (the watchdog fires
	// per-stream within milliseconds, plus the sub-second reconnect that fails
	// the same way) and well below the penalty window, so a genuinely dead host
	// still earns its stand-down inside about half a minute.
	serverFailCoalesce = 10 * time.Second

	// serverStreakDecay is how long a strike keeps counting towards the streak.
	// "In a row" has to mean in a row: strikes minutes apart are separate
	// incidents, and a server nothing was assigned to in between never got the
	// chance to clear itself with a healthy session. Without this, three
	// unrelated blips spread over an evening would eventually stand a working
	// server down.
	serverStreakDecay = 5 * time.Minute

	// serverPenaltyWindow is how long a stood-down server is skipped. Long enough
	// to ride out a restart or a transient outage on that host, short enough that
	// a recovered server is back in rotation without a tunnel restart.
	serverPenaltyWindow = 5 * time.Minute

	// healthySessionDuration is the session length that clears a server's failure
	// streak. It matches the threshold runWorker uses to treat a dropped session
	// as healthy rather than as part of a failure streak.
	healthySessionDuration = 60 * time.Second
)

type serverHealth struct {
	failures     int
	lastStrike   time.Time
	penalizedTil time.Time
}

var serverHealthState = struct {
	sync.Mutex
	byAddr map[string]*serverHealth
}{byAddr: make(map[string]*serverHealth)}

// resetServerHealth clears all accounting. Called when a proxy starts: the
// credentials, and usually the server list itself, are new.
func resetServerHealth() {
	serverHealthState.Lock()
	serverHealthState.byAddr = make(map[string]*serverHealth)
	serverHealthState.Unlock()
}

// noteServerFailure records one failed attempt against addr and stands the
// server down once the streak reaches serverFailThreshold. Callers must not
// report failures caused by our own cancellation — a losing failover candidate
// or a tunnel being torn down says nothing about the server.
//
// Failures arriving within serverFailCoalesce of the last counted one are the
// same incident reported by another stream, and count once.
func noteServerFailure(addr string) {
	noteServerFailureAt(addr, time.Now())
}

func noteServerFailureAt(addr string, now time.Time) {
	if addr == "" {
		return
	}
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	h := serverHealthState.byAddr[addr]
	if h == nil {
		h = &serverHealth{}
		serverHealthState.byAddr[addr] = h
	}
	if !h.lastStrike.IsZero() {
		if since := now.Sub(h.lastStrike); since < serverFailCoalesce {
			return
		} else if since > serverStreakDecay {
			h.failures = 0
		}
	}
	h.lastStrike = now
	h.failures++
	if h.failures < serverFailThreshold {
		return
	}
	// Re-arm on every failure past the threshold, so a server that keeps failing
	// keeps its penalty rolling instead of coming back every window.
	h.penalizedTil = now.Add(serverPenaltyWindow)
	turnLog("[TURN HEALTH] %s failed %d times in a row — standing it down for %v",
		addr, h.failures, serverPenaltyWindow)
}

// noteServerSuccess clears addr's failure streak and any active penalty. Only a
// session that actually carried traffic for a while should call this; an
// Allocate that succeeds and then blackholes is not evidence of a healthy server.
func noteServerSuccess(addr string) {
	if addr == "" {
		return
	}
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	h := serverHealthState.byAddr[addr]
	if h == nil || (h.failures == 0 && h.penalizedTil.IsZero()) {
		return
	}
	if !h.penalizedTil.IsZero() {
		turnLog("[TURN HEALTH] %s carried a healthy session — penalty lifted", addr)
	}
	delete(serverHealthState.byAddr, addr)
}

// serverPenalized reports whether addr is currently stood down.
func serverPenalized(addr string, now time.Time) bool {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	h := serverHealthState.byAddr[addr]
	if h == nil || h.penalizedTil.IsZero() {
		return false
	}
	if now.Before(h.penalizedTil) {
		return true
	}
	// The window expired. Drop the whole entry rather than only the deadline: the
	// server gets a clean slate, so one more failure does not immediately re-arm
	// the penalty from a streak earned minutes ago.
	delete(serverHealthState.byAddr, addr)
	return false
}
