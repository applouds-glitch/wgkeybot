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

	// lastGood is when this server last completed a data-plane handshake. It is
	// the evidence noteServerHandshakeFailure weighs, so entries are cleared in
	// place rather than deleted — dropping the entry would drop the proof.
	lastGood time.Time
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
	h.failures = 0
	h.lastStrike = time.Time{}
	h.penalizedTil = time.Time{}
}

// noteServerHandshakeOK records that addr completed a data-plane handshake —
// the transport's own handshake, not the TURN Allocate that precedes it. This
// is the fast counterpart of noteServerSuccess: it says nothing about whether
// the server will keep carrying traffic, only that at this instant its relay
// carried an authenticated round trip. noteServerHandshakeFailure reads these
// stamps; nothing else does.
func noteServerHandshakeOK(addr string) {
	noteServerHandshakeOKAt(addr, time.Now())
}

func noteServerHandshakeOKAt(addr string, now time.Time) {
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
	h.lastGood = now
}

// noteServerHandshakeFailure reports that addr allocated a relay and then failed
// the data-plane handshake through it — the one verdict that is worth acting on
// before the streak fills up, because it is the shape of the failure that used
// to be invisible: Allocate succeeds, so nothing counts against the host, while
// the relay quietly eats every packet.
//
// It stands the server down on a single strike, but only when the uplink is
// provably innocent: some *other* server completed a handshake while this
// attempt was failing. That overlap is the whole discriminator. A dead uplink
// fails every server at once and proves nothing in the window, so it falls back
// to the ordinary streak (see serverFailCoalesce) instead of standing down every
// server VK returned; proof from addr itself argues the host is fine and one
// stream was unlucky, so it does not count either.
//
// attemptStart is when the failed handshake began — proof older than that is
// exactly what a dying uplink leaves behind and must not authorise anything.
func noteServerHandshakeFailure(addr string, attemptStart time.Time) {
	noteServerHandshakeFailureAt(addr, attemptStart, time.Now())
}

func noteServerHandshakeFailureAt(addr string, attemptStart, now time.Time) {
	if addr == "" {
		return
	}
	if !siblingProvedAnotherServer(addr, attemptStart, now) {
		noteServerFailureAt(addr, now)
		return
	}

	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	h := serverHealthState.byAddr[addr]
	if h == nil {
		h = &serverHealth{}
		serverHealthState.byAddr[addr] = h
	}
	h.lastStrike = now
	h.failures++
	// Every stream assigned to the bad host reports this within the same breath.
	// Re-arming the window on each is harmless and correct; saying so ten times
	// is not.
	alreadyDown := now.Before(h.penalizedTil)
	h.penalizedTil = now.Add(serverPenaltyWindow)
	if !alreadyDown {
		turnLog("[TURN HEALTH] %s allocated but failed its data-plane handshake while another server carried one — standing it down for %v",
			addr, serverPenaltyWindow)
	}
}

// siblingProvedAnotherServer reports whether a server other than addr completed
// a data-plane handshake between attemptStart and now.
func siblingProvedAnotherServer(addr string, attemptStart, now time.Time) bool {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	for other, h := range serverHealthState.byAddr {
		if other == addr || h.lastGood.IsZero() {
			continue
		}
		if h.lastGood.After(attemptStart) && !h.lastGood.After(now) {
			return true
		}
	}
	return false
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
	// The window expired. Clear the streak as well as the deadline: the server
	// gets a clean slate, so one more failure does not immediately re-arm the
	// penalty from a streak earned minutes ago.
	h.failures = 0
	h.lastStrike = time.Time{}
	h.penalizedTil = time.Time{}
	return false
}
