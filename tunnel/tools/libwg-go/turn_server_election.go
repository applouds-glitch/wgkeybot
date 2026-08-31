/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"slices"
	"time"
)

// Per-session election of the one TURN server the tunnel runs on.
//
// assignServers spread the streams across every server VK returned, and the
// penalty in turn_server_health.go was the only way off a host that was down.
// That penalty is a punishment, and it is priced accordingly: three strikes ten
// seconds apart, or a single data-plane failure that provably overlaps another
// server's success. Both are slower than TunnelManager's 25s handshake budget
// when one of the two relays VK hands out is simply dead — half the streams sat
// there burning relayProofTimeout plus a reconnect backoff, over and over, and
// the tunnel was torn down before the accounting had made up its mind.
//
// The election is the fast path beside it. It is not a punishment, so it needs
// no alibi and no threshold: one failed data-plane handshake takes a server out
// of the rotation for the rest of the session, and the proven server with the
// best Dial->Allocate latency takes every stream. Nothing is persisted — the
// resetServerHealth() in wgTurnProxyStart wipes it — so each connection learns
// its own verdict from scratch, which is what "for the current connection"
// means here.
//
// The state lives in serverHealth (turn_server_health.go) rather than a map of
// its own: the two are read together on every decision, and a second map would
// need its own lock and would drift out of step with the first.

// electionSettleWindow is how long after the session's first data-plane proof
// the election waits before locking a winner in.
//
// Without it the winner would always be whichever relay happened to answer
// first, and "the fastest server" would mean nothing: both prove themselves
// within about a second of each other, so the order is decided by workerStagger
// and a coin toss on the mobile RTT. Waiting lets every server that works report
// its latency first.
//
// This delays only the choice among the survivors, never the reaction to a
// failure: a server that fails its proof is dropped the moment it fails, and
// assignServers keeps spreading streams over whoever is left in the meantime.
// Well inside the 25s connect budget either way.
const electionSettleWindow = 3 * time.Second

// Election state, guarded by serverHealthState's mutex and cleared alongside it
// in resetServerHealth.
var (
	// firstProofAt is when any server first proved its data plane this session.
	// It starts the settle window.
	firstProofAt time.Time

	// electedAddr is the server every stream is currently routed to, or "" while
	// the session is still probing. The election is sticky: once a server is
	// elected it keeps every stream until it stops being eligible, so streams
	// never migrate on latency noise.
	electedAddr string
)

// noteServerRTT records addr's Dial->Allocate latency, measured by
// dialAndAllocate for the session that is about to run on it. This is the only
// latency signal we have, and the election uses it purely to rank servers that
// have already proven they carry traffic — a fast server that eats packets
// still loses to a slow one that does not.
func noteServerRTT(addr string, rtt time.Duration) {
	if addr == "" || rtt <= 0 {
		return
	}
	serverHealthState.Lock()
	defer serverHealthState.Unlock()
	healthEntryLocked(addr).rtt = rtt
}

// noteServerDemoted takes addr out of this session's rotation: it allocated a
// relay and then failed the data-plane handshake through it. Unlike the
// stand-down in noteServerHandshakeFailure this needs no proof from a sibling,
// because it punishes nothing — it only stops handing the host new streams while
// some other server still works. If the uplink is what died, every server ends
// up demoted, and assignServers falls back to the full list rather than to
// nothing.
func noteServerDemoted(addr string) { noteServerDemotedAt(addr, time.Now()) }

func noteServerDemotedAt(addr string, now time.Time) {
	if addr == "" {
		return
	}
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	h := healthEntryLocked(addr)
	// Every stream assigned to the bad host reports this within the same breath;
	// only the transition is worth a line.
	first := !demotedLocked(h)
	h.demotedAt = now
	if first {
		turnLog("[TURN ELECT] %s failed its data-plane handshake — out of rotation for this session", addr)
	}
}

// serverDemoted reports whether addr's last data-plane verdict was a failure.
func serverDemoted(addr string) bool {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()
	return demotedLocked(serverHealthState.byAddr[addr])
}

// demotedLocked compares the two stamps rather than latching a flag, so a
// demoted server that later carries a real round trip (reached as a failover
// candidate once everything else is gone) rejoins the rotation on its own. It
// takes actual proof to come back — nobody re-probes it on a timer.
func demotedLocked(h *serverHealth) bool {
	return h != nil && h.demotedAt.After(h.lastGood)
}

// electServer returns the server every stream should run on, or "" while the
// session is still probing — in which case assignServers keeps its round-robin
// spread so each candidate gets tried.
//
// Sticky by design: an incumbent that is still eligible is returned unchanged.
// Re-electing on every call would let ordinary latency jitter migrate the whole
// tunnel between hosts, and only the elected server keeps measuring its rtt
// anyway (nothing else is dialed), so the comparison would be against a frozen
// number from startup.
func electServer(candidates []string, now time.Time) string {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	if electedAddr != "" && eligibleLocked(electedAddr, now) {
		if slices.Contains(candidates, electedAddr) {
			return electedAddr
		}
		// This group's link did not come back with the elected server. Give it
		// the best of what it did get, without disturbing the global election —
		// otherwise two groups with different lists would fight over it.
		return bestLocked(candidates, now)
	}

	// Hold the round-robin spread until every working server has had time to
	// report, so the choice is the fastest one and not the luckiest one.
	if firstProofAt.IsZero() || now.Sub(firstProofAt) < electionSettleWindow {
		return ""
	}

	best := bestLocked(candidates, now)
	switch {
	case best == "":
		if electedAddr != "" {
			turnLog("[TURN ELECT] %s left the rotation and no proven server is left — re-probing %v",
				electedAddr, candidates)
			electedAddr = ""
		}
	case best != electedAddr:
		h := serverHealthState.byAddr[best]
		if electedAddr == "" {
			turnLog("[TURN ELECT] %s elected (rtt=%v) — routing every stream to it", best, h.rtt)
		} else {
			turnLog("[TURN ELECT] %s replaces %s (rtt=%v) — routing every stream to it", best, electedAddr, h.rtt)
		}
		electedAddr = best
	}
	return best
}

// bestLocked returns the eligible candidate with the lowest Dial->Allocate
// latency, or "" if none of them has proven its data plane.
func bestLocked(candidates []string, now time.Time) string {
	best := ""
	var bestRTT time.Duration
	for _, addr := range candidates {
		if !eligibleLocked(addr, now) {
			continue
		}
		rtt := serverHealthState.byAddr[addr].rtt
		if best == "" || rtt < bestRTT {
			best, bestRTT = addr, rtt
		}
	}
	return best
}

// eligibleLocked reports whether addr may be elected: it has carried a
// data-plane round trip, that proof is still its latest verdict, and it is not
// serving a stand-down.
func eligibleLocked(addr string, now time.Time) bool {
	h := serverHealthState.byAddr[addr]
	if h == nil || h.lastGood.IsZero() {
		return false
	}
	return !demotedLocked(h) && !penalizedLocked(h, now)
}

// resetElectionLocked clears the session-scoped election — this is what makes
// the verdict last exactly one connection. Called from resetServerHealth, which
// owns the lock and the rest of this state.
func resetElectionLocked() {
	firstProofAt = time.Time{}
	electedAddr = ""
}
