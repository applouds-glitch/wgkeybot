/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"slices"
	"time"
)

// Per-session demotion of a TURN server whose data plane failed, and the order
// the list falls back to when every server has a verdict against it.
//
// Until 2026-10-10 UDP also elected one server here — the proven one with the
// best Dial->Allocate latency — and routed every stream to it. Both transports
// now spread the streams over the relays (assignRelays): a single relay whose
// downlink went bad under every stream looked healthy to every check the
// session had, and spread, the judge of relay loss has a second relay to compare
// it with (relay_judge.go). What stays is the fast verdict the election brought
// with it: one failed data-plane handshake takes a server out of the rotation for
// the rest of the session, with no alibi and no threshold, because it punishes
// nothing — the penalty in turn_server_health.go is the slower, priced verdict.
// Nothing is persisted: resetServerHealth() in wgTurnProxyStart wipes it.
//
// The state lives in serverHealth (turn_server_health.go): the two are read
// together on every decision, and a second map would need its own lock and
// would drift out of step with the first.

// noteServerDemoted takes addr out of this session's rotation: it allocated a
// relay and then failed the data-plane handshake through it. Unlike the
// stand-down in noteServerHandshakeFailure this needs no proof from a sibling,
// because it punishes nothing — it only stops handing the host new streams while
// some other server still works. If the uplink is what died, every server ends
// up demoted, and assignRelays falls back to the full list rather than to
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
		turnLog("[TURN HEALTH] %s failed its data-plane handshake — out of rotation for this session", addr)
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

// outageOrder ranks the whole list for the case where every server has a
// verdict against it (see assignRelays). Servers that never failed a data-plane
// handshake go first, demoted ones last; within each, the server with the most
// recent proof leads, and the canonical order breaks the remaining ties.
//
// The head is the server every stream dials, and runWithCreds fans out to the
// rest only when the head fails to Allocate. A relay that allocates and then
// eats the data plane therefore never hands a stream on: at the head of the
// outage list it absorbs every attempt. Field log 18.09: 193.203.43.43 allocated
// in 200ms and never completed one SRTP handshake, while 91.231.135.87 — the only
// relay that ever carried the tunnel — was stood down for failing Allocates on a
// flapping path. "1…" sorts before "9…", so for the last 4-5 minutes before the
// watchdog tore the VPN down, in both sessions, every stream went to 193 and 91
// was never dialled. Ranked this way 91 leads, and 193 is still reached as
// failover whenever 91 does not answer.
//
// The streams do not all take the same head, though, when more than one server
// has carried a round trip and none of those has failed one since: that leading
// run is rotated by streamID, and stream 0 keeps the order exactly. Field run
// 18.10 (TCP, Rostelecom): a path dark for two minutes stood every relay down —
// relay_silence.go now keeps that from happening, this is the fallback should
// all of them be stood down again — and once the light was back every stream
// went to the relay with the freshest proof, seconds fresher than the rest: 8 of
// the 10 came up on it, and 13 minutes later they were still there. Behind that
// run the order stands — the unproven, then the demoted — so a relay that eats
// the data plane still never leads one that carried (18.09).
//
// Within that run the relays crowded with the credential's ghosts
// (orphaned_allocations.go) go behind the rest, rotated among them as in
// assignRelaysAround — and no further: behind an unproven or a demoted relay a
// crowded one would hand every stream to the very relay 18.09 is about, its
// worst case a 486 against that one's dead data plane (Codex review, 18.10).
func outageOrder(sorted []string, streamID int, crowded map[string]bool) []string {
	serverHealthState.Lock()
	defer serverHealthState.Unlock()

	out := append([]string(nil), sorted...)
	slices.SortStableFunc(out, func(a, b string) int {
		ha, hb := serverHealthState.byAddr[a], serverHealthState.byAddr[b]
		if da, db := demotedLocked(ha), demotedLocked(hb); da != db {
			if da {
				return 1
			}
			return -1
		}
		return lastGoodLocked(hb).Compare(lastGoodLocked(ha))
	})
	proven := 0
	for _, addr := range out {
		h := serverHealthState.byAddr[addr]
		if lastGoodLocked(h).IsZero() || demotedLocked(h) {
			break
		}
		proven++
	}
	if proven < 2 {
		return out
	}
	var clean, full []string
	for _, addr := range out[:proven] {
		if crowded[addr] {
			full = append(full, addr)
		} else {
			clean = append(clean, addr)
		}
	}
	if len(clean) == 0 || len(full) == 0 {
		return append(rotateServers(out[:proven], streamID%proven), out[proven:]...)
	}
	head := append(rotateServers(clean, streamID%len(clean)), rotateServers(full, streamID%len(full))...)
	return append(head, out[proven:]...)
}

// lastGoodLocked is h.lastGood for a server that may have no entry yet.
func lastGoodLocked(h *serverHealth) time.Time {
	if h == nil {
		return time.Time{}
	}
	return h.lastGood
}
