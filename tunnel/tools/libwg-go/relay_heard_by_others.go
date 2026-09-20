/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync"
	"time"
)

// Over TCP a data-plane handshake that fails is first of all the FLOW's failure.
//
// Over UDP a relay that allocates and then carries nothing is a fact about the
// relay, and one failed handshake takes it out of the rotation at once
// (noteServerHandshakeFailure). On the network that needs TCP every connection
// has a fate of its own: half of them hang for seconds beside neighbours to the
// same address that answer in 200ms (field log 19.09). There the same rule ruled
// on relays that were working as it spoke — 193.203.43.23 "out of rotation" with
// four live streams on it — and its stand-down clause is worse: "another server
// completed a handshake during this attempt" is true all the time when flows
// hang at random, so a single hung flow could stand a working relay down for
// five minutes.
//
// So over TCP the verdict needs the relay to have no alibi: if another stream is
// on it right now and hearing it — ready, and heard from within
// dispatchStaleAfter, the dispatcher's own measure — the relay's data plane
// works and the flow is what failed. Nothing is recorded. A relay nobody hears
// gets the verdict as before, so one that allocates and never carries a byte is
// still out after its first handshake. What this gives up: a relay that serves
// its old sessions and fails every NEW one keeps being dialed until the old ones
// go. Over UDP, where a flow has no fate of its own, nothing changes.
var liveSessions = struct {
	sync.Mutex
	byRelay map[string]map[*stream]struct{}
}{byRelay: map[string]map[*stream]struct{}{}}

// trackLiveSession books s as running a session on addr until the returned func
// is called.
func trackLiveSession(addr string, s *stream) func() {
	liveSessions.Lock()
	set := liveSessions.byRelay[addr]
	if set == nil {
		set = map[*stream]struct{}{}
		liveSessions.byRelay[addr] = set
	}
	set[s] = struct{}{}
	liveSessions.Unlock()

	return func() {
		liveSessions.Lock()
		delete(set, s)
		if len(liveSessions.byRelay[addr]) == 0 {
			delete(liveSessions.byRelay, addr)
		}
		liveSessions.Unlock()
	}
}

// relayHeardByOthers reports whether a stream other than except is ready on addr
// and has heard from it within dispatchStaleAfter. A ready stream that has not
// published its clock yet is no witness: only a received packet is.
func relayHeardByOthers(addr string, except *stream, now time.Time) bool {
	liveSessions.Lock()
	defer liveSessions.Unlock()
	for s := range liveSessions.byRelay[addr] {
		if s == except || !s.ready.Load() {
			continue
		}
		if a := s.activity.Load(); a != nil && a.rxAge(now) <= dispatchStaleAfter {
			return true
		}
	}
	return false
}
