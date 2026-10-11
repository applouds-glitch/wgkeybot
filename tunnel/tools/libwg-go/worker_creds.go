/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"time"
)

// fetchCreds fetches TURN credentials for a specific group via the shared cache.
// groupID selects the correct credential cache slot (groupID * streamsPerCred),
// so all streams in a group share one credential. getCredsCached handles cache
// freshness, single-flight on a miss, and the VK re-fetch when the slot is
// expired or force-expired by refreshGroupCreds. Uses globalGetCreds
// (initialised by wgTurnProxyStart).
func fetchCreds(ctx context.Context, link string, groupID int) (user, pass string, addrs []string, err error) {
	streamID := groupID * streamsPerCredValue()
	u, p, a, e := globalGetCreds(ctx, link, streamID)
	if e != nil {
		err = fmt.Errorf("fetchCreds: %w", e)
		return
	}

	if len(a) == 0 {
		err = fmt.Errorf("fetchCreds: no TURN servers returned")
		return
	}
	if host, _, splitErr := net.SplitHostPort(a[0]); splitErr != nil || host == "" {
		err = fmt.Errorf("fetchCreds: invalid addr %q", a[0])
		return
	}

	user = u
	pass = p
	addrs = a
	return
}

// assignRelays returns the TURN servers a stream should try, its own first, over
// UDP and TCP alike: stream i prefers the (i mod n)-th of the n usable servers,
// so ten streams split 5/5 over the two relays VK hands out, and the rest of the
// list are its failover candidates.
//
// The list is sorted into a canonical order so the same physical server gets the
// same index in every group, regardless of the order VK returned the urls in for
// that group's link. Servers with a verdict against them — demoted for failing a
// data-plane handshake, standing down under a penalty, or resting from a bad
// downlink (relay_rest.go) — are dropped outright rather than demoted to the
// back: runWithCreds fans out to addrs[1:] all at once when the head fails to
// Allocate, so a dead host left anywhere in the list can still win that race and
// cost the stream another session. A healthy session is never moved, except off
// a relay that is being rested.
//
// If every server has a verdict against it the whole list stands. That is an
// outage, not a bad host, and an empty list would leave the stream nothing to
// dial; the next attempts re-probe all of them. Not in canonical order, though:
// outageOrder puts a server that failed only Allocates ahead of one that
// allocated and then failed the data plane, because the latter never fails over.
//
// UDP used to route every stream to one elected relay. Spread, the downlink of
// each relay pair carries half the traffic, and when one relay's downlink goes
// bad the judge has the other to compare it with (relay_judge.go) — a single
// relay going bad under every stream looked healthy to every check the session
// had (bench, 2026-10-10).
//
// Returns a fresh slice — addrs may alias the cached ServerAddrs slice (returned
// by reference on a cache hit), so it must not be mutated in place.
func assignRelays(addrs []string, streamID int, now time.Time) []string {
	sorted := append([]string(nil), addrs...)
	sort.Strings(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) < 2 {
		return sorted
	}
	live := make([]string, 0, len(sorted))
	for _, addr := range sorted {
		if relayUsable(addr, now) {
			live = append(live, addr)
		}
	}
	if len(live) == 0 {
		return outageOrder(sorted)
	}
	return rotateServers(live, streamID%len(live))
}

// relayUsable reports whether addr has no verdict against it: not demoted, not
// penalized, not resting.
func relayUsable(addr string, now time.Time) bool {
	return !serverDemoted(addr) && !serverPenalized(addr, now) && !relayResting(addr, now)
}

// hasOtherUsableRelay reports whether a session on addr, dialed from relays,
// has another usable relay to go to (relay_rest.go).
func hasOtherUsableRelay(relays []string, addr string, now time.Time) bool {
	for _, r := range relays {
		if r != addr && relayUsable(r, now) {
			return true
		}
	}
	return false
}

func streamAttemptOrder(user string, addrs []string, streamID int, cfg WorkerGroupConfig, now time.Time) []string {
	return orderAroundOrphans(user, assignRelays(addrs, streamID, now), now)
}

// rotateServers returns list rotated so idx comes first, leaving the rest in
// canonical order behind it as failover candidates.
func rotateServers(list []string, idx int) []string {
	out := make([]string, 0, len(list))
	out = append(out, list[idx:]...)
	out = append(out, list[:idx]...)
	return out
}
