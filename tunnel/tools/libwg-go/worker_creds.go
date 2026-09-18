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

// assignServers returns the TURN servers this stream should try, best first.
//
// The list is sorted into a canonical order so the same physical server gets the
// same index in every group, regardless of the order VK returned the urls in for
// that group's link. Servers with a verdict against them — demoted for failing a
// data-plane handshake, or standing down under a penalty — are dropped outright
// rather than demoted to the back: runWithCreds fans out to addrs[1:] all at
// once when the head fails to Allocate, so a dead host left anywhere in the list
// can still win that race and cost the stream another session.
//
// What is left is assigned one of two ways:
//
//   - Once the session has elected a server (see turn_server_election.go), every
//     stream in every group runs on it.
//   - Until then, every stream runs on the first server of what is left. The
//     streams are not spread over the relays: the others are reached only as
//     failover (runWithCreds fans out to them when the head fails to Allocate),
//     and a server that proves itself that way becomes eligible for the election
//     like any other.
//
// If every server has a verdict against it the whole list stands. That is an
// outage, not a bad host, and an empty list would leave the stream nothing to
// dial; the next attempts re-probe all of them. Not in canonical order, though:
// outageOrder puts a server that failed only Allocates ahead of one that
// allocated and then failed the data plane, because the latter never fails over.
//
// Returns a fresh slice — addrs may alias the cached ServerAddrs slice (returned
// by reference on a cache hit), so it must not be mutated in place.
func assignServers(addrs []string) []string {
	if len(addrs) < 2 {
		return addrs
	}
	sorted := append([]string(nil), addrs...)
	sort.Strings(sorted)

	now := time.Now()
	live := make([]string, 0, len(sorted))
	for _, addr := range sorted {
		if serverDemoted(addr) || serverPenalized(addr, now) {
			continue
		}
		live = append(live, addr)
	}
	if len(live) == 0 {
		live = outageOrder(sorted)
	}

	if elected := electServer(live, now); elected != "" {
		if idx := slices.Index(live, elected); idx >= 0 {
			return rotateServers(live, idx)
		}
	}
	return live
}

// rotateServers returns list rotated so idx comes first, leaving the rest in
// canonical order behind it as failover candidates.
func rotateServers(list []string, idx int) []string {
	out := make([]string, 0, len(list))
	out = append(out, list[idx:]...)
	out = append(out, list[:idx]...)
	return out
}
