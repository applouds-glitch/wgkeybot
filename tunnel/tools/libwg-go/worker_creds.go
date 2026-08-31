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
//     stream in every group runs on it. The point of the election is that only
//     one of the relays VK returns is reliably working, so spreading across them
//     buys nothing and costs a stalled stream per dead host.
//   - Until then, round-robin by stream ID. This is the probing phase and it has
//     to stay a spread: a server nobody dials never proves itself, so pinning
//     before the verdict is in would make the verdict unreachable.
//
// If every server has a verdict against it the original list stands. That is an
// outage, not a bad host, and an empty list would leave the stream nothing to
// dial; the next attempts re-probe all of them.
//
// Returns a fresh slice — addrs may alias the cached ServerAddrs slice (returned
// by reference on a cache hit), so it must not be mutated in place.
func assignServers(addrs []string, streamID int) []string {
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
		live = sorted
	}

	if elected := electServer(live, now); elected != "" {
		if idx := slices.Index(live, elected); idx >= 0 {
			return rotateServers(live, idx)
		}
	}
	return rotateServers(live, streamID%len(live))
}

// rotateServers returns list rotated so idx comes first, leaving the rest in
// canonical order behind it as failover candidates.
func rotateServers(list []string, idx int) []string {
	out := make([]string, 0, len(list))
	out = append(out, list[idx:]...)
	out = append(out, list[:idx]...)
	return out
}
