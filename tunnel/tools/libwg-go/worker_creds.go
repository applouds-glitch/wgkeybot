/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"sort"
)

// fetchCreds fetches TURN credentials for a specific group via the shared cache.
// groupID selects the correct credential cache slot (groupID * streamsPerCred),
// so all streams in a group share one credential. getCredsCached handles cache
// freshness, single-flight on a miss, and the VK re-fetch when the slot is
// expired or force-expired by refreshGroupCreds. Uses globalGetCreds
// (initialised by wgTurnProxyStart).
func fetchCreds(ctx context.Context, link string, groupID int) (user, pass string, addrs []string, err error) {
	streamID := groupID * streamsPerCred
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

// assignServers returns addrs rotated so index 0 is this stream's assigned TURN
// server, picked round-robin by stream ID. Streams are thereby spread evenly
// across every server VK returned instead of piling onto whichever one happened
// to win a latency race — the load (and the per-credential Allocate quota) is
// split across the hosts, and a reconnecting stream always returns to its own
// server rather than sticking to a stale winner.
//
// The list is first sorted into a canonical order so the same physical server
// gets the same index in every group, regardless of the order VK returned the
// urls in for that group's link. The remaining servers follow in canonical
// order and act purely as failover candidates: runWithCreds dials them only
// after the assigned one errors.
//
// Returns a fresh slice when rotating — addrs may alias the cached ServerAddrs
// slice (returned by reference on a cache hit), so it must not be mutated in
// place.
func assignServers(addrs []string, streamID int) []string {
	if len(addrs) < 2 {
		return addrs
	}
	sorted := append([]string(nil), addrs...)
	sort.Strings(sorted)
	idx := streamID % len(sorted)
	out := make([]string, 0, len(sorted))
	out = append(out, sorted[idx:]...)
	out = append(out, sorted[:idx]...)
	return out
}
