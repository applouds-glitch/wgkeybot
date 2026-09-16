/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
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

// assignServers preserves VK's preference order for every stream. The first
// available address is primary; runWithCreds only dials the others if Allocate
// or the data-plane handshake fails. Do not sort, spread hosts, or rank by RTT:
// a slightly faster Allocate is not evidence of a more reliable server.
//
// Exclude failed data planes and penalized hosts while alternatives remain.
// If every host is excluded, retry the original list so an uplink outage cannot
// leave the tunnel without candidates. A manual single-server pin also stands.
// The cached address slice is never modified.
func assignServers(addrs []string) []string {
	if len(addrs) < 2 {
		return addrs
	}

	now := time.Now()
	live := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if serverDemoted(addr) || serverPenalized(addr, now) {
			continue
		}
		live = append(live, addr)
	}
	if len(live) == 0 {
		return append([]string(nil), addrs...)
	}
	return live
}
