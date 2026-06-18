/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
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

// preferredAddr remembers, per group, the TURN server that last won the
// Allocate race (see stream_run_with_creds.go). It is a warm-cache hint only:
// the next reconnect tries it first (head-start), but still races the rest in
// case it has died. Kept separate from StreamCredentialsCache so it never
// interferes with credential freshness/single-flight.
var (
	preferredMu   sync.Mutex
	preferredAddr = map[int]string{}
)

// recordPreferred stores the race-winning address for a group.
func recordPreferred(groupID int, addr string) {
	preferredMu.Lock()
	preferredAddr[groupID] = addr
	preferredMu.Unlock()
}

// hasPreferred reports whether a fastest server has already been elected for the
// group. The first connection (none elected yet) probes all servers at once;
// later connections follow the election and only head-start-race.
func hasPreferred(groupID int) bool {
	preferredMu.Lock()
	_, ok := preferredAddr[groupID]
	preferredMu.Unlock()
	return ok
}

// orderPreferred returns addrs with the group's remembered preferred server
// moved to index 0 (the head-start slot). If there is no remembered preferred,
// or it is absent from the current list (e.g. creds were refreshed with a
// different server set), addrs is returned unchanged. When reordering it
// returns a fresh slice — addrs may alias the cached ServerAddrs slice, so it
// must not be mutated in place.
func orderPreferred(addrs []string, groupID int) []string {
	preferredMu.Lock()
	pref := preferredAddr[groupID]
	preferredMu.Unlock()
	if pref == "" {
		return addrs
	}
	for i, a := range addrs {
		if a != pref {
			continue
		}
		if i == 0 {
			return addrs
		}
		out := make([]string, 0, len(addrs))
		out = append(out, pref)
		out = append(out, addrs[:i]...)
		out = append(out, addrs[i+1:]...)
		return out
	}
	return addrs
}
