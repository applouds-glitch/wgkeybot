/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"reflect"
	"testing"
)

// A typical device runs 8 streams (2 groups × 4) against the 2 TURN servers VK
// returns, and the load must land 4/4 rather than piling onto one host.
func TestAssignServersSpreadsEvenly(t *testing.T) {
	addrs := []string{"1.1.1.1:3478", "2.2.2.2:3478"}

	counts := map[string]int{}
	for id := 0; id < 8; id++ {
		counts[assignServers(addrs, id)[0]]++
	}

	for _, a := range addrs {
		if counts[a] != 4 {
			t.Errorf("server %s got %d of 8 streams, want 4 (counts: %v)", a, counts[a], counts)
		}
	}
}

// The assigned server must be the same for a given stream ID no matter what
// order VK happened to return the urls in for that group's link — otherwise
// group 0 and group 1 would disagree on which server is index 0 and the split
// would drift.
func TestAssignServersCanonicalOrder(t *testing.T) {
	forward := []string{"1.1.1.1:3478", "2.2.2.2:3478"}
	reversed := []string{"2.2.2.2:3478", "1.1.1.1:3478"}

	for id := 0; id < 8; id++ {
		if got, want := assignServers(reversed, id), assignServers(forward, id); !reflect.DeepEqual(got, want) {
			t.Errorf("stream %d: reversed input gave %v, want %v", id, got, want)
		}
	}
}

// Every server stays in the returned list — the ones after index 0 are the
// failover candidates runWithCreds falls back to when the assigned one errors.
func TestAssignServersKeepsFailoverCandidates(t *testing.T) {
	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"}

	for id := 0; id < 6; id++ {
		got := assignServers(addrs, id)
		if len(got) != len(addrs) {
			t.Fatalf("stream %d: got %d servers, want %d", id, len(got), len(addrs))
		}
		seen := map[string]bool{}
		for _, a := range got {
			seen[a] = true
		}
		for _, a := range addrs {
			if !seen[a] {
				t.Errorf("stream %d: server %s missing from %v", id, a, got)
			}
		}
	}
}

// addrs may alias the cached TurnCredentials.ServerAddrs slice (getCredsCached
// returns it by reference on a hit), so assignServers must never reorder in
// place — that would corrupt the cache for every other stream in the group.
func TestAssignServersDoesNotMutateInput(t *testing.T) {
	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	orig := append([]string(nil), addrs...)

	for id := 0; id < 4; id++ {
		assignServers(addrs, id)
	}

	if !reflect.DeepEqual(addrs, orig) {
		t.Errorf("input mutated: got %v, want %v", addrs, orig)
	}
}

// A single server (VK returned one url, or TurnIP is pinned) must pass through
// untouched — applyTurnOverride collapses the list before we get here.
func TestAssignServersSingleServer(t *testing.T) {
	addrs := []string{"1.1.1.1:3478"}

	for id := 0; id < 4; id++ {
		if got := assignServers(addrs, id); !reflect.DeepEqual(got, addrs) {
			t.Errorf("stream %d: got %v, want %v", id, got, addrs)
		}
	}
}
