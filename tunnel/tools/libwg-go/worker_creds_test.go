/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"reflect"
	"testing"
)

// Until a server is elected, every stream — in every group — runs on the same
// host: the first in canonical order. The others are only failover candidates.
// resetServerHealth puts every test in this file back into that probing state.
func TestAssignServersPutsEveryStreamOnOneServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"2.2.2.2:3478", "1.1.1.1:3478"}

	for id := 0; id < 8; id++ {
		if got := assignServers(addrs)[0]; got != "1.1.1.1:3478" {
			t.Fatalf("stream %d ran on %s, want every stream on 1.1.1.1:3478", id, got)
		}
	}
}

// The first server must be the same no matter what order VK happened to return
// the urls in for a group's link — otherwise group 0 and group 1 would start on
// different hosts.
func TestAssignServersCanonicalOrder(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	forward := []string{"1.1.1.1:3478", "2.2.2.2:3478"}
	reversed := []string{"2.2.2.2:3478", "1.1.1.1:3478"}

	if got, want := assignServers(reversed), assignServers(forward); !reflect.DeepEqual(got, want) {
		t.Errorf("reversed input gave %v, want %v", got, want)
	}
}

// Every server with no verdict against it stays in the returned list — the ones
// after index 0 are the failover candidates runWithCreds falls back to when the
// first one errors.
func TestAssignServersKeepsFailoverCandidates(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"}

	got := assignServers(addrs)
	want := []string{"1.1.1.1:3478", "2.2.2.2:3478", "3.3.3.3:3478"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// addrs may alias the cached TurnCredentials.ServerAddrs slice (getCredsCached
// returns it by reference on a hit), so assignServers must never reorder in
// place — that would corrupt the cache for every other stream in the group.
func TestAssignServersDoesNotMutateInput(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	orig := append([]string(nil), addrs...)

	assignServers(addrs)

	if !reflect.DeepEqual(addrs, orig) {
		t.Errorf("input mutated: got %v, want %v", addrs, orig)
	}
}

// A single server (VK returned one url, or TurnIP is pinned) must pass through
// untouched — applyTurnOverride collapses the list before we get here.
func TestAssignServersSingleServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478"}

	if got := assignServers(addrs); !reflect.DeepEqual(got, addrs) {
		t.Errorf("got %v, want %v", got, addrs)
	}
}
