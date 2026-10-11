/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"reflect"
	"testing"
	"time"
)

// Streams take turns: stream i prefers the (i mod n)-th server in canonical
// order, with the rest of the list behind it as failover. resetServerHealth puts
// every test in this file back into a state with no verdicts.
func TestAssignRelaysSpreadsTheStreams(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"2.2.2.2:3478", "1.1.1.1:3478"}
	for id := 0; id < 8; id++ {
		want := []string{"1.1.1.1:3478", "2.2.2.2:3478"}[id%2]
		if got := assignRelays(addrs, id, time.Now())[0]; got != want {
			t.Fatalf("stream %d ran on %s, want %s", id, got, want)
		}
	}
}

// A stream's server must be the same no matter what order VK happened to return
// the urls in for a group's link — otherwise the same stream would land on
// different hosts in different groups' lists.
func TestAssignRelaysCanonicalOrder(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	forward := []string{"1.1.1.1:3478", "2.2.2.2:3478"}
	reversed := []string{"2.2.2.2:3478", "1.1.1.1:3478"}

	for id := 0; id < 4; id++ {
		if got, want := assignRelays(reversed, id, time.Now()), assignRelays(forward, id, time.Now()); !reflect.DeepEqual(got, want) {
			t.Errorf("stream %d: reversed input gave %v, want %v", id, got, want)
		}
	}
}

// Every server with no verdict against it stays in the returned list — the ones
// after index 0 are the failover candidates runWithCreds falls back to when the
// first one errors.
func TestAssignRelaysKeepsFailoverCandidates(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478", "2.2.2.2:3478"}

	got := assignRelays(addrs, 1, time.Now())
	want := []string{"2.2.2.2:3478", "3.3.3.3:3478", "1.1.1.1:3478"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// addrs may alias the cached TurnCredentials.ServerAddrs slice (getCredsCached
// returns it by reference on a hit), so assignRelays must never reorder in
// place — that would corrupt the cache for every other stream in the group.
func TestAssignRelaysDoesNotMutateInput(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"3.3.3.3:3478", "1.1.1.1:3478"}
	orig := append([]string(nil), addrs...)

	assignRelays(addrs, 1, time.Now())

	if !reflect.DeepEqual(addrs, orig) {
		t.Errorf("input mutated: got %v, want %v", addrs, orig)
	}
}

// A single server (VK returned one url, or TurnIP is pinned) must pass through
// untouched — applyTurnOverride collapses the list before we get here.
func TestAssignRelaysSingleServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	addrs := []string{"1.1.1.1:3478"}

	if got := assignRelays(addrs, 3, time.Now()); !reflect.DeepEqual(got, addrs) {
		t.Errorf("got %v, want %v", got, addrs)
	}
}
