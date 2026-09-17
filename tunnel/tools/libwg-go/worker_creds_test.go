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

// VK counts its ten allocations per (identity, relay). Ten streams on one relay
// run at the limit, where any reconnect that cannot confirm its deallocate is a
// 486; spread over two they sit at five of ten, which also leaves room for a
// whole group reconnecting on top of its own ghosts.
func TestStreamsSpreadEvenlyOverTheRelays(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	addrs := []string{"relay-a:19302", "relay-b:19302"}
	first := map[string]int{}
	for id := 0; id < 10; id++ {
		order := serversForAttempt(addrs, id, "u", "p", time.Now())
		if len(order) != len(addrs) {
			t.Fatalf("stream %d lost its failover candidate: %v", id, order)
		}
		first[order[0]]++
	}
	if first[addrs[0]] != 5 || first[addrs[1]] != 5 {
		t.Fatalf("streams not spread five and five: %v", first)
	}
}

func TestServersForAttemptHandlesDegenerateLists(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	if got := serversForAttempt(nil, 3, "u", "p", time.Now()); len(got) != 0 {
		t.Fatalf("empty list produced %v", got)
	}
	one := []string{"pinned:3478"}
	for _, start := range []int{0, 7, -3} {
		if got := serversForAttempt(one, start, "u", "p", time.Now()); !reflect.DeepEqual(got, one) {
			t.Fatalf("start=%d: a single pinned relay became %v", start, got)
		}
	}
}

// The cached slice is shared by every stream of the group.
func TestServersForAttemptDoesNotModifyTheCachedList(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	addrs := []string{"a", "b", "c"}
	serversForAttempt(addrs, 2, "u", "p", time.Now())
	if !reflect.DeepEqual(addrs, []string{"a", "b", "c"}) {
		t.Fatalf("cached address list modified: %v", addrs)
	}
}

// A relay that answered this identity with 486 is not dialed again until the
// ghost allocations there can have expired — but only for this identity, and
// the other relay stays a candidate.
func TestServersForAttemptSkipsRelaysThatRefusedThisIdentity(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	now := time.Now()
	addrs := []string{"relay-a", "relay-b"}
	noteCredentialRelayQuota("u", "p", "relay-a", now)

	if got := serversForAttempt(addrs, 0, "u", "p", now); !reflect.DeepEqual(got, []string{"relay-b"}) {
		t.Fatalf("refused relay still offered: %v", got)
	}
	if got := serversForAttempt(addrs, 0, "other", "p", now); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("one identity's 486 hid the relay from another: %v", got)
	}
	if got := serversForAttempt(addrs, 0, "u", "p", now.Add(credentialRelayCooldown)); !reflect.DeepEqual(got, addrs) {
		t.Fatalf("refusal outlived its cooldown: %v", got)
	}

	// Every relay refused: nothing to dial, the identity is what has to change.
	noteCredentialRelayQuota("u", "p", "relay-b", now)
	if got := serversForAttempt(addrs, 0, "u", "p", now); len(got) != 0 {
		t.Fatalf("spent identity still offered relays: %v", got)
	}
	if !credentialSaturatedEverywhere("u", "p", addrs, now) {
		t.Fatal("identity refused by every relay not reported as spent")
	}
}

// The whole failover policy: a short failure moves the stream's next attempt to
// the next relay, a session that lasted pins the stream where it ran. Nothing
// is shared between streams, so an uplink outage cannot lock a relay out.
func TestShortFailureMovesTheStreamToTheNextRelay(t *testing.T) {
	resetCredentialQuota()
	defer resetCredentialQuota()
	addrs := []string{"relay-a", "relay-b"}
	s := &stream{id: 4}
	head := func() string { return serversForAttempt(addrs, s.id+s.addrShift, "u", "p", time.Now())[0] }

	if head() != "relay-a" {
		t.Fatalf("stream 4 should start on relay-a, got %s", head())
	}
	s.noteRelayOutcome(addrs, false)
	if head() != "relay-b" {
		t.Fatalf("a short failure left the stream on the relay that failed: %s", head())
	}

	// relay-b carries a session that lasts: reconnects go back to it.
	s.serverAddr = "relay-b"
	s.noteRelayOutcome(addrs, true)
	if head() != "relay-b" {
		t.Fatalf("a lasting session did not pin its relay: %s", head())
	}

	// A dark uplink fails every attempt alike. The stream only walks the list.
	for i := 0; i < 6; i++ {
		s.serverAddr = ""
		s.noteRelayOutcome(addrs, false)
	}
	if got := len(serversForAttempt(addrs, s.id+s.addrShift, "u", "p", time.Now())); got != 2 {
		t.Fatalf("an outage cost the stream a relay: %d candidates left", got)
	}

	// An attempt that never allocated ran on no relay and pins nothing.
	before := s.addrShift
	s.serverAddr = ""
	s.noteRelayOutcome(addrs, true)
	if s.addrShift != before {
		t.Fatal("an attempt with no relay changed the stream's shift")
	}
}
