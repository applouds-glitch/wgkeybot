/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// The thresholds are literals on purpose: a test that derives them from the
// constants stays green when a constant is halved.

func TestTwoFreshCredentialsRefusedPauseMintingAndTheLadderDoubles(t *testing.T) {
	var b quotaBreaker
	t0 := time.Now()
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	// Ten workers refused on the same fresh credential are one refusal.
	for i := 0; i < 10; i++ {
		if paused, _ := b.noteRefusal("a", true, at(time.Duration(i)*100*time.Millisecond)); paused {
			t.Fatal("refusals of one credential paused minting")
		}
	}
	paused, left := b.noteRefusal("b", true, at(time.Second))
	if !paused || left != 30*time.Second {
		t.Fatalf("after two fresh credentials refused: paused=%v left=%v, want a 30s pause", paused, left)
	}
	if !b.skipRefresh(0, at(10*time.Second)) {
		t.Fatal("a refresh inside the pause was not skipped")
	}
	if b.skipRefresh(0, at(31*time.Second)) {
		t.Fatal("a refresh after the pause was skipped")
	}
	// Refusals inside the pause do not trip it again, whatever the credential.
	b.noteRefusal("b", true, at(5*time.Second))
	b.noteRefusal("c", true, at(6*time.Second))
	if b.trips != 1 {
		t.Fatalf("trips %d after refusals inside the pause, want 1", b.trips)
	}
	// Two fresh credentials refused after the pause, within the ladder window: double.
	b.noteRefusal("b", true, at(40*time.Second))
	if _, left := b.noteRefusal("d", true, at(41*time.Second)); left != 60*time.Second {
		t.Fatalf("second trip pause %v, want 60s", left)
	}
	// Up to the cap.
	now := at(2 * time.Minute)
	for i := 0; i < 6; i++ {
		now = now.Add(b.lastPause + time.Second)
		b.noteRefusal(fmt.Sprintf("x%d", i), true, now)
		_, left = b.noteRefusal(fmt.Sprintf("y%d", i), true, now.Add(time.Second))
	}
	if left != 5*time.Minute {
		t.Fatalf("pause after many trips %v, want the 5m cap", left)
	}
	// A trip long after the last starts the ladder over.
	later := now.Add(20 * time.Minute)
	b.noteRefusal("p", true, later)
	if _, left := b.noteRefusal("q", true, later.Add(time.Second)); left != 30*time.Second {
		t.Fatalf("a trip 20 minutes after the last paused for %v, want 30s again", left)
	}
}

// A 486 on an older credential, or on one that has been accepted before, is
// the identity's real quota: it is not counted, and a fresh identity remains
// its cure.
func TestOlderOrAcceptedCredentialsDoNotTripTheBreaker(t *testing.T) {
	var b quotaBreaker
	t0 := time.Now()
	for i := 0; i < 10; i++ {
		if paused, _ := b.noteRefusal(fmt.Sprintf("old%d", i), false, t0.Add(time.Duration(i)*time.Second)); paused {
			t.Fatal("refusals on older credentials paused minting")
		}
	}
	if b.skipRefresh(1, t0.Add(20*time.Second)) {
		t.Fatal("a refresh was skipped with nothing tripped")
	}
	// Fresh credentials refused too far apart do not add up either.
	b.noteRefusal("a", true, t0)
	if paused, _ := b.noteRefusal("b", true, t0.Add(61*time.Second)); paused {
		t.Fatal("two fresh credentials refused 61s apart paused minting")
	}
}

// credFreshAndUntouched reads the slot: the current credential, younger than a
// minute, with no allocation stamped on it.
func TestCredFreshAndUntouched(t *testing.T) {
	resetAllocationBook(t)
	cache := getStreamCache(7 * streamsPerCredValue())
	cache.mutex.Lock()
	prev := cache.creds
	cache.creds = TurnCredentials{Username: "fresh-user", FetchedAt: time.Now().Add(-10 * time.Second), ExpiresAt: time.Now().Add(time.Hour)}
	cache.mutex.Unlock()
	t.Cleanup(func() { cache.mutex.Lock(); cache.creds = prev; cache.mutex.Unlock() })

	now := time.Now()
	if !credFreshAndUntouched(7, "fresh-user", now) {
		t.Fatal("a 10-second-old credential with no allocation is not fresh")
	}
	if credFreshAndUntouched(7, "other-user", now) {
		t.Fatal("a credential the slot does not hold read as fresh")
	}
	if credFreshAndUntouched(7, "fresh-user", now.Add(2*time.Minute)) {
		t.Fatal("a two-minute-old credential read as fresh")
	}
	// Force-expired by a sibling's refreshGroupCreds, the slot still holds it:
	// the refusals that arrive after are still this credential's.
	cache.mutex.Lock()
	expireCredsLocked(cache)
	cache.mutex.Unlock()
	if !credFreshAndUntouched(7, "fresh-user", now) {
		t.Fatal("a force-expired fresh credential stopped counting")
	}
	trackAllocation(&countingConn{}, "fresh-user", "1.2.3.4:19302")
	if credFreshAndUntouched(7, "fresh-user", now) {
		t.Fatal("a credential an allocation succeeded on read as untouched")
	}
}

// The worker's question: only a 486 is held, and only once the breaker tripped.
func TestOnlyA486OnFreshCredentialsPausesMinting(t *testing.T) {
	resetAllocationBook(t)
	mintBreaker = quotaBreaker{}
	t.Cleanup(func() { mintBreaker = quotaBreaker{} })
	cache := getStreamCache(3 * streamsPerCredValue())
	cache.mutex.Lock()
	prev := cache.creds
	cache.creds = TurnCredentials{Username: "one", FetchedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	cache.mutex.Unlock()
	t.Cleanup(func() { cache.mutex.Lock(); cache.creds = prev; cache.mutex.Unlock() })

	now := time.Now()
	if quotaRefusalPausesMinting(allocateErr(turnErr(401)), 3, "one", now) {
		t.Fatal("a 401 was held")
	}
	if quotaRefusalPausesMinting(quota486(), 3, "one", now) {
		t.Fatal("the first fresh credential refused was held")
	}
	cache.mutex.Lock()
	cache.creds = TurnCredentials{Username: "two", FetchedAt: now, ExpiresAt: now.Add(time.Hour)}
	cache.mutex.Unlock()
	if !quotaRefusalPausesMinting(quota486(), 3, "two", now.Add(time.Second)) {
		t.Fatal("the second fresh credential refused was not held")
	}
	// Held, but a 401 on it still rotates it.
	if quotaRefusalPausesMinting(allocateErr(turnErr(401)), 3, "two", now.Add(2*time.Second)) {
		t.Fatal("a 401 inside the pause was held")
	}
}

// A session that ended because the relay no longer knows its socket leaves
// the allocation seated at the relay: it counts as a ghost on the (credential,
// relay), and the Refresh(0) its close sent — from the socket the relay does
// not know — does not read as a release settling.
func TestOutOfReachSessionOrphansItsRelay(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	for name, err := range map[string]error{
		"probe":     &deadStreamError{silent: time.Minute, probe: true, listened: 30 * time.Second},
		"wrapped":   fmt.Errorf("the relay connection is no longer read: %w", &deadStreamError{probe: true}),
		"blackhole": errors.New("TURN blackhole: Failed to refresh permissions: CreatePermission error response (error 400: Bad Request)"),
		"check":     errors.New("TURN blackhole: allocation check after thaw: CreatePermission error response (error 400: Bad Request)"),
	} {
		if !outOfReachError(err) {
			t.Errorf("%s: %v not read as out of reach", name, err)
		}
	}
	for name, err := range map[string]error{
		"detector":  &deadStreamError{silent: 90 * time.Second},
		"transport": errors.New("relay RX: read udp: use of closed network connection"),
		"mismatch":  errors.New("TURN blackhole: Failed to refresh permissions: CreatePermission error response (error 437: Allocation Mismatch)"),
		"nil":       nil,
	} {
		if outOfReachError(err) {
			t.Errorf("%s: %v read as out of reach", name, err)
		}
	}
	key := relayIdentity{user: "u", relay: orphanRelay1}
	releaseAllocation(key, nil, now, nil) // the close's Refresh(0) went out — on the new mapping
	noteOutOfReach("u", orphanRelay1, nil, now)
	if n := ghosts("u", orphanRelay1, now); n != 1 {
		t.Fatalf("the out-of-reach allocation counted %d ghost(s), want 1", n)
	}
	if _, _, settling := settlingQuotaError(quota486(), "u", []string{orphanRelay1}, now.Add(time.Second)); settling {
		t.Fatal("a 486 from a relay holding an out-of-reach allocation read as a release settling")
	}
}
