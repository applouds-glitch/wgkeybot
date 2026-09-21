/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func slotIsCurrent(group int) bool {
	cache := getStreamCache(group * streamsPerCredValue())
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return time.Now().Before(cache.creds.ExpiresAt)
}

func lastRefreshOf(group int) time.Time {
	cache := getStreamCache(group * streamsPerCredValue())
	cache.refreshMu.Lock()
	defer cache.refreshMu.Unlock()
	return cache.lastRefresh
}

func fillSlot(t *testing.T, group int, user string) {
	t.Helper()
	if _, _, _, err := getCredsCached(context.Background(), "link", group*streamsPerCredValue(), fixedCreds(user)); err != nil {
		t.Fatal(err)
	}
}

// A rejection of the credential the slot holds rotates it; a rejection of one it
// no longer holds changes nothing — not the new credential, and not the
// throttle's clock, which the new credential may need for itself.
func TestRefreshActsOnlyOnTheCredentialTheSlotHolds(t *testing.T) {
	const group = 98
	dropCredSlot(t, group)
	fillSlot(t, group, "old")

	refreshGroupCreds(group, "old")
	if slotIsCurrent(group) {
		t.Fatal("a rejection of the current credential left it in place")
	}
	rotatedAt := lastRefreshOf(group)
	if rotatedAt.IsZero() {
		t.Fatal("the rotation did not start the throttle")
	}

	fillSlot(t, group, "new")
	// The straggler: an attempt on the old credential that ended long after its
	// siblings', past the throttle window.
	cache := getStreamCache(group * streamsPerCredValue())
	cache.refreshMu.Lock()
	cache.lastRefresh = time.Now().Add(-2 * credRefreshThrottle)
	longAgo := cache.lastRefresh
	cache.refreshMu.Unlock()

	refreshGroupCreds(group, "old")
	if !slotIsCurrent(group) {
		t.Fatal("a late rejection of the old credential expired the new one: a trip to VK for a credential nobody refused")
	}
	if got := lastRefreshOf(group); !got.Equal(longAgo) {
		t.Fatal("a rejection of a replaced credential moved the throttle's clock")
	}

	// The new one refused in its turn is rotated like any other.
	refreshGroupCreds(group, "new")
	if slotIsCurrent(group) {
		t.Fatal("a rejection of the new credential left it in place")
	}
}

// The way it happened: the rejection arrives while the replacement is being
// fetched. The slot's lock is held across the fetch, so the rejection waits —
// and when it gets the lock the slot holds the new credential.
func TestRejectionThatWaitedOutTheFetchLeavesTheNewCredentialAlone(t *testing.T) {
	const group = 99
	dropCredSlot(t, group)
	fillSlot(t, group, "old")
	refreshGroupCreds(group, "old")

	// Past the throttle, as after a captcha ladder.
	cache := getStreamCache(group * streamsPerCredValue())
	cache.refreshMu.Lock()
	cache.lastRefresh = time.Now().Add(-2 * credRefreshThrottle)
	cache.refreshMu.Unlock()

	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	defer letGo() // whatever fails below, the fetch must not be left holding the slot
	fetching := make(chan struct{})
	fetched := make(chan struct{})
	go func() {
		defer close(fetched)
		getCredsCached(context.Background(), "link", group*streamsPerCredValue(), func(context.Context, string) (string, string, []string, int, error) {
			close(fetching)
			<-release
			return "new", "pass", []string{"192.0.2.1:3478"}, 0, nil
		})
	}()
	within := func(what string, ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: not within 2s", what)
		}
	}
	within("the slot being refetched (the first rejection should have expired it)", fetching)

	calling := make(chan struct{})
	refreshed := make(chan struct{})
	go func() {
		defer close(refreshed)
		close(calling)
		refreshGroupCreds(group, "old")
	}()
	within("the late rejection being reported", calling)
	select {
	case <-refreshed:
		t.Fatal("the rejection did not wait for the fetch: the test staged nothing")
	case <-time.After(200 * time.Millisecond):
	}
	letGo()
	within("the fetch", fetched)
	within("the rejection", refreshed)

	if !slotIsCurrent(group) || credsReplaced(group, "new") {
		t.Fatal("the rejection of the old credential expired the one the fetch had just produced")
	}
}

// Every worker of the group reports the same refusal at once: one rotation.
func TestSimultaneousRejectionsRotateOnce(t *testing.T) {
	const group = 100
	dropCredSlot(t, group)
	fillSlot(t, group, "full")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			refreshGroupCreds(group, "full")
		}()
	}
	wg.Wait()
	if slotIsCurrent(group) {
		t.Fatal("ten rejections left the credential in place")
	}

	// The fresh one refused at once as well — a quota that is simply full — is
	// held by the throttle.
	fillSlot(t, group, "fresh")
	refreshGroupCreds(group, "fresh")
	if !slotIsCurrent(group) {
		t.Fatal("a credential fetched moments ago was rotated inside the throttle window")
	}
}
