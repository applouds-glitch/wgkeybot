/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func stockSpare(t *testing.T, link, user string, ttl time.Duration) *StreamCredentialsCache {
	t.Helper()
	cache := getStreamCache(0)
	cache.mutex.Lock()
	cache.spare = TurnCredentials{
		Username: user, Password: "p", ServerAddrs: []string{"relay-a", "relay-b"},
		ExpiresAt: time.Now().Add(ttl), FetchedAt: time.Now(), Link: link,
	}
	cache.mutex.Unlock()
	return cache
}

func fetchNever(t *testing.T) fetchFunc {
	return func(context.Context, string) (string, string, []string, int, error) {
		t.Error("went to VK although the slot held a usable spare")
		return "", "", nil, 0, errors.New("unexpected fetch")
	}
}

// The whole point of the spare: an identity spent on 486 is replaced on the
// spot, with no trip to VK at the moment the streams are down.
func TestSpentIdentityIsReplacedByTheSpareWithoutATripToVK(t *testing.T) {
	prepareReconnectTest(t)
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		return "working", "p", []string{"relay-a", "relay-b"}, 3600, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, fetch); err != nil {
		t.Fatal(err)
	}
	cache := stockSpare(t, "link", "spare", time.Hour)

	if !refreshGroupCreds(0, "working", "p") {
		t.Fatal("rotation with a stocked spare did not report a ready credential")
	}
	user, _, addrs, err := getCredsCached(context.Background(), "link", 0, fetchNever(t))
	if err != nil || user != "spare" || len(addrs) != 2 {
		t.Fatalf("after rotation got user=%q addrs=%v err=%v", user, addrs, err)
	}
	cache.mutex.RLock()
	left := cache.spare.Username
	cache.mutex.RUnlock()
	if left != "" {
		t.Fatalf("promoted spare still held in reserve: %q", left)
	}
	select {
	case <-cache.spareWanted:
	default:
		t.Fatal("promotion did not ask the filler for the next spare")
	}

	// Siblings failing on the old identity a moment later must not burn the one
	// that just replaced it — and have nothing to wait for either.
	if refreshGroupCreds(0, "working", "p") {
		t.Fatal("a late failure of the old identity rotated the new one")
	}
	if !groupCredentialReplaced(0, "working", "p") || groupCredentialReplaced(0, "spare", "p") {
		t.Fatal("siblings cannot tell that the slot already holds the replacement")
	}
	if user, _, _, _ := getCredsCached(context.Background(), "link", 0, fetchNever(t)); user != "spare" {
		t.Fatalf("new identity lost to a sibling's late failure: %q", user)
	}
}

// Without a spare nothing changes: the slot is force-expired and the next fetch
// goes to VK, solve ladder and all.
func TestRotationWithoutASpareStillGoesToVK(t *testing.T) {
	prepareReconnectTest(t)
	calls := 0
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		calls++
		return fmt.Sprintf("id-%d", calls), "p", []string{"relay"}, 3600, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, fetch); err != nil {
		t.Fatal(err)
	}
	if refreshGroupCreds(0, "id-1", "p") {
		t.Fatal("rotation claimed a ready credential with no spare in the slot")
	}
	user, _, _, err := getCredsCached(context.Background(), "link", 0, fetch)
	if err != nil || user != "id-2" || calls != 2 {
		t.Fatalf("user=%q calls=%d err=%v", user, calls, err)
	}
}

// A quick stop/start holds the used identity aside (its allocations may still
// live on the relay). The spare has never touched a relay, so the reconnect
// takes it instead of going to VK.
func TestReconnectTakesTheUnusedSpareInsteadOfATripToVK(t *testing.T) {
	prepareReconnectTest(t)
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		return "working", "p", []string{"relay"}, 3600, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, fetch); err != nil {
		t.Fatal(err)
	}
	finish, err := beginCredentialUse(context.Background(), "working", "p", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	finish(true)
	stockSpare(t, "link", "spare", time.Hour)
	quarantineRecentlyUsedCredentials(time.Now())

	user, _, _, err := getCredsCached(context.Background(), "link", 0, fetchNever(t))
	if err != nil || user != "spare" {
		t.Fatalf("reconnect got user=%q err=%v", user, err)
	}
}

func TestUnusableSparesAreNotPromoted(t *testing.T) {
	cases := []struct {
		name  string
		stock func(t *testing.T)
	}{
		{"another link", func(t *testing.T) { stockSpare(t, "other-link", "spare", time.Hour) }},
		{"expired", func(t *testing.T) { stockSpare(t, "link", "spare", -time.Second) }},
		{"same identity as the one that failed", func(t *testing.T) { stockSpare(t, "link", "working", time.Hour) }},
		{"held aside after use", func(t *testing.T) {
			stockSpare(t, "link", "spare", time.Hour)
			finish, err := beginCredentialUse(context.Background(), "spare", "p", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			finish(true)
			quarantineRecentlyUsedCredentials(time.Now())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepareReconnectTest(t)
			fetch := func(context.Context, string) (string, string, []string, int, error) {
				return "working", "p", []string{"relay"}, 3600, nil
			}
			if _, _, _, err := getCredsCached(context.Background(), "link", 0, fetch); err != nil {
				t.Fatal(err)
			}
			tc.stock(t)
			if refreshGroupCreds(0, "working", "p") {
				t.Fatal("an unusable spare was promoted")
			}
		})
	}
}

var fastSpareSchedule = spareSchedule{
	initialDelay: 5 * time.Millisecond,
	minInterval:  20 * time.Millisecond,
	retryBase:    20 * time.Millisecond,
	retryMax:     40 * time.Millisecond,
	renewMargin:  time.Minute,
	idleRecheck:  10 * time.Millisecond,
}

func waitForSpare(t *testing.T, want string) {
	t.Helper()
	cache := getStreamCache(0)
	deadline := time.Now().Add(3 * time.Second)
	for {
		cache.mutex.RLock()
		got := cache.spare.Username
		cache.mutex.RUnlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("spare is %q, want %q", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func installSpareFetch(t *testing.T, fetch fetchFunc) {
	t.Helper()
	prev := globalFetchSpare
	globalFetchSpare = fetch
	t.Cleanup(func() { globalFetchSpare = prev })
}

// The filler stocks the slot while the group is up, restocks it after a
// promotion, and stays away from VK while the group has no ready stream — a
// spare is no use to a tunnel that is not running, and a fetch made while the
// uplink is what took the streams down is the one most likely to fail.
func TestFillerStocksAndRestocksTheSpareOnlyWhileTheGroupIsUp(t *testing.T) {
	prepareReconnectTest(t)
	var calls, ready atomic.Int32
	installSpareFetch(t, func(context.Context, string) (string, string, []string, int, error) {
		n := calls.Add(1)
		return fmt.Sprintf("spare-%d", n), "p", []string{"relay-a", "relay-b"}, 3600, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSpareFiller(ctx, WorkerGroupConfig{GroupID: 0, Link: "link"}, fastSpareSchedule, func() bool { return ready.Load() == 1 })
	}()

	time.Sleep(60 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("filler went to VK %d time(s) with no ready stream in the group", calls.Load())
	}

	ready.Store(1)
	waitForSpare(t, "spare-1")
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("filler kept fetching with the slot stocked: %d calls", calls.Load())
	}

	// The working identity is spent: the spare takes over and a new one follows.
	cache := getStreamCache(0)
	cache.mutex.Lock()
	cache.creds = TurnCredentials{Username: "working", Password: "p", ServerAddrs: []string{"relay-a"},
		ExpiresAt: time.Now().Add(time.Hour), FetchedAt: time.Now(), Link: "link"}
	cache.mutex.Unlock()
	if !refreshGroupCreds(0, "working", "p") {
		t.Fatal("stocked spare was not promoted")
	}
	waitForSpare(t, "spare-2")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("filler outlived its group")
	}
}

// A failed background fetch costs nothing and opens nothing: it is retried
// later, and the slot simply has no spare until then.
func TestFillerRetriesAFailedFetchWithoutStockingAnything(t *testing.T) {
	prepareReconnectTest(t)
	var calls atomic.Int32
	installSpareFetch(t, func(context.Context, string) (string, string, []string, int, error) {
		if calls.Add(1) == 1 {
			return "", "", nil, 0, errors.New("transient VK Calls failure")
		}
		return "spare-after-retry", "p", []string{"relay"}, 3600, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runSpareFiller(ctx, WorkerGroupConfig{GroupID: 0, Link: "link"}, fastSpareSchedule, func() bool { return true })

	waitForSpare(t, "spare-after-retry")
	if calls.Load() != 2 {
		t.Fatalf("expected one failure and one retry, got %d calls", calls.Load())
	}
}

// The first fetch stays clear of the connection's own prefetch, and consecutive
// ones are far enough apart that a group burning through identities cannot turn
// the filler into a mint storm.
func TestDefaultSpareScheduleIsPaced(t *testing.T) {
	if defaultSpareSchedule.initialDelay < time.Minute {
		t.Fatalf("first spare fetch %v after start crowds the connection's own prefetch", defaultSpareSchedule.initialDelay)
	}
	if defaultSpareSchedule.minInterval < 2*time.Minute {
		t.Fatalf("spare fetches %v apart can turn into a mint storm", defaultSpareSchedule.minInterval)
	}
}
