/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func dropCredSlot(t *testing.T, group int) {
	t.Helper()
	drop := func() {
		credentialsStore.mu.Lock()
		delete(credentialsStore.caches, getCacheID(group*streamsPerCredValue()))
		credentialsStore.mu.Unlock()
	}
	drop()
	t.Cleanup(drop)
}

// invalidateGroupCreds force-expires a group's slot whatever it holds — what
// refreshGroupCreds does once it has decided to.
func invalidateGroupCreds(groupID int) {
	cache := getStreamCache(groupID * streamsPerCredValue())
	cache.mutex.Lock()
	expireCredsLocked(cache)
	cache.mutex.Unlock()
}

func fixedCreds(user string) fetchFunc {
	return func(context.Context, string) (string, string, []string, int, error) {
		return user, "pass", []string{"192.0.2.1:3478"}, 0, nil
	}
}

// The credential a worker dialed with is current until its slot is
// force-expired or refilled with another one.
func TestCredsReplacedFollowsTheSlot(t *testing.T) {
	const group = 94
	dropCredSlot(t, group)
	streamID := group * streamsPerCredValue()
	ctx := context.Background()

	if _, _, _, err := getCredsCached(ctx, "link", streamID, fixedCreds("u1")); err != nil {
		t.Fatal(err)
	}
	if credsReplaced(group, "u1") {
		t.Fatal("the current credential read as replaced")
	}
	invalidateGroupCreds(group)
	if !credsReplaced(group, "u1") {
		t.Fatal("a force-expired credential still read as current")
	}
	if _, _, _, err := getCredsCached(ctx, "link", streamID, fixedCreds("u2")); err != nil {
		t.Fatal(err)
	}
	if !credsReplaced(group, "u1") || credsReplaced(group, "u2") {
		t.Fatal("after the refill the old credential must read replaced and the new one current")
	}
}

// A fetch in flight holds the slot for as long as VK takes — a captcha ladder
// can take minutes. The answer is "replaced", and it must not wait for it.
func TestCredsReplacedDoesNotWaitForAFetch(t *testing.T) {
	const group = 95
	dropCredSlot(t, group)
	streamID := group * streamsPerCredValue()
	release := make(chan struct{})
	defer close(release)
	fetching := make(chan struct{})
	go getCredsCached(context.Background(), "link", streamID, func(context.Context, string) (string, string, []string, int, error) {
		close(fetching)
		<-release
		return "u3", "pass", []string{"192.0.2.1:3478"}, 0, nil
	})
	<-fetching

	answer := make(chan bool, 1)
	go func() { answer <- credsReplaced(group, "u2") }()
	select {
	case replaced := <-answer:
		if !replaced {
			t.Fatal("a slot being refetched read as holding the current credential")
		}
	case <-time.After(time.Second):
		t.Fatal("credsReplaced waited for the fetch in flight")
	}
}

// runWorkerAgainst runs one worker against addr until ctx ends, fetching
// through the real credential cache (as production does) from fn.
func runWorkerAgainst(t *testing.T, ctx context.Context, group int, addr string, fn fetchFunc) <-chan struct{} {
	t.Helper()
	prev := globalGetCreds
	globalGetCreds = func(ctx context.Context, link string, streamID int) (string, string, []string, error) {
		return getCredsCached(ctx, link, streamID, fn)
	}
	t.Cleanup(func() { globalGetCreds = prev })

	s, _ := newNoDTLSTestStream(t)
	peer := fakeRelay(t, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: peer}, s, 0)
	}()
	return done
}

// The second drop on 2026-09-18: every relay answered 486 on the old
// credential, the worker rotated it — and then sat out a 5-13s cooldown before
// anything fetched the new one. A 486 on a credential that is already replaced
// must retry at once, on the new credential.
func TestWorkerRetriesAtOnceAfter486OnReplacedCreds(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	const group = 96
	dropCredSlot(t, group)
	pc, _ := startInitialRefusalServer(t, 1, stun.CodeAllocQuotaReached)
	addr := pc.LocalAddr().String()

	var fetches atomic.Int32
	fn := func(context.Context, string) (string, string, []string, int, error) {
		if fetches.Add(1) == 1 {
			return "stale-" + t.Name(), "pass", []string{addr}, 0, nil
		}
		return t.Name(), "pass", []string{addr}, 0, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runWorkerAgainst(t, ctx, group, addr, fn)
	defer func() {
		cancel()
		<-done
	}()

	// The fast retry is 0.5-1s; the cooldown it replaces is at least 5s.
	waitFor(t, "a dial on the new credential", 2500*time.Millisecond, func() bool { return pc.count() >= 2 })
	if n := fetches.Load(); n != 2 {
		t.Fatalf("%d credential fetches, want the old one and exactly one new", n)
	}
}

// A 486 on the credential that is still current — its rotation throttled, as
// when the fresh one refuses too — keeps the long cooldown.
func TestWorker486OnCurrentCredsKeepsTheCooldown(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	const group = 97
	dropCredSlot(t, group)
	pc, _ := startInitialRefusalServer(t, 100, stun.CodeAllocQuotaReached)
	addr := pc.LocalAddr().String()

	cache := getStreamCache(group * streamsPerCredValue())
	cache.refreshMu.Lock()
	cache.lastRefresh = time.Now() // just rotated: the next rotation is throttled
	cache.refreshMu.Unlock()

	var fetches atomic.Int32
	fn := func(context.Context, string) (string, string, []string, int, error) {
		fetches.Add(1)
		return t.Name(), "pass", []string{addr}, 0, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runWorkerAgainst(t, ctx, group, addr, fn)
	defer func() {
		cancel()
		<-done
	}()

	waitFor(t, "the first dial", 2*time.Second, func() bool { return pc.count() >= 1 })
	time.Sleep(2500 * time.Millisecond)
	if n := pc.count(); n != 1 {
		t.Fatalf("%d dials within 2.5s of a 486 on the current credential, want the cooldown", n)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d credential fetches, want the current credential kept", n)
	}
}
