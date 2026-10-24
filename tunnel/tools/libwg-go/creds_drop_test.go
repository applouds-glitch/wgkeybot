/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// withNoDroppedCreds gives the test a process that has dropped no credential
// yet, and puts the real record back after it: a test that dropped before it
// (credential_ttl_test.go does, on cleanup) must not reach into it.
func withNoDroppedCreds(t *testing.T) {
	t.Helper()
	droppedCreds.Lock()
	prev := droppedCreds.users
	droppedCreds.users = map[string]bool{}
	droppedCreds.Unlock()
	t.Cleanup(func() {
		droppedCreds.Lock()
		droppedCreds.users = prev
		droppedCreds.Unlock()
	})
}

// The drop clears the file, but its write can fail, and a failed write leaves
// the old file — the dropped identity in it — where it was. The next start in
// this process must not read it back: the drop was for that identity.
func TestADroppedIdentityDoesNotComeBackFromAFileThatWasNotCleared(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	dropped := stampedUser(now.Add(8*time.Hour), "dropped")
	fresh := stampedUser(now.Add(8*time.Hour), "fresh")
	links := []string{credsLinkA}
	startTurnCreds(links, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(dropped))
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	invalidateAllCaches()
	// As if the drop's write had failed: the file still holds the identity.
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	startTurnCreds(links, time.Now())
	if user, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds(fresh)); user != fresh {
		t.Fatalf("the next start dialed %s, the identity that was dropped, want a new one", user)
	}
}

// A fetch that was under way when every credential was dropped brings a new
// identity — the one the drop was for — and the next start takes it from the
// file rather than going to VK again for another.
func TestAFetchThatOutlivedTheDropIsTakenByTheNextStart(t *testing.T) {
	withTurnCredsFile(t)
	now := time.Now()
	fresh := stampedUser(now.Add(8*time.Hour), "fresh")
	links := []string{credsLinkA}
	startTurnCreds(links, now)

	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, _, err := getCredsCached(context.Background(), credsLinkA, 0, func(ctx context.Context, link string) (string, string, []string, int, error) {
			close(entered)
			<-release
			return vkCreds(fresh)(ctx, link)
		})
		done <- err
	}()
	<-entered
	invalidateAllCaches() // while the fetch is under way
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	startTurnCreds(links, time.Now())
	if user, _, _ := fetchGroup(t, 0, credsLinkA, noFetch(t)); user != fresh {
		t.Fatalf("the next start dialed %s, want %s from the fetch that finished after the drop", user, fresh)
	}
}

// The drop names what it is for: the identities the file was last written
// with and those the slots hold. Not one it never saw, and not by time — a
// clock stepped back since does not bring a dropped one back.
func TestTheDropNamesTheIdentitiesItIsFor(t *testing.T) {
	withTurnCredsFile(t)
	now := time.Now()
	onDisk := stampedUser(now.Add(8*time.Hour), "on-disk")
	inSlot := stampedUser(now.Add(8*time.Hour), "in-slot")
	startTurnCreds([]string{credsLinkA, credsLinkB}, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(onDisk))
	// A slot holding a credential the file was never written with.
	cache := getStreamCache(1 * streamsPerCredValue())
	cache.mutex.Lock()
	cache.creds = TurnCredentials{Username: inSlot, Link: credsLinkB, ExpiresAt: now.Add(time.Hour), FetchedAt: now}
	cache.mutex.Unlock()

	invalidateAllCaches()
	for _, c := range []struct {
		user    string
		fetched time.Time
		dropped bool
	}{
		{onDisk, now, true},
		{onDisk, now.Add(time.Hour), true}, // "fetched" after the drop by a clock set back
		{inSlot, now, true},
		{stampedUser(now.Add(8*time.Hour), "never-seen"), now.Add(-time.Hour), false},
		{"", now, false},
	} {
		if got := wasDropped(TurnCredentials{Username: c.user, FetchedAt: c.fetched}); got != c.dropped {
			t.Errorf("%q fetched at %v: dropped = %v, want %v", c.user, c.fetched.Sub(now), got, c.dropped)
		}
	}
}

// The file can hold an identity the slots and the mirror no longer name: a
// slot moved from A to B whose write of B failed leaves A in the file. A clear
// that fails too would hand A to the next start — so the drop names the file's
// own identities as well (Codex review, 23.10).
func TestTheDropNamesWhatTheFileHoldsAsWell(t *testing.T) {
	path := withTurnCredsFile(t)
	now := time.Now()
	inFile := stampedUser(now.Add(8*time.Hour), "in-file")
	moved := stampedUser(now.Add(8*time.Hour), "moved")
	fresh := stampedUser(now.Add(8*time.Hour), "fresh")
	links := []string{credsLinkA}
	startTurnCreds(links, now)
	fetchGroup(t, 0, credsLinkA, vkCreds(inFile))
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The slot moves on, and its write does not reach the file.
	cache := getStreamCache(0)
	cache.mutex.Lock()
	cache.creds = TurnCredentials{Username: moved, Password: "p", ServerAddrs: credsRelays, Link: credsLinkA, ExpiresAt: now.Add(time.Hour), FetchedAt: now}
	noteSlotCreds(0, cache.creds)
	cache.mutex.Unlock()

	invalidateAllCaches()
	// And the drop's clear fails as well: the file still holds the first one.
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	startTurnCreds(links, time.Now())
	if user, _, _ := fetchGroup(t, 0, credsLinkA, vkCreds(fresh)); user != fresh {
		t.Fatalf("the next start dialed %s from the file, want a new identity", user)
	}
}
