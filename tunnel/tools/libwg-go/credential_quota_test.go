package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func resetCredentialQuota() {
	credentialQuota.Lock()
	defer credentialQuota.Unlock()
	credentialQuota.identities = make(map[credentialAllocationKey]credentialQuotaIdentity)
	credentialQuota.relays = make(map[credentialRelayKey]time.Time)
	credentialQuota.refusals = nil
	credentialQuota.lastTrip = time.Time{}
	credentialQuota.pausedTill = time.Time{}
	credentialQuota.pause = 0
}

func TestCredentialRelayCooldownIsScopedAndExpires(t *testing.T) {
	resetCredentialQuota()
	t.Cleanup(resetCredentialQuota)
	now := time.Now()
	noteCredentialRelayQuota("u", "p", "relay-a", now)
	for _, tc := range []struct {
		user, pass, addr string
		blocked          bool
	}{
		{"u", "p", "relay-a", true}, {"u", "p", "relay-b", false}, {"u", "other", "relay-a", false}, {"other", "p", "relay-a", false},
	} {
		err := checkCredentialRelayQuota(tc.user, tc.pass, tc.addr, now)
		if (err != nil) != tc.blocked {
			t.Fatalf("%+v: %v", tc, err)
		}
		if err != nil && (!isQuotaError(err) || !classifyCredError(err)) {
			t.Fatalf("worker cannot classify cooldown: %v", err)
		}
	}
	if err := checkCredentialRelayQuota("u", "p", "relay-a", now.Add(credentialRelayCooldown)); err != nil {
		t.Fatal(err)
	}
}

func TestFreshQuotaBreakerIgnoresHealthyPartialOldAndDuplicateRefusals(t *testing.T) {
	resetCredentialQuota()
	t.Cleanup(resetCredentialQuota)
	now := time.Now()
	addrs := []string{"a", "b"}
	refuse := func(user string) {
		for _, addr := range addrs {
			noteCredentialRelayQuota(user, "p", addr, now)
		}
		noteFreshCredentialRefusal(user, "p", addrs, now)
	}
	registerCredentialQuota("healthy", "p", now)
	noteCredentialAllocationAccepted("healthy", "p")
	refuse("healthy")
	registerCredentialQuota("old", "p", now.Add(-2*quotaFreshWindow))
	refuse("old")
	registerCredentialQuota("partial", "p", now)
	noteCredentialRelayQuota("partial", "p", "a", now)
	noteFreshCredentialRefusal("partial", "p", addrs, now)
	registerCredentialQuota("pending", "p", now)
	release, err := acquireCredentialAllocation(context.Background(), "pending", "p")
	if err != nil {
		t.Fatal(err)
	}
	refuse("pending")
	release()
	noteCredentialAllocationAccepted("pending", "p")
	refuse("pending")
	registerCredentialQuota("first", "p", now)
	refuse("first")
	refuse("first")
	if err := checkCredentialMintPause(now); err != nil {
		t.Fatalf("false breaker: %v", err)
	}
	registerCredentialQuota("second", "p", now)
	refuse("second")
	var paused *credentialMintPausedError
	if !errors.As(checkCredentialMintPause(now), &paused) || paused.until.Sub(now) != quotaPauseBase {
		t.Fatalf("missing 30s pause: %+v", paused)
	}
	if err := checkCredentialMintPause(now.Add(quotaPauseBase)); err != nil {
		t.Fatal(err)
	}
}

func TestFreshQuotaBreakerEscalatesAndRecovers(t *testing.T) {
	resetCredentialQuota()
	t.Cleanup(resetCredentialQuota)
	now := time.Now()
	for cycle := 0; cycle < 7; cycle++ {
		for j := 0; j < 2; j++ {
			u := fmt.Sprintf("%d-%d", cycle, j)
			registerCredentialQuota(u, "p", now)
			noteCredentialRelayQuota(u, "p", "a", now)
			noteFreshCredentialRefusal(u, "p", []string{"a"}, now)
		}
		var paused *credentialMintPausedError
		if !errors.As(checkCredentialMintPause(now), &paused) {
			t.Fatal("missing pause")
		}
		want := min(quotaPauseMax, quotaPauseBase*time.Duration(1<<cycle))
		if paused.until.Sub(now) != want {
			t.Fatalf("cycle %d: %v want %v", cycle, paused.until.Sub(now), want)
		}
		now = paused.until.Add(time.Second)
	}
	now = now.Add(credentialRelayCooldown)
	for _, u := range []string{"recover1", "recover2"} {
		registerCredentialQuota(u, "p", now)
		noteCredentialRelayQuota(u, "p", "a", now)
		noteFreshCredentialRefusal(u, "p", []string{"a"}, now)
	}
	var paused *credentialMintPausedError
	if !errors.As(checkCredentialMintPause(now), &paused) || paused.until.Sub(now) != quotaPauseBase {
		t.Fatal("backoff did not reset")
	}
}

func TestQuotaPauseAllowsCacheHitsAndStaleFailureCannotExpireReplacement(t *testing.T) {
	resetCredentialQuota()
	t.Cleanup(resetCredentialQuota)
	invalidateAllCaches()
	t.Cleanup(invalidateAllCaches)
	fn := func(context.Context, string) (string, string, []string, int, error) {
		return "new", "p", []string{"a"}, 3600, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, fn); err != nil {
		t.Fatal(err)
	}
	refreshGroupCreds(0, "old", "p")
	credentialQuota.Lock()
	credentialQuota.pausedTill = time.Now().Add(time.Minute)
	credentialQuota.Unlock()
	forbidden := func(context.Context, string) (string, string, []string, int, error) {
		t.Fatal("authentication during pause")
		return "", "", nil, 0, nil
	}
	if u, _, _, err := getCredsCached(context.Background(), "link", 0, forbidden); err != nil || u != "new" {
		t.Fatalf("cache invalidated by stale worker: %s %v", u, err)
	}
	refreshGroupCreds(0, "new", "p")
	var paused *credentialMintPausedError
	if _, _, _, err := getCredsCached(context.Background(), "link", 0, forbidden); !errors.As(err, &paused) {
		t.Fatalf("miss must pause: %v", err)
	}
}
