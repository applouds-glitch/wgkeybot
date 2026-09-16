package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func resetCredentialUses() {
	credentialUses.Lock()
	defer credentialUses.Unlock()
	credentialUses.byCred = make(map[credentialAllocationKey]*credentialUse)
}
func prepareReconnectTest(t *testing.T) {
	resetCredentialUses()
	resetCredentialQuota()
	invalidateAllCaches()
	t.Cleanup(func() { resetCredentialUses(); resetCredentialQuota(); invalidateAllCaches() })
}
func TestReconnectSkipsUsedCacheBeforeAny486AndKeepsUnused(t *testing.T) {
	prepareReconnectTest(t)
	calls := 0
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		calls++
		return "fresh", "p", []string{"relay"}, 3600, nil
	}
	_, _, _, err := getCredsCached(context.Background(), "link", 0, fetch)
	if err != nil {
		t.Fatal(err)
	}
	finish, err := beginCredentialUse(context.Background(), "fresh", "p", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	finish(true)
	quarantineRecentlyUsedCredentials(time.Now())
	if err := checkCredentialRelayQuota("fresh", "p", "relay", time.Now()); err == nil || isQuotaError(err) || !classifyCredError(err) {
		t.Fatalf("wrong classification: %v", err)
	}
	replacement := func(context.Context, string) (string, string, []string, int, error) {
		calls++
		return "replacement", "p", []string{"relay"}, 3600, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, _, _, e := getCredsCached(context.Background(), "link", 0, replacement)
			if e != nil || u != "replacement" {
				t.Errorf("reconnect: %s %v", u, e)
			}
		}()
	}
	wg.Wait()
	if calls != 2 {
		t.Fatalf("expected single replacement fetch, got %d", calls)
	}
	// Another reconnect before any Allocate must reuse the unused replacement.
	quarantineRecentlyUsedCredentials(time.Now())
	_, _, _, err = getCredsCached(context.Background(), "link", 0, replacement)
	if err != nil || calls != 2 {
		t.Fatalf("unused cache lost: %v calls=%d", err, calls)
	}
}
func TestReconnectTracksPendingLateCloseAndDoesNotExtendIdleCooldown(t *testing.T) {
	prepareReconnectTest(t)
	finish, err := beginCredentialUse(context.Background(), "u", "p", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	quarantineRecentlyUsedCredentials(time.Now())
	if err := checkCredentialReconnect("u", "p", time.Now()); err == nil {
		t.Fatal("pending Allocate not held aside")
	}
	finish(true)
	finish(true)
	credentialUses.Lock()
	use := *credentialUses.byCred[credentialAllocationKey{"u", "p"}]
	credentialUses.Unlock()
	if use.active != 0 || use.blockedUntil.Before(use.lastUsed.Add(credentialReconnectCooldown)) {
		t.Fatalf("late close lost: %+v", use)
	}
	quarantineRecentlyUsedCredentials(use.lastUsed.Add(time.Minute))
	if err := checkCredentialReconnect("u", "p", use.blockedUntil); err != nil {
		t.Fatalf("idle reconnect extended cooldown: %v", err)
	}
	// Even an old successful relay still counts while it remains open.
	done, _ := beginCredentialUse(context.Background(), "live", "p", time.Now().Add(-time.Hour))
	quarantineRecentlyUsedCredentials(time.Now())
	if err := checkCredentialReconnect("live", "p", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("live old relay reused")
	}
	done(true)
}
func TestReconnectIgnoresDefiniteRefusalAndCancelledWaiter(t *testing.T) {
	prepareReconnectTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := beginCredentialUse(ctx, "cancelled", "p", time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	finish, _ := beginCredentialUse(context.Background(), "refused", "p", time.Now())
	finish(false)
	quarantineRecentlyUsedCredentials(time.Now())
	for _, u := range []string{"cancelled", "refused", "unused"} {
		if err := checkCredentialReconnect(u, "p", time.Now()); err != nil {
			t.Fatalf("%s incorrectly quarantined: %v", u, err)
		}
	}
}
func TestReconnectDuplicateMintDoesNotCauseAuthenticationLoop(t *testing.T) {
	prepareReconnectTest(t)
	finish, _ := beginCredentialUse(context.Background(), "same", "p", time.Now())
	finish(true)
	quarantineRecentlyUsedCredentials(time.Now())
	calls := 0
	fetch := func(context.Context, string) (string, string, []string, int, error) {
		calls++
		return "same", "p", []string{"relay"}, 3600, nil
	}
	for i := 0; i < 10; i++ {
		_, _, _, err := getCredsCached(context.Background(), "link", 0, fetch)
		var wait *credentialReuseWaitError
		if !errors.As(err, &wait) {
			t.Fatalf("duplicate must wait: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("duplicate auth storm: %d requests", calls)
	}
	// A separate group can still fetch its own fresh identity.
	other := func(context.Context, string) (string, string, []string, int, error) {
		return "other", "p", []string{"relay"}, 3600, nil
	}
	if _, _, _, err := getCredsCached(context.Background(), "link", streamsPerCredValue(), other); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectExpiredQuarantineAllowsMultipleNewAllocations(t *testing.T) {
	prepareReconnectTest(t)
	now := time.Now()
	credentialUses.Lock()
	credentialUses.byCred[credentialAllocationKey{"u", "p"}] = &credentialUse{lastUsed: now.Add(-time.Hour), blockedUntil: now.Add(-time.Second)}
	credentialUses.Unlock()
	for i := 0; i < maxStreamsPerCredential; i++ {
		finish, err := beginCredentialUse(context.Background(), "u", "p", now)
		if err != nil {
			t.Fatalf("stream %d: expired cooldown returned: %v", i, err)
		}
		defer finish(true)
	}
}

func TestReconnectPreventsOldAllocateOnWireAndAllowsFreshCredential(t *testing.T) {
	prepareReconnectTest(t)
	addr, requests := startFailoverTestServer(t, false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, raw, relay, _, _, err := dialAndAllocate(ctx, &stream{}, "old", "pass", addr, WorkerGroupConfig{UseUDP: true})
	if err != nil {
		t.Fatal(err)
	}
	relay.Close()
	client.Close()
	raw.Close()
	quarantineRecentlyUsedCredentials(time.Now())
	before := requests.Load()
	_, _, _, _, _, err = dialAndAllocate(ctx, &stream{}, "old", "pass", addr, WorkerGroupConfig{UseUDP: true})
	var held *credentialReconnectError
	if !errors.As(err, &held) || requests.Load() != before {
		t.Fatalf("old credential hit server: requests %d -> %d err=%v", before, requests.Load(), err)
	}
	client, raw, relay, _, _, err = dialAndAllocate(ctx, &stream{}, "new", "pass", addr, WorkerGroupConfig{UseUDP: true})
	if err != nil {
		t.Fatalf("fresh credential blocked: %v", err)
	}
	relay.Close()
	client.Close()
	raw.Close()
	credentialUses.Lock()
	active := credentialUses.byCred[credentialAllocationKey{"new", "pass"}].active
	credentialUses.Unlock()
	if active != 0 {
		t.Fatal("relay close leaked usage")
	}
}
