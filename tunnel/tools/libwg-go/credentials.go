/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"time"
)

// TurnCredentials stores cached TURN credentials.
type TurnCredentials struct {
	Username    string
	Password    string
	ServerAddrs []string
	ExpiresAt   time.Time
	FetchedAt   time.Time
	Link        string
}

// StreamCredentialsCache holds credentials for a group of streams sharing one cache slot.
type StreamCredentialsCache struct {
	creds TurnCredentials
	mutex sync.RWMutex

	// refreshMu guards lastRefresh and serialises the throttle decision in
	// refreshGroupCreds independently of the creds lock above.
	refreshMu   sync.Mutex
	lastRefresh time.Time // guarded by refreshMu
}

const (
	// credentialLifetime is the fallback TTL used when the VK API reports no
	// lifetime of its own — which is what it always does in practice
	// (api_ttl=0s in every "Credentials cached until" log line), so this is the
	// TTL. It is deliberately generous: guessing low is the expensive mistake.
	// A stream that dies after more than one TTL forces a full four-step VK
	// re-auth even though the credential is demonstrably still good (logs show
	// cache slots living 46m and 3h between fetches), and every extra VK
	// request is captcha exposure. Guessing high costs one Allocate that comes
	// back "error 401: Unauthorized" — classifyCredError matches it,
	// refreshGroupCreds force-expires the slot, and the worker's sub-second
	// retry fetches a fresh credential. Bounded downside, so prefer the long
	// TTL and let the error path drive the re-fetch.
	credentialLifetime = 60 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	// credRefreshThrottle is the minimum gap between error-driven credential
	// re-fetches for one cache slot. The first worker in a slot that hits an
	// auth/quota error force-expires the slot; siblings that fail within this
	// window reuse the freshly fetched credential instead of stampeding VK.
	credRefreshThrottle = 15 * time.Second
)

// streamsPerCred — number of streams sharing one credential cache slot.
// Also used as StreamsPerGroup in StartTunnelGroups.
var streamsPerCred = 4

// getCacheID maps a stream ID to its shared credential cache slot.
func getCacheID(streamID int) int {
	return streamID / streamsPerCred
}

var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()
	if exists {
		return cache
	}

	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()
	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}
	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

// invalidateAllCaches clears all credential caches (called on network change).
func invalidateAllCaches() {
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	turnLog("[Auth] All credential caches cleared (streamsPerCred=%d)", streamsPerCred)
}

// invalidateGroupCreds force-expires the cached credential for a single group so
// the next getCredsCached goes back to the VK API for a fresh one. Unlike
// invalidateAllCaches it does NOT delete the slot: keeping the same
// *StreamCredentialsCache pointer means the per-slot cache.mutex in
// getCredsCached still single-flights the re-fetch across the group's workers
// (the first re-fetches, the rest get a cache hit). Called when the TURN server
// rejects allocations for this credential (stale/401/486).
func invalidateGroupCreds(groupID int) {
	cache := getStreamCache(groupID * streamsPerCred)
	cache.mutex.Lock()
	var lived time.Duration
	if !cache.creds.FetchedAt.IsZero() {
		lived = time.Since(cache.creds.FetchedAt).Round(time.Second)
	}
	cache.creds.ExpiresAt = time.Now().Add(-time.Second)
	cache.mutex.Unlock()
	turnLog("[Auth] Credential cache for group %d force-expired (lived %v)", groupID, lived)
}

// refreshGroupCreds is the throttled, error-driven re-fetch entry point used by
// workers. The first worker in a slot to hit an auth/quota error force-expires
// the slot; siblings that fail within credRefreshThrottle become no-ops and
// reuse the credential the first worker's next getCredsCached fetches. Throttle
// state lives behind refreshMu so the decision is independent of the creds lock.
func refreshGroupCreds(groupID int) {
	cache := getStreamCache(groupID * streamsPerCred)

	cache.refreshMu.Lock()
	if !cache.lastRefresh.IsZero() && time.Since(cache.lastRefresh) < credRefreshThrottle {
		ago := time.Since(cache.lastRefresh).Round(time.Second)
		cache.refreshMu.Unlock()
		turnLog("[Auth] Group %d creds refreshed %v ago — skipping re-fetch", groupID, ago)
		return
	}
	cache.lastRefresh = time.Now()
	cache.refreshMu.Unlock()

	invalidateGroupCreds(groupID)
}

// fetchFunc is the raw credential retrieval function (no cache logic).
// Returns (username, password, serverAddr, lifetimeSecs, error).
type fetchFunc func(ctx context.Context, link string) (string, string, []string, int, error)

// getCredsFunc is the credential function type used by WorkerGroup via globalGetCreds.
type getCredsFunc func(context.Context, string, int) (string, string, []string, error)

// getCredsCached checks cache, then calls fn directly. The per-slot cache.mutex
// serialises concurrent misses for the same slot (single-flight: the first
// caller fetches, the rest get a cache hit), and vkSemaphore bounds VK API
// concurrency across slots. Uses the TTL returned by the fetch function to set
// ExpiresAt, capped at defaultCycleSecs.
func getCredsCached(ctx context.Context, link string, streamID int, fn fetchFunc) (string, string, []string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		ttl := time.Until(cache.creds.ExpiresAt).Round(time.Second)
		turnLog("[STREAM %d] Cache hit (cache=%d, ttl=%v)", streamID, cacheID, ttl)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddrs, nil
	}

	if !cache.creds.FetchedAt.IsZero() {
		lived := time.Since(cache.creds.FetchedAt).Round(time.Second)
		expired := time.Since(cache.creds.ExpiresAt).Round(time.Second)
		turnLog("[STREAM %d] Cache miss (cache=%d) — previous creds lived %v (expired %v ago), fetching...",
			streamID, cacheID, lived, expired)
	} else {
		turnLog("[STREAM %d] Cache miss (cache=%d), fetching...", streamID, cacheID)
	}
	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	default:
	}

	user, pass, addrs, lifetimeSecs, err := fn(ctx, link)
	if err != nil {
		return "", "", nil, err
	}

	// Compute ExpiresAt from the real API lifetime; fall back to credentialLifetime.
	expiry := time.Now().Add(credentialLifetime - cacheSafetyMargin)
	if lifetimeSecs > int(cacheSafetyMargin.Seconds()) {
		d := time.Duration(lifetimeSecs)*time.Second - cacheSafetyMargin
		if d > time.Duration(defaultCycleSecs)*time.Second {
			d = time.Duration(defaultCycleSecs) * time.Second
		}
		expiry = time.Now().Add(d)
	}

	cache.creds = TurnCredentials{
		Username:    user,
		Password:    pass,
		ServerAddrs: addrs,
		ExpiresAt:   expiry,
		FetchedAt:   time.Now(),
		Link:        link,
	}
	turnLog("[STREAM %d] Credentials cached until %v (cache=%d, api_ttl=%ds)",
		streamID, cache.creds.ExpiresAt.Format("15:04:05"), cacheID, lifetimeSecs)
	return user, pass, addrs, nil
}
