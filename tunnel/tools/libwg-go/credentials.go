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
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

// StreamCredentialsCache holds credentials for a group of streams sharing one cache slot.
type StreamCredentialsCache struct {
	creds TurnCredentials
	mutex sync.RWMutex
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
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

// invalidateGroupCreds drops the cached credential for a single group so the
// next fetch goes back to the VK API for a fresh one. Called when the TURN
// server rejects allocations for this credential with a quota error (486).
func invalidateGroupCreds(groupID int) {
	cacheID := getCacheID(groupID * streamsPerCred)
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()
	if _, ok := credentialsStore.caches[cacheID]; ok {
		delete(credentialsStore.caches, cacheID)
		turnLog("[Auth] Credential cache for group %d (slot %d) invalidated", groupID, cacheID)
	}
}

// fetchFunc is the raw credential retrieval function (no cache logic).
// Returns (username, password, serverAddr, lifetimeSecs, error).
type fetchFunc func(ctx context.Context, link string) (string, string, string, int, error)

// getCredsFunc is the credential function type used by WorkerGroup via globalGetCreds.
type getCredsFunc func(context.Context, string, int) (string, string, string, error)

// getCredsCached checks cache, then calls fn directly (serialisation is handled by groupFetchMu in WorkerGroup).
// Uses the TTL returned by the fetch function to set ExpiresAt, capped at defaultCycleSecs.
func getCredsCached(ctx context.Context, link string, streamID int, fn fetchFunc) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if cache.creds.Link == link && time.Until(cache.creds.ExpiresAt) > 2*cacheSafetyMargin {
		ttl := time.Until(cache.creds.ExpiresAt).Round(time.Second)
		turnLog("[STREAM %d] Cache hit (cache=%d, ttl=%v)", streamID, cacheID, ttl)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}

	turnLog("[STREAM %d] Cache miss (cache=%d), fetching...", streamID, cacheID)
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	user, pass, addr, lifetimeSecs, err := fn(ctx, link)
	if err != nil {
		return "", "", "", err
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
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  expiry,
		Link:       link,
	}
	turnLog("[STREAM %d] Credentials cached until %v (cache=%d, api_ttl=%ds)",
		streamID, cache.creds.ExpiresAt.Format("15:04:05"), cacheID, lifetimeSecs)
	return user, pass, addr, nil
}
