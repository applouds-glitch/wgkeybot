/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	refreshMu      sync.Mutex
	lastRefresh    time.Time // guarded by refreshMu
	fetchNotBefore time.Time // guarded by mutex; VK returned quarantined credentials
	fetchRetryLink string    // guarded by mutex; do not pause a different call link

	// spare is an unused identity held in reserve (see credential_spare.go);
	// guarded by mutex. spareWanted wakes the filler once it has been promoted.
	spare       TurnCredentials
	spareWanted chan struct{}
}

const (
	// One credential may hold at most ten concurrent TURN allocations.
	maxStreamsPerCredential = 10

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
	// credentialExpiryBuffer is subtracted from the expiry VK stamps into the
	// TURN username (see credentialExpiryFromUsername). pion refreshes every
	// allocation at half its lifetime, so a credential that expires mid-session
	// costs a 401 on that refresh, a stream restart and a VK trip; stop handing
	// it out well before that. VK's usernames carry an expiry hours away, so the
	// buffer costs nothing in practice.
	credentialExpiryBuffer = 15 * time.Minute
	// credRefreshThrottle is the minimum gap between error-driven credential
	// re-fetches for one cache slot. The first worker in a slot that hits an
	// auth/quota error force-expires the slot; siblings that fail within this
	// window reuse the freshly fetched credential instead of stampeding VK.
	credRefreshThrottle = 15 * time.Second
)

// streamsPerCred — number of streams sharing one credential cache slot.
// Also used as StreamsPerGroup in StartTunnelGroups.
//
// Stored atomically because wgTurnProxyStart writes it for the session it is
// starting while workers of the previous session — cancelled, but not yet
// drained — are still reading it through getCacheID/fetchCreds. As a plain int
// that is a data race, and a torn or stale read sends a departing worker to the
// wrong cache slot.
var streamsPerCred atomic.Int64

func init() { streamsPerCred.Store(4) }

func streamsPerCredValue() int { return int(streamsPerCred.Load()) }

func setStreamsPerCred(n int) {
	streamsPerCred.Store(int64(clampStreamsPerCred(n)))
}

func clampStreamsPerCred(n int) int { return max(1, min(n, maxStreamsPerCredential)) }

// getCacheID maps a stream ID to its shared credential cache slot.
func getCacheID(streamID int) int {
	return streamID / streamsPerCredValue()
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
	cache = &StreamCredentialsCache{spareWanted: make(chan struct{}, 1)}
	credentialsStore.caches[cacheID] = cache
	return cache
}

// invalidateAllCaches clears all credential caches (called on network change).
func invalidateAllCaches() {
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	turnLog("[Auth] All credential caches cleared (streamsPerCred=%d)", streamsPerCredValue())
}

// refreshGroupCreds is the throttled, error-driven rotation entry point used by
// workers. The first worker in a slot to find its identity spent replaces it:
// with the spare if the slot holds one (reported as true — the new credential is
// already in the cache, nothing to wait for), otherwise by force-expiring the
// slot so the next getCredsCached goes to VK. Siblings that fail within
// credRefreshThrottle become no-ops and reuse whatever the first one landed.
// Throttle state lives behind refreshMu so the decision is independent of the
// creds lock.
func refreshGroupCreds(groupID int, user, pass string) bool {
	cache := getStreamCache(groupID * streamsPerCredValue())
	cache.refreshMu.Lock()
	defer cache.refreshMu.Unlock()
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	// A late failure belongs to the credential that actually failed. It must
	// never expire the replacement fetched by a sibling in the meantime.
	if cache.creds.Username != user || cache.creds.Password != pass {
		return false
	}
	if !cache.lastRefresh.IsZero() && time.Since(cache.lastRefresh) < credRefreshThrottle {
		return false
	}
	now := time.Now()
	cache.lastRefresh = now
	lived := now.Sub(cache.creds.FetchedAt).Round(time.Second)
	if cache.spareUsableLocked(cache.creds.Link, now) {
		cache.promoteSpareLocked(groupID, fmt.Sprintf("previous identity spent after %v", lived), now)
		return true
	}
	cache.creds.ExpiresAt = now.Add(-time.Second)
	turnLog("[Auth] Credential cache for group %d force-expired (lived %v)", groupID, lived)
	return false
}

// groupCredentialReplaced reports whether the group's slot already holds a live
// identity other than the one that just failed — a sibling got there first.
func groupCredentialReplaced(groupID int, user, pass string) bool {
	cache := getStreamCache(groupID * streamsPerCredValue())
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	c := cache.creds
	return c.Username != "" && (c.Username != user || c.Password != pass) && time.Now().Before(c.ExpiresAt)
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

	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) && checkCredentialReconnect(cache.creds.Username, cache.creds.Password, time.Now()) == nil {
		ttl := time.Until(cache.creds.ExpiresAt).Round(time.Second)
		turnLog("[STREAM %d] Cache hit (cache=%d, ttl=%v)", streamID, cacheID, ttl)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddrs, nil
	}

	// The working identity is expired, held aside after a reconnect, or belongs
	// to another link. An unused spare answers all three without a trip to VK —
	// which is what makes a quick stop/start instant: the quarantine sets the
	// used identity aside, and the spare has never touched a relay.
	if cache.spareUsableLocked(link, time.Now()) {
		cache.promoteSpareLocked(cacheID, "working identity unavailable", time.Now())
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

	if cache.fetchRetryLink == link && time.Now().Before(cache.fetchNotBefore) {
		return "", "", nil, &credentialReuseWaitError{cache.fetchNotBefore}
	}
	if err := checkCredentialMintPause(time.Now()); err != nil {
		return "", "", nil, err
	}

	user, pass, addrs, lifetimeSecs, err := fn(ctx, link)
	if err != nil {
		return "", "", nil, err
	}

	if err := checkCredentialReconnect(user, pass, time.Now()); err != nil {
		cache.fetchNotBefore = err.(*credentialReconnectError).until
		cache.fetchRetryLink = link
		return "", "", nil, &credentialReuseWaitError{cache.fetchNotBefore}
	}
	cache.fetchNotBefore = time.Time{}
	cache.fetchRetryLink = ""
	registerCredentialQuota(user, pass, time.Now())

	cache.creds = TurnCredentials{
		Username:    user,
		Password:    pass,
		ServerAddrs: addrs,
		ExpiresAt:   credentialExpiry(user, lifetimeSecs, time.Now()),
		FetchedAt:   time.Now(),
		Link:        link,
	}
	turnLog("[STREAM %d] Credentials cached until %v (cache=%d, api_ttl=%ds)",
		streamID, cache.creds.ExpiresAt.Format("15:04:05"), cacheID, lifetimeSecs)
	return user, pass, addrs, nil
}

// credentialExpiry is the cache deadline for a freshly fetched identity: from the
// real API lifetime when VK reports one, else from the expiry VK stamps into the
// username, else credentialLifetime.
func credentialExpiry(user string, lifetimeSecs int, now time.Time) time.Time {
	if lifetimeSecs > int(cacheSafetyMargin.Seconds()) {
		d := time.Duration(lifetimeSecs)*time.Second - cacheSafetyMargin
		if d > time.Duration(defaultCycleSecs)*time.Second {
			d = time.Duration(defaultCycleSecs) * time.Second
		}
		return now.Add(d)
	}
	if until, ok := credentialExpiryFromUsername(user); ok {
		return credentialCacheExpiry(until, now)
	}
	return now.Add(credentialLifetime - cacheSafetyMargin)
}

// credentialExpiryFromUsername reads the expiry VK's TURN REST service stamps
// into the username: "<unix seconds>:<key id>" (draft-uberti-behave-turn-rest).
// VK's JSON never reports a lifetime (api_ttl=0s in every log line), so this
// stamp is the only statement VK makes about how long the credential lives —
// typically hours, against the one-hour guess credentialLifetime falls back
// to. Every hour shaved off a good credential is one more VK round trip, and
// every VK round trip is captcha exposure. A username without the stamp, or
// with an unparsable one, simply reports false and the fallback applies.
func credentialExpiryFromUsername(username string) (time.Time, bool) {
	stamp, _, found := strings.Cut(username, ":")
	if !found || stamp == "" {
		return time.Time{}, false
	}
	secs, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || secs <= 0 {
		return time.Time{}, false
	}
	return time.Unix(secs, 0), true
}

// credentialCacheExpiry turns the stamped expiry into a cache deadline: the
// stamp minus credentialExpiryBuffer, never beyond defaultCycleSecs, and never
// before now. A stamp already inside the buffer is not a reason to refuse the
// credential — the relay still takes it, and a 401 on the next attempt is the
// cheap, bounded outcome the fallback TTL already accepts — so such a
// credential is cached for the ordinary fallback lifetime instead.
func credentialCacheExpiry(until, now time.Time) time.Time {
	expiry := until.Add(-credentialExpiryBuffer)
	if cap := now.Add(time.Duration(defaultCycleSecs) * time.Second); expiry.After(cap) {
		expiry = cap
	}
	if !expiry.After(now) {
		return now.Add(credentialLifetime - cacheSafetyMargin)
	}
	return expiry
}
