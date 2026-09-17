/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"math/rand"
	"time"
)

// A spare identity per credential slot: fetched in the background while the
// tunnel is up, never used until the working one is spent, and then promoted in
// place of a trip to VK.
//
// The only cure for an identity whose quota is full of ghost allocations is
// another identity — both reference clients agree on that (vk-turn-proxy-ios
// keeps a pool four times the size it needs; free-turn-proxy just refetches
// every ten minutes), and neither tries to out-account the relay. What they do
// not agree with is fetching it at the moment of need. That moment is, by
// construction, a bad one: the streams are down, the uplink is often what took
// them down, and a fetch that stumbles there falls through to the legacy chain
// and its full-screen captcha. In the 2026-09-17 log the trip made under a dark
// uplink timed out twice, forty seconds with the group's cache lock held.
//
// So the trip is made early instead, when nothing depends on it, and only down
// the captcha-free path (fetchVkCredsNoCaptcha): a spare that cannot be had
// without a captcha is simply not had, and the old inline fetch — solve ladder
// included — remains what happens when there is no spare to promote.
type spareSchedule struct {
	// initialDelay keeps the first fetch away from connection setup: the
	// prefetch for the working identity has just been to VK, and a tunnel that
	// is about to be torn down again does not need a spare.
	initialDelay, initialJitter time.Duration

	// minInterval spaces consecutive spare fetches, promotions included, so a
	// group that burns through identities cannot turn the filler into the mint
	// storm credential_quota.go exists to stop. vk-turn-proxy-ios paces its pool
	// grower at one fill per 120-300s; same numbers.
	minInterval, intervalJitter time.Duration

	// A failed fetch is retried on a doubling backoff. Nothing is waiting on it.
	retryBase, retryMax time.Duration

	// renewMargin replaces a spare this long before its cache deadline, so the
	// one promoted at three in the morning is not one that expires at four.
	renewMargin time.Duration

	// idleRecheck is how soon the filler looks again when the moment was wrong:
	// no ready stream, no network, or minting paused by the quota breaker.
	idleRecheck time.Duration
}

var defaultSpareSchedule = spareSchedule{
	initialDelay:   90 * time.Second,
	initialJitter:  60 * time.Second,
	minInterval:    2 * time.Minute,
	intervalJitter: 3 * time.Minute,
	retryBase:      5 * time.Minute,
	retryMax:       30 * time.Minute,
	renewMargin:    30 * time.Minute,
	idleRecheck:    time.Minute,
}

func jittered(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	return base + time.Duration(rand.Int63n(int64(jitter)))
}

// globalFetchSpare is the captcha-free fetch the filler uses, installed by
// wgTurnProxyStart. nil (hosts and tests that never start a proxy) disables it.
var globalFetchSpare fetchFunc

// spareUsableLocked reports whether the slot holds a spare that can replace the
// working identity for link right now. Callers must hold c.mutex.
func (c *StreamCredentialsCache) spareUsableLocked(link string, now time.Time) bool {
	sp := c.spare
	if sp.Username == "" || sp.Link != link || !now.Before(sp.ExpiresAt) {
		return false
	}
	if sp.Username == c.creds.Username && sp.Password == c.creds.Password {
		return false
	}
	return checkCredentialReconnect(sp.Username, sp.Password, now) == nil
}

// promoteSpareLocked makes the spare the working identity and asks the filler
// for the next one. Callers must hold c.mutex and have checked spareUsableLocked.
func (c *StreamCredentialsCache) promoteSpareLocked(cacheID int, why string, now time.Time) {
	c.creds = c.spare
	c.spare = TurnCredentials{}
	// The quota breaker judges an identity by how it fares in its first minute
	// of use, and for a spare that minute starts now, not when it was fetched.
	markCredentialQuotaFresh(c.creds.Username, c.creds.Password, now)
	select {
	case c.spareWanted <- struct{}{}:
	default:
	}
	turnLog("[Auth] Spare identity promoted (cache=%d, %s, ttl=%v) — no trip to VK",
		cacheID, why, time.Until(c.creds.ExpiresAt).Round(time.Second))
}

// runSpareFiller keeps the slot of one group stocked with a spare identity for
// as long as the group runs. It never blocks a worker: the fetch happens outside
// the cache lock, and a worker that needs credentials while it is in flight
// fetches its own exactly as before.
func runSpareFiller(ctx context.Context, cfg WorkerGroupConfig, sched spareSchedule, groupReady func() bool) {
	fetch := globalFetchSpare
	if fetch == nil || cfg.Link == "" {
		return
	}
	cacheID := cfg.GroupID
	retry := sched.retryBase
	var lastAttempt time.Time
	wait := jittered(sched.initialDelay, sched.initialJitter)

	for {
		cache := getStreamCache(cfg.GroupID * streamsPerCredValue())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-cache.spareWanted:
			timer.Stop()
		case <-timer.C:
		}

		now := time.Now()
		cache.mutex.RLock()
		stocked := cache.spareUsableLocked(cfg.Link, now.Add(sched.renewMargin))
		deadline := cache.spare.ExpiresAt
		cache.mutex.RUnlock()
		if stocked {
			wait = max(sched.idleRecheck, time.Until(deadline.Add(-sched.renewMargin)))
			continue
		}

		// Pace the mint, and keep it for a moment when it can succeed and is worth
		// having: a live group on a network that answers.
		if since := now.Sub(lastAttempt); !lastAttempt.IsZero() && since < sched.minInterval {
			wait = jittered(sched.minInterval-since, sched.intervalJitter)
			continue
		}
		if !groupReady() || !isNetworkAvailable() || checkCredentialMintPause(now) != nil {
			wait = sched.idleRecheck
			continue
		}

		select {
		case vkSemaphore <- struct{}{}:
		case <-ctx.Done():
			return
		}
		lastAttempt = time.Now()
		user, pass, addrs, lifetimeSecs, err := fetch(ctx, cfg.Link)
		<-vkSemaphore
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			turnLog("[Auth] Spare identity fetch failed (cache=%d): %v — retry in %v", cacheID, err, retry)
			wait = retry
			retry = min(sched.retryMax, 2*retry)
			continue
		}
		retry = sched.retryBase

		now = time.Now()
		cache.mutex.Lock()
		switch {
		case len(addrs) == 0:
			turnLog("[Auth] Spare identity discarded (cache=%d): VK returned no TURN servers", cacheID)
		case user == cache.creds.Username && pass == cache.creds.Password,
			checkCredentialReconnect(user, pass, now) != nil:
			// VK handed back an identity this client already holds allocations
			// on: as a spare it would bring its ghosts along.
			turnLog("[Auth] Spare identity discarded (cache=%d): VK returned one already in use", cacheID)
		default:
			registerCredentialQuota(user, pass, now)
			cache.spare = TurnCredentials{
				Username:    user,
				Password:    pass,
				ServerAddrs: addrs,
				ExpiresAt:   credentialExpiry(user, lifetimeSecs, now),
				FetchedAt:   now,
				Link:        cfg.Link,
			}
			turnLog("[Auth] Spare identity ready (cache=%d, until %v)", cacheID, cache.spare.ExpiresAt.Format("15:04:05"))
		}
		cache.mutex.Unlock()
		wait = jittered(sched.minInterval, sched.intervalJitter)
	}
}
