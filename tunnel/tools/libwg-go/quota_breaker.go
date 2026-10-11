/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync"
	"time"
)

// The relay-refusal breaker — after anton48/vk-turn-proxy-ios quotabreaker.go
// (builds 389–391).
//
// A 486 ("Allocation Quota Reached") on a credential's FIRST allocation cannot
// be that identity's quota: a fresh identity has its ten seats on the relay. It
// says the relay, or the host behind it, refuses regardless of identity, and
// minting another one is waste — a run of 486s becomes a run of mints, until
// VK rate-limits the minting with a captcha, which the extension cannot solve
// (the captcha ladder). refreshGroupCreds mints at most once per
// credRefreshThrottle per group, which is still hundreds an hour with nothing
// to stop it.
//
// A refusal counts only on a credential that is FRESH (fetched less than
// quotaFreshCredWindow ago) and that NO allocation ever succeeded on — their
// build 391's lesson: the tenth allocation refused after nine successes is the
// identity's real quota, on a credential five seconds old, and a fresh identity
// is exactly its cure. Each credential counts once, however many workers report
// its refusal. quotaRefusalTrip such credentials within quotaRefusalWindow
// pause minting for quotaPauseBase, doubled per trip within quotaLadderWindow
// up to quotaPauseMax. The credential in hand stays in use: the workers retry
// on it with the quota cooldown, and a 486 on an older credential — ghosts
// from before a switch, a freeze — rotates it as before.

const (
	quotaFreshCredWindow = 60 * time.Second // a credential younger than this has no quota of its own to fill
	quotaRefusalWindow   = 60 * time.Second // fresh refusals are counted over this much
	quotaRefusalTrip     = 2                // and this many of them pause minting
	quotaLadderWindow    = 10 * time.Minute // a trip this soon after the last doubles the pause
	quotaPauseBase       = 30 * time.Second
	quotaPauseMax        = 5 * time.Minute
)

type freshRefusal struct {
	user string
	at   time.Time
}

type quotaBreaker struct {
	mu          sync.Mutex
	fresh       []freshRefusal // fresh, never-accepted credentials refused within quotaRefusalWindow, one entry each
	trips       int            // how many times it tripped, this process (the log)
	lastTrip    time.Time      // the ladder's clock
	lastPause   time.Duration  // the pause the last trip set
	pausedUntil time.Time      // minting is skipped while now is before it
	announced   bool           // the running pause has been logged as skipping a refresh
}

// mintBreaker is the one breaker of the process: the refusals of every group
// count together, as they come from the same relays.
var mintBreaker quotaBreaker

// noteRefusal records a 486 on user's credential; fresh says the credential is
// younger than quotaFreshCredWindow and nothing was ever allocated on it
// (credFreshAndUntouched). It reports whether minting is paused now.
func (b *quotaBreaker) noteRefusal(user string, fresh bool, now time.Time) (paused bool, left time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Before(b.pausedUntil) {
		// A refusal inside the pause is the pause's own: the workers are retrying
		// the credential the trip kept, as they are meant to.
		return true, b.pausedUntil.Sub(now)
	}
	if !fresh {
		return false, 0
	}
	kept := b.fresh[:0]
	counted := false
	for _, r := range b.fresh {
		if r.at.Before(now.Add(-quotaRefusalWindow)) {
			continue
		}
		counted = counted || r.user == user
		kept = append(kept, r)
	}
	if !counted {
		kept = append(kept, freshRefusal{user: user, at: now})
	}
	b.fresh = kept
	if len(b.fresh) < quotaRefusalTrip {
		return false, 0
	}
	pause := quotaPauseBase
	if !b.lastTrip.IsZero() && now.Sub(b.lastTrip) < quotaLadderWindow {
		pause = min(b.lastPause*2, quotaPauseMax)
	}
	b.trips++
	b.lastTrip, b.lastPause = now, pause
	b.pausedUntil = now.Add(pause)
	b.fresh = nil
	b.announced = false
	turnLog("[QUOTA] the relay refused %d fresh credentials within %v (486 with no allocation ever accepted on them) — minting paused for %v (trip %d); the credential in hand stays in use",
		quotaRefusalTrip, quotaRefusalWindow, pause.Round(time.Second), b.trips)
	return true, pause
}

// skipRefresh reports whether a credential refresh is to be skipped now — and
// says so once per pause.
func (b *quotaBreaker) skipRefresh(groupID int, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !now.Before(b.pausedUntil) {
		return false
	}
	if !b.announced {
		b.announced = true
		turnLog("[QUOTA] group %d: minting paused for another %v — the credential is kept and retried",
			groupID, b.pausedUntil.Sub(now).Round(time.Second))
	}
	return true
}

// quotaRefusalPausesMinting is the worker's question about a credential error:
// is it a 486 the breaker holds minting against? A 486 is counted first, so the
// refusal that trips the breaker is itself held. Any other credential error —
// 401, 438 — is never held: it says the credential is bad, not that the relay
// refuses everyone.
func quotaRefusalPausesMinting(err error, groupID int, user string, now time.Time) bool {
	if !isQuotaError(err) {
		return false
	}
	mintBreaker.noteRefusal(user, credFreshAndUntouched(groupID, user, now), now)
	return mintBreaker.skipRefresh(groupID, now)
}

// credFreshAndUntouched: user is the group's current credential, fetched less
// than quotaFreshCredWindow ago, and no allocation has ever succeeded on it
// (allocationBook.succeeded, stamped by trackAllocation). A slot whose lock is
// taken — a fetch in flight — reads as not fresh: the refusal is an older
// credential's then. A force-expired slot still holds the credential, so its
// later refusals — the siblings' — are still its own.
func credFreshAndUntouched(groupID int, user string, now time.Time) bool {
	cache := getStreamCache(groupID * streamsPerCredValue())
	if !cache.mutex.TryRLock() {
		return false
	}
	fresh := cache.creds.Username == user && !cache.creds.FetchedAt.IsZero() && now.Sub(cache.creds.FetchedAt) < quotaFreshCredWindow
	cache.mutex.RUnlock()
	if !fresh {
		return false
	}
	allocationBook.Lock()
	defer allocationBook.Unlock()
	return !allocationBook.succeeded[user]
}
