/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Refresh(0) is best effort: its response or an earlier Allocate response may
// have been lost. Allow the ordinary 600s allocation lifetime plus some margin.
const credentialReconnectCooldown = credentialRelayCooldown + 30*time.Second

type credentialUse struct {
	active       int // Allocate in flight or a relay not yet closed
	lastUsed     time.Time
	blockedUntil time.Time
}

var credentialUses = struct {
	sync.Mutex
	byCred map[credentialAllocationKey]*credentialUse
}{byCred: make(map[credentialAllocationKey]*credentialUse)}

type credentialReconnectError struct{ until time.Time }

func (e *credentialReconnectError) Error() string {
	return "TURN credential held aside after reconnect"
}

type credentialReuseWaitError struct{ until time.Time }

func (e *credentialReuseWaitError) Error() string {
	return fmt.Sprintf("VK returned recently used TURN credentials; retry in %v", max(time.Duration(0), time.Until(e.until)).Round(time.Second))
}
func (e *credentialReuseWaitError) RetryAt() time.Time  { return e.until }
func (e *credentialMintPausedError) RetryAt() time.Time { return e.until }

func checkCredentialReconnect(user, pass string, now time.Time) error {
	credentialUses.Lock()
	defer credentialUses.Unlock()
	return credentialReconnectLocked(credentialAllocationKey{user, pass}, now)
}
func credentialReconnectLocked(key credentialAllocationKey, now time.Time) error {
	if use := credentialUses.byCred[key]; use != nil && !use.blockedUntil.IsZero() {
		if use.active > 0 {
			use.blockedUntil = maxTime(use.blockedUntil, now.Add(credentialReconnectCooldown))
		}
		if !now.Before(use.blockedUntil) {
			use.blockedUntil = time.Time{}
			return nil
		}
		return &credentialReconnectError{use.blockedUntil}
	}
	return nil
}

// Start tracking only when the Allocate is about to go on the wire, not while
// waiting for a local slot or dialing. Checking cancellation under this lock
// lets cancel -> quarantine include every departing worker's possible request.
func beginCredentialUse(ctx context.Context, user, pass string, now time.Time) (func(bool), error) {
	key := credentialAllocationKey{user, pass}
	credentialUses.Lock()
	if err := ctx.Err(); err != nil {
		credentialUses.Unlock()
		return nil, err
	}
	if err := credentialReconnectLocked(key, now); err != nil {
		credentialUses.Unlock()
		return nil, err
	}
	use := credentialUses.byCred[key]
	if use == nil {
		use = &credentialUse{}
		credentialUses.byCred[key] = use
	}
	use.active++
	credentialUses.Unlock()
	var once sync.Once
	return func(possibleAllocation bool) {
		once.Do(func() {
			credentialUses.Lock()
			defer credentialUses.Unlock()
			use.active--
			if possibleAllocation {
				use.lastUsed = time.Now()
				if !use.blockedUntil.IsZero() {
					use.blockedUntil = maxTime(use.blockedUntil, use.lastUsed.Add(credentialReconnectCooldown))
				}
			}
		})
	}, nil
}
func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

// Keep unused cached credentials. Quarantine active/recently used identities
// before the new connection fetches from cache, even if no 486 was observed.
func quarantineRecentlyUsedCredentials(now time.Time) {
	credentialUses.Lock()
	defer credentialUses.Unlock()
	count := 0
	for key, use := range credentialUses.byCred {
		until := use.lastUsed.Add(credentialReconnectCooldown)
		if use.active > 0 {
			until = now.Add(credentialReconnectCooldown)
		}
		if !now.Before(until) {
			if !now.Before(use.blockedUntil) {
				delete(credentialUses.byCred, key)
			}
			continue
		}
		use.blockedUntil = maxTime(use.blockedUntil, until)
		count++
	}
	if count > 0 {
		turnLog("[Auth] Reconnect: holding aside %d recently used credential identities (up to %v)", count, credentialReconnectCooldown)
	}
}

// Every close path (winner, losing racer, watchdog) updates last use once, after
// the underlying relay has attempted to send its allocation-delete request.
type credentialTrackedRelay struct {
	net.PacketConn
	once     sync.Once
	finish   func(bool)
	closeErr error
}

func (c *credentialTrackedRelay) Close() error {
	c.once.Do(func() { c.closeErr = c.PacketConn.Close(); c.finish(true) })
	return c.closeErr
}
