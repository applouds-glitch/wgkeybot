/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"fmt"
	"sync"
	"time"
)

const (
	credentialRelayCooldown = 10 * time.Minute // a lost allocation can live for 600 s
	quotaFreshWindow        = time.Minute
	quotaPauseBase          = 30 * time.Second
	quotaPauseMax           = 5 * time.Minute
)

type credentialRelayKey struct {
	credentialAllocationKey
	addr string
}

type credentialQuotaIdentity struct {
	fetchedAt time.Time
	accepted  bool // any successful Allocate, even if that allocation has since closed
	counted   bool // one refusal per identity, not per worker or per relay
}

type credentialQuotaState struct {
	sync.Mutex
	identities map[credentialAllocationKey]credentialQuotaIdentity
	relays     map[credentialRelayKey]time.Time
	refusals   []time.Time
	lastTrip   time.Time
	pausedTill time.Time
	pause      time.Duration
}

var credentialQuota = credentialQuotaState{
	identities: make(map[credentialAllocationKey]credentialQuotaIdentity),
	relays:     make(map[credentialRelayKey]time.Time),
}

// These records survive proxy restarts and cache invalidation: neither action
// deletes the allocations still held by the TURN server.
func registerCredentialQuota(user, pass string, now time.Time) {
	credentialQuota.Lock()
	defer credentialQuota.Unlock()
	for key, identity := range credentialQuota.identities {
		if now.Sub(identity.fetchedAt) > 2*credentialLifetime {
			delete(credentialQuota.identities, key)
		}
	}
	for key, until := range credentialQuota.relays {
		if !now.Before(until) {
			delete(credentialQuota.relays, key)
		}
	}
	key := credentialAllocationKey{user, pass}
	if _, exists := credentialQuota.identities[key]; !exists {
		credentialQuota.identities[key] = credentialQuotaIdentity{fetchedAt: now}
	}
}

type credentialRelayQuotaError struct{ addr string }

func (e *credentialRelayQuotaError) Error() string {
	return fmt.Sprintf("TURN allocation quota cooldown on %s", e.addr)
}

func checkCredentialRelayQuota(user, pass, addr string, now time.Time) error {
	if err := checkCredentialReconnect(user, pass, now); err != nil {
		return err
	}
	credentialQuota.Lock()
	defer credentialQuota.Unlock()
	key := credentialRelayKey{credentialAllocationKey{user, pass}, addr}
	if now.Before(credentialQuota.relays[key]) {
		return &credentialRelayQuotaError{addr}
	}
	return nil
}

func noteCredentialRelayQuota(user, pass, addr string, now time.Time) {
	credentialQuota.Lock()
	credentialQuota.relays[credentialRelayKey{credentialAllocationKey{user, pass}, addr}] = now.Add(credentialRelayCooldown)
	credentialQuota.Unlock()
	turnLog("[Auth] Relay %s saturated for this credential — cooldown %v", addr, credentialRelayCooldown)
}

func noteCredentialAllocationAccepted(user, pass string) {
	credentialQuota.Lock()
	key := credentialAllocationKey{user, pass}
	identity := credentialQuota.identities[key]
	identity.accepted = true
	credentialQuota.identities[key] = identity
	credentialQuota.Unlock()
}

// Called only after an entire stream's failover attempt has failed. Healthy
// siblings, older identities and repeated reports of one identity do not trip
// the breaker. Checking outstanding leases also lets an in-flight sibling
// finish before deciding the relay refuses a fresh identity altogether.
func noteFreshCredentialRefusal(user, pass string, addrs []string, now time.Time) {
	key := credentialAllocationKey{user, pass}
	credentialAllocations.Lock()
	defer credentialAllocations.Unlock()
	if slots := credentialAllocations.byCred[key]; slots != nil && slots.refs > 0 {
		return
	}
	credentialQuota.Lock()
	defer credentialQuota.Unlock()
	identity := credentialQuota.identities[key]
	if identity.fetchedAt.IsZero() || now.Sub(identity.fetchedAt) >= quotaFreshWindow || identity.accepted || identity.counted || len(addrs) == 0 {
		return
	}
	for _, addr := range addrs {
		if !now.Before(credentialQuota.relays[credentialRelayKey{key, addr}]) {
			return // a timeout or other failure on another relay is not a fresh 486
		}
	}
	identity.counted = true
	credentialQuota.identities[key] = identity
	fresh := credentialQuota.refusals[:0]
	for _, at := range credentialQuota.refusals {
		if now.Sub(at) < quotaFreshWindow {
			fresh = append(fresh, at)
		}
	}
	credentialQuota.refusals = append(fresh, now)
	if len(credentialQuota.refusals) < 2 || now.Before(credentialQuota.pausedTill) {
		return
	}
	if now.Sub(credentialQuota.lastTrip) >= credentialRelayCooldown {
		credentialQuota.pause = quotaPauseBase
	} else {
		credentialQuota.pause = min(quotaPauseMax, 2*credentialQuota.pause)
	}
	credentialQuota.lastTrip = now
	credentialQuota.pausedTill = now.Add(credentialQuota.pause)
	credentialQuota.refusals = nil
	turnLog("[Auth] TURN refused two fresh identities — new credential fetches paused for %v; cached credentials remain usable", credentialQuota.pause)
}

type credentialMintPausedError struct{ until time.Time }

func (e *credentialMintPausedError) Error() string {
	return fmt.Sprintf("TURN refused fresh credentials; authentication paused for %v", max(time.Duration(0), time.Until(e.until)).Round(time.Second))
}

func checkCredentialMintPause(now time.Time) error {
	credentialQuota.Lock()
	defer credentialQuota.Unlock()
	if now.Before(credentialQuota.pausedTill) {
		return &credentialMintPausedError{credentialQuota.pausedTill}
	}
	return nil
}
