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

// A tethered client's every new connection arrives as a name, and net.Resolver
// caches nothing at all. Without this, opening one page costs one DNS round trip
// per host — each of them a UDP exchange that travels the full TURN path to the
// tunnel's resolver and back, which is exactly the leg where latency is worst.
//
// The TTL is fixed rather than read from the answer because Go's resolver API
// does not expose one: LookupHost returns addresses and nothing else. A minute
// is short enough that a failover on the far side is noticed about as fast as a
// phone's own DNS cache would notice it, and long enough that a page's worth of
// third-party hosts is resolved once instead of once per connection.
//
// Only successes are cached. A negative answer is usually the tunnel still
// settling, and remembering it would turn a half-second of bad luck into a
// minute of a site being "down".
const (
	tetherDNSCacheTTL     = time.Minute
	tetherDNSCacheEntries = 256
)

type cachedAddrs struct {
	addrs   []string
	expires time.Time
}

// hostLookup is one resolution in progress, shared by every caller that asked
// for the same name while it was running.
type hostLookup struct {
	done  chan struct{}
	addrs []string
	err   error
}

type cachingLookup struct {
	inner tetherLookup
	ttl   time.Duration
	max   int
	// now is a field so the TTL can be tested without sleeping.
	now func() time.Time

	mu      sync.Mutex
	entries map[string]cachedAddrs
	// inflight collapses concurrent lookups of the same name into one, the way
	// DnsCache does for the TURN side. The cache alone does not help here: one
	// page opens a dozen connections to the same host at once, every one of them
	// misses, and every one pays its own round trip down the whole TURN path
	// before the first answer is ever stored.
	inflight map[string]*hostLookup
}

func newCachingLookup(inner tetherLookup) *cachingLookup {
	return &cachingLookup{
		inner:    inner,
		ttl:      tetherDNSCacheTTL,
		max:      tetherDNSCacheEntries,
		now:      time.Now,
		entries:  make(map[string]cachedAddrs),
		inflight: make(map[string]*hostLookup),
	}
}

func (c *cachingLookup) LookupHost(ctx context.Context, host string) ([]string, error) {
	for {
		if addrs, ok := c.get(host); ok {
			return addrs, nil
		}

		c.mu.Lock()
		if call, ok := c.inflight[host]; ok {
			c.mu.Unlock()
			select {
			case <-call.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if call.err == nil {
				return copyAddrs(call.addrs), nil
			}
			// The leader may have failed only because ITS caller went away — a
			// tethered connection dropped while this one is still very much alive.
			// That says nothing about the name, so take the lookup over instead of
			// inheriting a cancellation that was never ours.
			if isContextErr(call.err) && ctx.Err() == nil {
				continue
			}
			return nil, call.err
		}
		call := &hostLookup{done: make(chan struct{})}
		c.inflight[host] = call
		c.mu.Unlock()

		call.addrs, call.err = c.inner.LookupHost(ctx, host)

		// Publishing the answer and leaving inflight happen under one lock, so a
		// caller arriving right now reads the cache rather than starting a second
		// lookup of a name that was just resolved.
		c.mu.Lock()
		if call.err == nil && len(call.addrs) > 0 {
			c.putLocked(host, call.addrs)
		}
		delete(c.inflight, host)
		c.mu.Unlock()
		close(call.done)

		if call.err != nil {
			return nil, call.err
		}
		return copyAddrs(call.addrs), nil
	}
}

// copyAddrs hands out a private copy of an answer. Callers are free to sort or
// truncate what they get, and every waiter on one lookup gets the same slice —
// so nobody may be handed the original.
func copyAddrs(addrs []string) []string {
	out := make([]string, len(addrs))
	copy(out, addrs)
	return out
}

func (c *cachingLookup) get(host string) ([]string, bool) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		delete(c.entries, host)
		return nil, false
	}
	return copyAddrs(e.addrs), true
}

// putLocked stores an answer. The caller holds c.mu: LookupHost publishes here
// and leaves the inflight map in the same critical section.
func (c *cachingLookup) putLocked(host string, addrs []string) {
	now := c.now()
	if len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[host] = cachedAddrs{addrs: copyAddrs(addrs), expires: now.Add(c.ttl)}
}

// evictLocked drops what has expired and, if that freed nothing, the entry
// closest to expiring. Approximate on purpose: the cache is a latency shortcut,
// not a store, and an LRU's bookkeeping would cost more than the miss it saves.
func (c *cachingLookup) evictLocked(now time.Time) {
	oldestKey := ""
	var oldest time.Time
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
			continue
		}
		if oldestKey == "" || e.expires.Before(oldest) {
			oldestKey, oldest = k, e.expires
		}
	}
	if len(c.entries) >= c.max && oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
