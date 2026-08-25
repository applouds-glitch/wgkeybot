/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type countingLookup struct {
	addrs []string
	err   error
	calls int
}

func (c *countingLookup) LookupHost(_ context.Context, _ string) ([]string, error) {
	c.calls++
	return c.addrs, c.err
}

// Every connection a tethered client opens arrives as a name, and each miss is a
// full DNS round trip down the TURN path. The second one must not be.
func TestLookupCacheAnswersTheSecondCallItself(t *testing.T) {
	inner := &countingLookup{addrs: []string{"93.184.216.34"}}
	cache := newCachingLookup(inner)

	for i := 0; i < 3; i++ {
		got, err := cache.LookupHost(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"93.184.216.34"}) {
			t.Fatalf("lookup = %v", got)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("resolver was asked %d times, want 1", inner.calls)
	}
}

// The answer handed out is a copy: the dial path filters and truncates it, and
// doing that in place would corrupt the entry for everyone after.
func TestLookupCacheHandsOutACopy(t *testing.T) {
	inner := &countingLookup{addrs: []string{"93.184.216.34", "93.184.216.35"}}
	cache := newCachingLookup(inner)

	first, _ := cache.LookupHost(context.Background(), "example.com")
	first[0] = "0.0.0.0"

	second, _ := cache.LookupHost(context.Background(), "example.com")
	if second[0] != "93.184.216.34" {
		t.Fatalf("cached entry was mutated through the caller's slice: %v", second)
	}
}

func TestLookupCacheExpires(t *testing.T) {
	inner := &countingLookup{addrs: []string{"93.184.216.34"}}
	cache := newCachingLookup(inner)
	now := time.Now()
	cache.now = func() time.Time { return now }

	if _, err := cache.LookupHost(context.Background(), "example.com"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	now = now.Add(tetherDNSCacheTTL + time.Second)
	if _, err := cache.LookupHost(context.Background(), "example.com"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("resolver was asked %d times, want 2 (the entry should have expired)", inner.calls)
	}
}

// A failure is usually the tunnel still settling. Remembering it would turn half
// a second of bad luck into a minute of a site being "down".
func TestLookupCacheDoesNotRememberFailures(t *testing.T) {
	inner := &countingLookup{err: errors.New("SERVFAIL")}
	cache := newCachingLookup(inner)

	for i := 0; i < 3; i++ {
		if _, err := cache.LookupHost(context.Background(), "example.com"); err == nil {
			t.Fatal("lookup unexpectedly succeeded")
		}
	}
	if inner.calls != 3 {
		t.Fatalf("resolver was asked %d times, want 3", inner.calls)
	}
}

// The cache is a latency shortcut, not a store: it must stay bounded no matter
// how many hosts a client visits.
func TestLookupCacheStaysBounded(t *testing.T) {
	inner := &countingLookup{addrs: []string{"93.184.216.34"}}
	cache := newCachingLookup(inner)
	cache.max = 8

	for i := 0; i < 64; i++ {
		if _, err := cache.LookupHost(context.Background(), "host"+string(rune('a'+i%26))+string(rune('a'+i/26))); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size > cache.max {
		t.Fatalf("cache holds %d entries, want at most %d", size, cache.max)
	}
}

// blockingLookup holds every caller that reaches the resolver until release is
// closed, so a test can count how many of them actually got there.
type blockingLookup struct {
	release chan struct{}
	addrs   []string

	mu    sync.Mutex
	calls int
}

func (b *blockingLookup) LookupHost(ctx context.Context, _ string) ([]string, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return append([]string(nil), b.addrs...), nil
}

func (b *blockingLookup) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// Opening one page fires a dozen connections to the same host at once. The cache
// alone does not help there: every one of them misses, and every one pays its
// own round trip down the whole TURN path before the first answer is stored.
func TestLookupCacheCollapsesConcurrentLookups(t *testing.T) {
	inner := &blockingLookup{release: make(chan struct{}), addrs: []string{"93.184.216.34"}}
	cache := newCachingLookup(inner)

	const callers = 8
	var started, done sync.WaitGroup
	started.Add(callers)
	done.Add(callers)
	got := make([][]string, callers)
	errs := make([]error, callers)
	for i := 0; i < callers; i++ {
		go func(i int) {
			defer done.Done()
			started.Done()
			got[i], errs[i] = cache.LookupHost(context.Background(), "example.com")
		}(i)
	}

	// Every caller is running; the short pause covers the step from there to the
	// inflight check. Then the one lookup in flight is allowed to answer.
	started.Wait()
	time.Sleep(50 * time.Millisecond)
	close(inner.release)
	done.Wait()

	if n := inner.count(); n != 1 {
		t.Fatalf("%d lookups reached the resolver, want 1", n)
	}
	for i := range got {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if !reflect.DeepEqual(got[i], []string{"93.184.216.34"}) {
			t.Fatalf("caller %d got %v, want the leader's answer", i, got[i])
		}
	}
}
