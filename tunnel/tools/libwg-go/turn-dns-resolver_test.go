/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withFakeDNS swaps the active server list and the resolver seam for one test,
// restoring both — and the last-successful bias, which the race writes — after.
func withFakeDNS(t *testing.T, servers []DNSServer, fn func(context.Context, string, DNSServer) (string, error)) {
	t.Helper()

	prevServers, prevFn := dnsServers, resolveAnyFn
	lastSuccessfulMu.Lock()
	prevIdx := lastSuccessfulIndex
	lastSuccessfulIndex = 0
	lastSuccessfulMu.Unlock()

	dnsServers, resolveAnyFn = servers, fn

	t.Cleanup(func() {
		dnsServers, resolveAnyFn = prevServers, prevFn
		lastSuccessfulMu.Lock()
		lastSuccessfulIndex = prevIdx
		lastSuccessfulMu.Unlock()
	})
}

func fakeServers(ips ...string) []DNSServer {
	servers := make([]DNSServer, 0, len(ips))
	for _, ip := range ips {
		servers = append(servers, DNSServer{Type: DNSPlain, IP: ip})
	}
	return servers
}

// The healthy case must look exactly as it did before hedging: one query to one
// server. Racing a resolver that answers in milliseconds would multiply DNS
// traffic for nothing.
func TestResolveWithOrderedServersLeavesHealthyServerAlone(t *testing.T) {
	var mu sync.Mutex
	var queried []string

	withFakeDNS(t, fakeServers("192.168.1.1", "77.88.8.8", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) (string, error) {
			mu.Lock()
			queried = append(queried, s.IP)
			mu.Unlock()
			return "93.186.237.1", nil
		})

	ip, err := resolveWithOrderedServers(context.Background(), "login.vk.ru")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if ip != "93.186.237.1" {
		t.Fatalf("got %q, want 93.186.237.1", ip)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(queried) != 1 {
		t.Fatalf("healthy first server was raced: queried %v", queried)
	}
}

// A server that has stopped answering used to cost its full timeout before the
// next one was even tried. Now the next one joins after the hedge — but not
// before it, or the head start the last-successful bias buys would be gone.
func TestResolveWithOrderedServersHedgesPastHungServer(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) (string, error) {
			if s.IP == "192.168.1.1" {
				<-ctx.Done()
				return "", ctx.Err()
			}
			return "93.186.237.1", nil
		})

	start := time.Now()
	ip, err := resolveWithOrderedServers(context.Background(), "login.vk.ru")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if ip != "93.186.237.1" {
		t.Fatalf("got %q, want the second server's answer", ip)
	}
	if elapsed+time.Millisecond < dnsHedgeDelay {
		t.Fatalf("second server started after %v, before the %v hedge", elapsed, dnsHedgeDelay)
	}
	if elapsed > 2*dnsHedgeDelay {
		t.Fatalf("hung server held the lookup up for %v", elapsed)
	}
}

// A server that has already said no is not worth waiting the stagger out for,
// so a list of fast failures is walked at the speed of the failures.
func TestResolveWithOrderedServersBringsNextForwardOnFailure(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1", "77.88.8.8", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) (string, error) {
			if s.IP == "8.8.8.8" {
				return "93.186.237.1", nil
			}
			return "", errors.New("i/o timeout")
		})

	start := time.Now()
	ip, err := resolveWithOrderedServers(context.Background(), "login.vk.ru")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if ip != "93.186.237.1" {
		t.Fatalf("got %q, want the third server's answer", ip)
	}
	if elapsed >= dnsHedgeDelay {
		t.Fatalf("two instant failures took %v — the next server waited out the hedge", elapsed)
	}
}

// Every server failing is still an error, and it carries a cause now.
func TestResolveWithOrderedServersReportsTotalFailure(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(ctx context.Context, domain string, s DNSServer) (string, error) {
			return "", errors.New("i/o timeout")
		})

	if _, err := resolveWithOrderedServers(context.Background(), "login.vk.ru"); err == nil {
		t.Fatal("expected an error when every server failed")
	}
}

// Two credential fetches asking for the same VK host at the same time — the
// shape vkSemaphore allows — must cost one walk of the server list, not two.
func TestResolveCollapsesConcurrentLookups(t *testing.T) {
	var lookups atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	withFakeDNS(t, fakeServers("192.168.1.1"),
		func(ctx context.Context, domain string, s DNSServer) (string, error) {
			lookups.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			return "93.186.237.1", nil
		})

	cache := &DnsCache{
		ips:      make(map[string]string),
		inflight: make(map[string]*dnsLookup),
	}

	const callers = 5
	results := make([]string, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = cache.Resolve(context.Background(), "login.vk.ru")
		}(i)
	}

	// Let the leader get in, then give the followers time to queue behind it.
	<-started
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := lookups.Load(); got != 1 {
		t.Fatalf("%d callers produced %d lookups, want 1", callers, got)
	}
	for i := 0; i < callers; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d failed: %v", i, errs[i])
		}
		if results[i] != "93.186.237.1" {
			t.Fatalf("caller %d got %q", i, results[i])
		}
	}
	if cached, ok := cache.ips["login.vk.ru"]; !ok || cached != "93.186.237.1" {
		t.Fatalf("answer not cached: %q (present=%v)", cached, ok)
	}
	if len(cache.inflight) != 0 {
		t.Fatalf("inflight not cleaned up: %v", cache.inflight)
	}
}

// A failed lookup must not be cached as an answer, and must not leave the name
// wedged in the inflight map either.
func TestResolveDoesNotCacheFailures(t *testing.T) {
	withFakeDNS(t, fakeServers("192.168.1.1"),
		func(ctx context.Context, domain string, s DNSServer) (string, error) {
			return "", errors.New("i/o timeout")
		})

	cache := &DnsCache{
		ips:      make(map[string]string),
		inflight: make(map[string]*dnsLookup),
	}
	if _, err := cache.Resolve(context.Background(), "login.vk.ru"); err == nil {
		t.Fatal("expected an error")
	}
	if len(cache.ips) != 0 {
		t.Fatalf("failure was cached: %v", cache.ips)
	}
	if len(cache.inflight) != 0 {
		t.Fatalf("inflight not cleaned up: %v", cache.inflight)
	}
}
