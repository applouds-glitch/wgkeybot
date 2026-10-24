/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/kiper292/tls-client"
)

// withOwnNetworkBudget shortens the own-network retry for one test.
func withOwnNetworkBudget(t *testing.T, budget, delay time.Duration) {
	t.Helper()
	prevBudget, prevDelay := vkCallsOwnNetworkBudget, vkCallsOwnNetworkRetryDelay
	vkCallsOwnNetworkBudget, vkCallsOwnNetworkRetryDelay = budget, delay
	t.Cleanup(func() { vkCallsOwnNetworkBudget, vkCallsOwnNetworkRetryDelay = prevBudget, prevDelay })
}

// A request that died in DNS the way dialVKHost reports it, wrapped by the HTTP
// client the way client.Do returns it. reached: whether any resolver was.
func lookupRequestError(r *fhttp.Request, reached bool, cause error) error {
	lookup := dnsResolveError{fmt.Errorf("all DNS servers failed for %s: %w", r.URL.Host, cause), reached}
	return &url.Error{Op: "Post", URL: r.URL.String(), Err: fmt.Errorf("DNS resolution failed for %s: %w", r.URL.Host, lookup)}
}

func deadDNSRequestError(r *fhttp.Request) error {
	return lookupRequestError(r, false, errors.New("i/o timeout"))
}

// Silence from every server is the phone's network; one server that answered —
// even only to say SERVFAIL — makes the failure the name's. A refused connection
// is no answer: a firewall on the way can send that just as well.
func TestResolveTellsSilenceFromAnswer(t *testing.T) {
	cases := []struct {
		name    string
		answer  func(DNSServer) ([]string, error)
		reached bool
	}{
		{"every query timed out", func(DNSServer) ([]string, error) { return nil, errors.New("i/o timeout") }, false},
		{"protect refused every socket", func(DNSServer) ([]string, error) {
			return nil, fmt.Errorf("failed to dial UDP: %w", errSocketNotProtected)
		}, false},
		{"one server said SERVFAIL", func(s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return nil, dnsReachedf("DNS error: rcode=2")
			}
			return nil, errors.New("i/o timeout")
		}, true},
		{"one server answered with nothing", func(s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return nil, nil
			}
			return nil, errors.New("i/o timeout")
		}, true},
		{"one server refused the connection", func(s DNSServer) ([]string, error) {
			if s.IP == "8.8.8.8" {
				return nil, fmt.Errorf("failed to connect to DoT server: %w", syscall.ECONNREFUSED)
			}
			return nil, errors.New("i/o timeout")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
				func(_ context.Context, _ string, s DNSServer) ([]string, error) { return tc.answer(s) })
			_, err := resolveWithOrderedServers(context.Background(), "internal.api.vk.ru")
			reached, isLookup := dnsLookupOutcome(err)
			if !isLookup {
				t.Fatalf("not a lookup failure: %v", err)
			}
			if reached != tc.reached {
				t.Fatalf("reached = %v, want %v (%v)", reached, tc.reached, err)
			}
			if !strings.Contains(err.Error(), "all DNS servers failed for internal.api.vk.ru") {
				t.Fatalf("message changed: %v", err)
			}
		})
	}
}

// Every way parseDNSResponse refuses a reply is a server reached.
func TestParseDNSResponseFailuresReachedAServer(t *testing.T) {
	nxdomain := make([]byte, 12)
	nxdomain[2], nxdomain[3] = 0x81, 0x83 // response, recursion desired/available, rcode 3
	empty := make([]byte, 12)
	empty[2], empty[3] = 0x81, 0x80 // response, rcode 0, no answers
	for name, reply := range map[string][]byte{
		"too short":    {0x00, 0x01},
		"not response": make([]byte, 12),
		"NXDOMAIN":     nxdomain,
		"no answers":   empty,
	} {
		if _, err := parseDNSResponse(reply, "vk.ru"); err == nil || !serverReached(err) {
			t.Errorf("%s: %v is not marked as a server reached", name, err)
		}
	}
}

// A DoT or DoH connection that was accepted and then hung up before the TLS
// handshake proved anything is no answer: a captive portal or a middlebox takes
// connections to 443 and 853 just as readily. Played against a local listener
// that accepts and closes.
func TestEncryptedDNSAcceptedConnectionIsNoAnswer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	prevDoH, prevDoT := dohPort, dotPort
	dohPort, dotPort = port, port
	t.Cleanup(func() { dohPort, dotPort = prevDoH, prevDoT })

	if _, err := resolveDoTWithServer(context.Background(), "vk.ru", "127.0.0.1", "dns.example"); err == nil || serverReached(err) {
		t.Errorf("DoT: %v read as an answer", err)
	}
	if _, err := resolveDoHWithServer(context.Background(), "vk.ru", "127.0.0.1", "dns.example"); err == nil || serverReached(err) {
		t.Errorf("DoH: %v read as an answer", err)
	}
}

// A cancelled lookup must come out as the cancellation, never as a network that
// answered nothing: the live follower of a shared lookup takes it over only on a
// context error. Here the select nearly always wakes on the cancellation; the
// guard after the loop covers the rarer order — the last result winning the
// select after the context was cancelled — which a host test cannot force, so
// this only keeps the common order honest.
func TestResolveCancellationIsNeverSilence(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		withFakeDNS(t, fakeServers("192.168.1.1"),
			func(context.Context, string, DNSServer) ([]string, error) {
				cancel()
				return nil, errors.New("use of closed network connection")
			})
		_, err := resolveWithOrderedServers(ctx, "internal.api.vk.ru")
		if _, isLookup := dnsLookupOutcome(err); isLookup || !errors.Is(err, context.Canceled) {
			t.Fatalf("round %d: cancelled lookup came out as %v", i, err)
		}
	}
}

// The field case: DNS dead for longer than three attempts take. The attempts
// that never reached VK are not counted, so the flow is still going when the
// network comes back — and gets the credential without a captcha.
func TestVKCallsOwnNetworkAttemptsAreNotCounted(t *testing.T) {
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	const deadFor = 5 // > vkCallsAttempts
	calls := 0
	live := scriptedVKAnswer(t, "", nil)
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		if calls <= deadFor {
			return nil, deadDNSRequestError(r)
		}
		return live.Do(r)
	}}
	user, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if err != nil || user != "u" {
		t.Fatalf("flow gave up on its own network: user=%q err=%v", user, err)
	}
}

// protect() refusing the socket is our side too, and costs no attempt.
func TestVKCallsProtectRefusalIsOwnNetwork(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, time.Millisecond)
	calls := 0
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: fmt.Errorf("dial udp: %w", errSocketNotProtected)}
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("protect refusal not read as our network: %v", err)
	}
	if calls <= vkCallsAttempts {
		t.Fatalf("only %d attempts in the budget — own-network failures were counted", calls)
	}
}

// A lookup some resolver answered is the name's, whatever errno another
// server's socket carried: the first error can be an unreachable IPv6 resolver
// while the second one said SERVFAIL.
func TestVKCallsAnsweredLookupIsNotOwnNetwork(t *testing.T) {
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	calls := 0
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		return nil, lookupRequestError(r, true, fmt.Errorf("failed to dial UDP: %w", syscall.ENETUNREACH))
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if calls != vkCallsAttempts || isVKCallsOwnNetwork(err) {
		t.Fatalf("answered lookup read as our network: calls=%d err=%v", calls, err)
	}
}

// Anything VK answered is VK's, even when the network changed while it did: a
// 5xx is a response, not a request lost on the way.
func TestVKCallsAnswerDuringNetworkChangeIsCounted(t *testing.T) {
	resetNetworkSwitch(t)
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	calls := 0
	client := scriptedHTTPClient{do: func(*fhttp.Request) (*fhttp.Response, error) {
		calls++
		networkSwitch.Lock()
		networkSwitch.leftAt = time.Now()
		networkSwitch.Unlock()
		return &fhttp.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("bad gateway"))}, nil
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if calls != vkCallsAttempts || isVKCallsOwnNetwork(err) || !isTransientVKCalls(err) {
		t.Fatalf("VK's 502 during a network change: calls=%d err=%v", calls, err)
	}
}

// ...while a request that got no response when the network was left under it is
// ours.
func TestVKCallsNoResponseDuringNetworkChangeIsOwnNetwork(t *testing.T) {
	resetNetworkSwitch(t)
	withOwnNetworkBudget(t, 50*time.Millisecond, time.Millisecond)
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		networkSwitch.Lock()
		networkSwitch.leftAt = time.Now()
		networkSwitch.Unlock()
		return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: errors.New("read: connection timed out")}
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("no response on a network left mid-attempt not read as ours: %v", err)
	}
}

// Past the budget the flow gives up with an error that is both ours (so
// fetchVkCreds weighs the legacy chain) and transient (so the link check still
// says "try later").
func TestVKCallsOwnNetworkBudgetBoundsTheWait(t *testing.T) {
	withOwnNetworkBudget(t, 40*time.Millisecond, 5*time.Millisecond)
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) { return nil, deadDNSRequestError(r) }}
	started := time.Now()
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("budget of 40ms took %v", elapsed)
	}
	if !isVKCallsOwnNetwork(err) || !isTransientVKCalls(err) {
		t.Fatalf("want own-network and transient, got %v", err)
	}
	if got := checkVKLink(context.Background(), "hash", client, Profile{}); got != linkCheckTemporary {
		t.Fatalf("link check verdict = %d, want %d", got, linkCheckTemporary)
	}
}

// VK's own "come back later" still gets exactly vkCallsAttempts, whatever our
// network did in between, and the flow ending on it keeps the legacy fallback.
func TestVKCallsOwnNetworkDoesNotStretchVKRetries(t *testing.T) {
	withOwnNetworkBudget(t, time.Minute, time.Millisecond)
	calls, busy := 0, 0
	client := scriptedHTTPClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		calls++
		if calls%2 == 1 {
			return nil, deadDNSRequestError(r)
		}
		busy++
		return jsonHTTP(`{"error":{"error_code":6,"error_msg":"Too many requests"}}`), nil
	}}
	_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
	if busy != vkCallsAttempts {
		t.Fatalf("VK asked to come back later %d times, want %d", busy, vkCallsAttempts)
	}
	if isVKCallsOwnNetwork(err) || !isTransientVKCalls(err) {
		t.Fatalf("a flow VK ended must keep the legacy fallback: %v", err)
	}
}

// fakeVKDNS answers login.vk.ru with legacyIP (none: silence) and keeps every
// other name silent, counting the servers asked per name.
func fakeVKDNS(t *testing.T, legacyIP string) (asked func(string) int) {
	t.Helper()
	var mu sync.Mutex
	count := map[string]int{}
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(_ context.Context, domain string, _ DNSServer) ([]string, error) {
			mu.Lock()
			count[domain]++
			mu.Unlock()
			if domain == vkLegacyFirstHost && legacyIP != "" {
				return []string{legacyIP}, nil
			}
			return nil, errors.New("i/o timeout")
		})
	for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
		hostCache.Forget(host)
	}
	t.Cleanup(func() {
		for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
			hostCache.Forget(host)
		}
	})
	return func(domain string) int {
		mu.Lock()
		defer mu.Unlock()
		return count[domain]
	}
}

// stubLegacyChain stands in for the legacy chain and counts the calls.
func stubLegacyChain(t *testing.T) (calls func() int) {
	t.Helper()
	var n atomic.Int32
	prev := vkLegacyChain
	vkLegacyChain = func(context.Context, string, tlsclient.HttpClient, Profile) (string, string, []string, int, error) {
		n.Add(1)
		return "", "", nil, 0, errors.New("legacy stub")
	}
	t.Cleanup(func() { vkLegacyChain = prev })
	return func() int { return int(n.Load()) }
}

// End to end through the real client: with every resolver silent, the error
// survives the HTTP stack as ours, the legacy host is asked once — one walk of
// the two servers — and the legacy chain never starts.
func TestFetchVkCredsSkipsLegacyWhenOurNetworkIsDead(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	asked := fakeVKDNS(t, "")
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(context.Background(), "link")
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("want an own-network error, got %v", err)
	}
	if asked(vkCallsAPIHost) == 0 {
		t.Fatalf("the captcha-free flow never resolved %s", vkCallsAPIHost)
	}
	if n := asked(vkLegacyFirstHost); n != 2 {
		t.Fatalf("%s asked %d times, want one walk of 2 servers", vkLegacyFirstHost, n)
	}
	if n := legacy(); n != 0 {
		t.Fatalf("legacy chain entered %d times on a dead network", n)
	}
}

// Silence about the VK Calls host alone — a resolver dropping that one name
// while it answers for login.vk.ru — leaves the legacy chain its chance, as
// before own-network failures were told apart.
func TestFetchVkCredsKeepsLegacyWhenItsHostResolves(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	fakeVKDNS(t, "127.0.0.1")
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(context.Background(), "link")
	if n := legacy(); n != 1 {
		t.Fatalf("legacy chain entered %d times although %s resolves (%v)", n, vkLegacyFirstHost, err)
	}
}

// Audit 2026-10-16: login.vk.ru cached from earlier on this network passed for
// a resolver that answers now, and the legacy chain went out — captcha and all
// — over resolvers that had all gone silent. The legacy host is asked afresh,
// and the silence leaves the cached answer where it was.
func TestFetchVkCredsAsksForTheLegacyHostAfresh(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	asked := fakeVKDNS(t, "")
	hostCache.mu.Lock()
	hostCache.ips[vkLegacyFirstHost] = []string{"127.0.0.1"}
	hostCache.mu.Unlock()
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(context.Background(), "link")
	if !isVKCallsOwnNetwork(err) {
		t.Fatalf("want an own-network error, got %v", err)
	}
	if n := asked(vkLegacyFirstHost); n != 2 {
		t.Fatalf("%s asked %d times, want one walk of 2 servers past the cached answer", vkLegacyFirstHost, n)
	}
	if n := legacy(); n != 0 {
		t.Fatalf("legacy chain entered %d times on resolvers that answer nobody", n)
	}
	hostCache.mu.Lock()
	cached := hostCache.ips[vkLegacyFirstHost]
	hostCache.mu.Unlock()
	if len(cached) != 1 || cached[0] != "127.0.0.1" {
		t.Errorf("the failed lookup left %v cached, want the earlier answer kept", cached)
	}
}

// Field log 23.10: a stop during the captcha-free flow read as that flow
// failing, "falling back to legacy captcha path", and the legacy chain was
// entered only to fail on the cancellation. login.vk.ru resolves here, so only
// the stop stands between the fetch and the legacy chain.
func TestFetchVkCredsStoppedMidFlowSkipsLegacy(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withFakeDNS(t, fakeServers("192.168.1.1"),
		func(_ context.Context, domain string, _ DNSServer) ([]string, error) {
			if domain == vkLegacyFirstHost {
				return []string{"127.0.0.1"}, nil
			}
			cancel() // the stop lands while the flow resolves its first host
			return nil, errors.New("i/o timeout")
		})
	for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
		hostCache.Forget(host)
	}
	t.Cleanup(func() {
		for _, host := range []string{vkCallsAPIHost, vkLegacyFirstHost} {
			hostCache.Forget(host)
		}
	})
	legacy := stubLegacyChain(t)

	_, _, _, _, err := fetchVkCreds(ctx, "link")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the cancellation back, got %v", err)
	}
	if n := legacy(); n != 0 {
		t.Fatalf("legacy chain entered %d times after the stop", n)
	}
}
