/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	tlsclient "github.com/kiper292/tls-client"
)

// withVKHostMemory gives the test an empty memory and a state dir of its own.
func withVKHostMemory(t *testing.T) string {
	t.Helper()
	prevDir := stateDirPath()
	reset := func() {
		vkHostMemory.Lock()
		vkHostMemory.loadedFrom = ""
		vkHostMemory.written = time.Time{}
		vkHostMemory.hosts = map[string]vkRememberedAddrs{}
		vkHostMemory.Unlock()
	}
	reset()
	dir := t.TempDir()
	setStateDir(dir)
	t.Cleanup(func() {
		setStateDir(prevDir)
		reset()
	})
	return dir
}

// silentDNS makes every lookup fail without a resolver being reached, as on the
// Wi-Fi of the field log; reached makes them fail with a resolver's answer.
func silentDNS(t *testing.T, reached bool) {
	t.Helper()
	withFakeDNS(t, fakeServers("192.168.1.1", "8.8.8.8"),
		func(context.Context, string, DNSServer) ([]string, error) {
			if reached {
				return nil, dnsReachedf("DNS error: rcode=2")
			}
			return nil, errors.New("i/o timeout")
		})
}

// talk has the fake far end say its one word, so the connection counts as heard.
func talk(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func emptyCache() *DnsCache {
	return &DnsCache{ips: map[string][]string{}, inflight: map[string]*dnsLookup{}}
}

func TestVKCallsOKHostNameIsTheURLsHost(t *testing.T) {
	u, err := url.Parse(vkCallsOKHost)
	if err != nil || u.Hostname() != vkCallsOKHostName {
		t.Fatalf("vkCallsOKHost %q has host %q, vkCallsOKHostName is %q", vkCallsOKHost, u.Hostname(), vkCallsOKHostName)
	}
}

// Field log 23.10: no resolver answered while VK itself was reachable. The flow's
// host is dialled on the addresses it last connected on, and the one that
// connects heads them from then on. The cache is left alone: an address there
// reads as DNS's, and its silence as VK's.
func TestVKDialUsesRememberedAddressesWhenNoResolverAnswers(t *testing.T) {
	withVKHostMemory(t)
	silentDNS(t, false)
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1", "10.0.0.2"}, time.Now().Add(-time.Hour))
	d := &fakeDialer{refuse: map[string]error{"10.0.0.1": errors.New("connection refused")}}
	cache := emptyCache()
	var conns atomic.Uint64

	conn, err := dialVKHostCounting(context.Background(), cache, "tcp", vkCallsAPIHost+":443", d.dial, &conns)
	if err != nil {
		t.Fatalf("dial failed although a remembered address answers: %v", err)
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("connections from memory counted %d, want 1 (silentOverRemembered reads it)", got)
	}
	talk(t, conn) // heard, so not set aside on close
	conn.Close()
	want := []string{"10.0.0.2", "10.0.0.1"}
	if got := cache.snapshot(vkCallsAPIHost); len(got) != 0 {
		t.Errorf("addresses from memory went into the cache: %v", got)
	}
	if got := rememberedVKAddrs(vkCallsAPIHost, time.Now()); !slices.Equal(got, want) {
		t.Errorf("remembered %v, want %v", got, want)
	}
}

// On a network that carries nothing the remembered addresses fail as well, and
// the caller must still see the lookup's failure — our own network — or the
// early -5 and the guard on the legacy chain would read it as VK's.
func TestVKDialKeepsTheLookupFailureWhenNoRememberedAddressConnects(t *testing.T) {
	withVKHostMemory(t)
	silentDNS(t, false)
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, time.Now())
	d := &fakeDialer{refuse: map[string]error{"10.0.0.1": errors.New("connection refused")}}

	_, err := dialVKHost(context.Background(), emptyCache(), "tcp", vkCallsAPIHost+":443", d.dial)
	reached, isLookup := dnsLookupOutcome(err)
	if !isLookup || reached {
		t.Fatalf("error %v reads as lookup=%v reached=%v, want an unreached lookup", err, isLookup, reached)
	}
	if got := d.dialledAddrs(); !slices.Equal(got, []string{"10.0.0.1"}) {
		t.Errorf("dialled %v, want the remembered address", got)
	}
}

// The walk is bounded: a silent remembered address costs vkRememberedDialTimeout,
// not a VK connect's 20s.
func TestVKDialBoundsTheWalkOverRememberedAddresses(t *testing.T) {
	withVKHostMemory(t)
	silentDNS(t, false)
	prev := vkRememberedDialTimeout
	vkRememberedDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() { vkRememberedDialTimeout = prev })
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, time.Now())
	d := &fakeDialer{silent: map[string]bool{"10.0.0.1": true}}

	started := time.Now()
	_, err := dialVKHost(context.Background(), emptyCache(), "tcp", vkCallsAPIHost+":443", d.dial)
	if err == nil {
		t.Fatal("a silent remembered address connected")
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("the walk took %v", took)
	}
	if _, isLookup := dnsLookupOutcome(err); !isLookup {
		t.Fatalf("a timed-out walk lost the lookup's failure: %v", err)
	}
}

// A resolver that answered, even with an error, is the name's verdict: nothing
// remembered is dialled over it.
func TestVKDialTakesAResolversAnswer(t *testing.T) {
	withVKHostMemory(t)
	silentDNS(t, true)
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, time.Now())
	d := &fakeDialer{}

	if _, err := dialVKHost(context.Background(), emptyCache(), "tcp", vkCallsAPIHost+":443", d.dial); err == nil {
		t.Fatal("dialled past a resolver's answer")
	}
	if got := d.dialledAddrs(); len(got) != 0 {
		t.Fatalf("dialled %v past a resolver's answer", got)
	}
}

// Only the captcha-free flow's hosts are remembered: the legacy chain's must not
// go out over a DNS that answers nobody.
func TestVKDialRemembersOnlyTheCaptchaFreeHosts(t *testing.T) {
	withVKHostMemory(t)
	d := &fakeDialer{}
	for _, host := range []string{vkLegacyFirstHost, "api.vk.ru", vkCallsAPIHost} {
		conn, err := dialVKHost(context.Background(), cacheWith(host, "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"), "tcp", host+":443", d.dial)
		if err != nil {
			t.Fatal(err)
		}
		talk(t, conn)
		conn.Close()
	}
	vkHostMemory.Lock()
	for _, host := range []string{vkLegacyFirstHost, "api.vk.ru"} {
		if got, ok := vkHostMemory.hosts[host]; ok {
			t.Errorf("%s remembered: %v", host, got.IPs)
		}
	}
	vkHostMemory.Unlock()
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	if got := rememberedVKAddrs(vkCallsAPIHost, time.Now()); !slices.Equal(got, want) {
		t.Errorf("%s remembered %v, want %v (capped at %d)", vkCallsAPIHost, got, want, vkRememberedAddrsMax)
	}
}

// The addresses outlive the process — the file is what the next one reads — and
// stop being dialled once they have not connected for vkRememberedMaxAge.
func TestVKHostMemorySurvivesTheProcessAndAges(t *testing.T) {
	dir := withVKHostMemory(t)
	now := time.Now()
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, now)
	rememberVKAddrs(vkCallsOKHostName, []string{"10.0.0.9"}, now.Add(-vkRememberedMaxAge-time.Hour))
	if _, err := os.Stat(filepath.Join(dir, vkHostMemoryFileName)); err != nil {
		t.Fatalf("no file written: %v", err)
	}

	vkHostMemory.Lock() // a new process: nothing in memory
	vkHostMemory.loadedFrom = ""
	vkHostMemory.written = time.Time{}
	vkHostMemory.hosts = map[string]vkRememberedAddrs{}
	vkHostMemory.Unlock()

	if got := rememberedVKAddrs(vkCallsAPIHost, now); !slices.Equal(got, []string{"10.0.0.1"}) {
		t.Errorf("after a restart %v, want the address from the file", got)
	}
	if got := rememberedVKAddrs(vkCallsOKHostName, now); got != nil {
		t.Errorf("an address unconnected for over %v is still dialled: %v", vkRememberedMaxAge, got)
	}
}

// An unchanged list is not written on every connect, only to move its date —
// counted from the last write, so connects an hour apart do not put it off for
// ever.
func TestVKHostMemoryRewritesAnUnchangedListOnlyToMoveItsDate(t *testing.T) {
	dir := withVKHostMemory(t)
	path := filepath.Join(dir, vkHostMemoryFileName)
	now := time.Now()
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, now)
	os.Remove(path)
	for h := 1; h < 24; h++ {
		rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, now.Add(time.Duration(h)*time.Hour))
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("an unchanged list was written again within a day")
	}
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1"}, now.Add(vkRememberedRewriteAfter+time.Minute))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("an unchanged list was not rewritten after %v of hourly connects: %v", vkRememberedRewriteAfter, err)
	}
}

// A remembered address that takes the connection and never answers goes to the
// tail of the memory, so the next walk starts elsewhere — in the next process
// too, though the next connect brings no new order to write.
func TestVKDialSetsASilentRememberedAddressAside(t *testing.T) {
	withVKHostMemory(t)
	silentDNS(t, false)
	rememberVKAddrs(vkCallsAPIHost, []string{"10.0.0.1", "10.0.0.2"}, time.Now())
	d := &fakeDialer{}

	conn, err := dialVKHost(context.Background(), emptyCache(), "tcp", vkCallsAPIHost+":443", d.dial)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close() // never heard
	want := []string{"10.0.0.2", "10.0.0.1"}
	if got := rememberedVKAddrs(vkCallsAPIHost, time.Now()); !slices.Equal(got, want) {
		t.Fatalf("remembered %v after a silent connect, want %v", got, want)
	}
	rememberVKAddrs(vkCallsAPIHost, want, time.Now()) // the next connect, on 10.0.0.2

	vkHostMemory.Lock() // a new process: nothing in memory
	vkHostMemory.loadedFrom = ""
	vkHostMemory.written = time.Time{}
	vkHostMemory.hosts = map[string]vkRememberedAddrs{}
	vkHostMemory.Unlock()
	if got := rememberedVKAddrs(vkCallsAPIHost, time.Now()); !slices.Equal(got, want) {
		t.Fatalf("after a restart %v, want %v: the silent address leads again", got, want)
	}
}

// Codex review 23.10: DNS answers nobody, a remembered address takes the TCP
// connection and the TLS handshake then hears nothing. That silence must stay
// ours, as the lookup's failure was: retried within the own-network budget and
// ending in errVKCallsOwnNetwork (the early -5, the guard on the legacy chain) —
// not three counted attempts and the legacy chain. What counts is this client's
// connections: another client's must not cut this flow's attempts short.
func TestVKCallsSilenceOverARememberedAddressIsOurNetwork(t *testing.T) {
	withOwnNetworkBudget(t, 50*time.Millisecond, 5*time.Millisecond)
	prev := vkCallsAttemptFn
	t.Cleanup(func() { vkCallsAttemptFn = prev })
	silent := transientVKCallsf("%s: %w: %w", "auth.getAnonymToken", errVKCallsNoResponse, errors.New("TLS handshake timeout"))
	answered := transientVKCallsf("auth.getAnonymToken: VK API error_code=6: Too many requests")

	cases := []struct {
		name       string
		err        error
		overMemory bool
		pooled     bool // only the first attempt dialled from memory; the rest reuse it
		other      bool // another client dialled from memory meanwhile, not this one
		ours       bool
	}{
		{"silence over a remembered address", silent, true, false, false, true},
		{"silence over a DNS answer", silent, false, false, false, false},
		{"VK's answer over a remembered address", answered, true, false, false, false},
		{"silence over a pooled connection from memory", silent, false, true, false, true},
		{"silence while another client dialled from memory", silent, false, false, true, false},
	}
	for _, c := range cases {
		calls := 0
		mine, theirs := new(atomic.Uint64), new(atomic.Uint64)
		client := vkAPIClient{remembered: mine}
		vkCallsAttemptFn = func(context.Context, string, tlsclient.HttpClient, Profile) (string, string, []string, int, error) {
			calls++
			if c.overMemory || (c.pooled && calls == 1) {
				mine.Add(1)
			}
			if c.other {
				theirs.Add(1) // the link check, or the fetch of another group
			}
			return "", "", nil, 0, c.err
		}
		_, _, _, _, err := getVKCredsViaVKCalls(context.Background(), "link", client, Profile{})
		if got := isVKCallsOwnNetwork(err); got != c.ours {
			t.Errorf("%s: own network = %v (%v), want %v", c.name, got, err, c.ours)
		}
		if !c.ours && calls != vkCallsAttempts {
			t.Errorf("%s: %d attempts, want %d counted", c.name, calls, vkCallsAttempts)
		}
	}
}

// The count a flow reads is the one its client's dial adds to.
func TestVKAPIClientReadsItsOwnDialsCount(t *testing.T) {
	var dials *atomic.Uint64
	client, _, _, err := newVKAPIClientDialing(func(remembered *atomic.Uint64) func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials = remembered
		return vkDialCounting(remembered)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	read := rememberedDialsOf(client)
	dials.Add(2)
	if got := read(); got != 2 {
		t.Fatalf("the client reads %d of its dial's 2", got)
	}
}
