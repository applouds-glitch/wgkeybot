/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// Kotlin hands the addresses down exactly as the config spells them, prefix and
// all, and a prefix is not something netip.ParseAddr accepts.
func TestParseTunnelAddrsDropsThePrefix(t *testing.T) {
	got := parseTunnelAddrs(" 10.10.11.126/32 , fd00::2/128 ,, nonsense ")
	want := []netip.Addr{netip.MustParseAddr("10.10.11.126"), netip.MustParseAddr("fd00::2")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTunnelAddrs = %v, want %v", got, want)
	}
}

// Sharing without a way to verify egress would be sharing on trust, and the
// sheet promises more than that.
func TestNewTetherEgressGuardNeedsTunnelAddresses(t *testing.T) {
	if _, err := newTetherEgressGuard("192.168.49.1", "  , "); err == nil {
		t.Fatal("guard was created without any tunnel address")
	}
}

func TestGuardRefusesDestinationsAClientHasNoBusinessReaching(t *testing.T) {
	guard, err := newTetherEgressGuard("192.168.49.1", "10.10.11.126/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	for _, tc := range []struct {
		ip    string
		allow bool
		why   string
	}{
		{"93.184.216.34", true, "an ordinary public address is the whole point"},
		{"10.20.30.40", true, "a private address behind the WireGuard server is legitimately reachable"},
		{"127.0.0.1", false, "loopback is the phone itself: adb and every debug listener live there"},
		{"192.168.49.1", false, "the access point's own address is the proxy asking itself"},
		{"192.168.49.5", false, "a neighbour on the hotspot is on-link: it leaves over the access point, never through the tunnel, so checkEgress would retire sharing for everybody"},
		{"169.254.7.7", false, "link-local never crosses the tunnel"},
		{"224.0.0.1", false, "multicast never crosses the tunnel"},
		{"255.255.255.255", false, "broadcast never crosses the tunnel"},
		{"0.0.0.0", false, "the unspecified address is not a destination"},
		{"10.10.11.126", false, "the tunnel's own address is the phone again"},
		{"2606:4700::1111", false, "an IPv4-only tunnel cannot carry an AAAA answer"},
	} {
		if got := guard.allowDest(netip.MustParseAddr(tc.ip), routeTunnel); got != tc.allow {
			t.Errorf("allowDest(%s) = %v, want %v — %s", tc.ip, got, tc.allow, tc.why)
		}
	}
}

// A dual-stack tunnel must not have its own AAAA answers thrown away.
func TestGuardAllowsIPv6WhenTheTunnelCarriesIt(t *testing.T) {
	guard, err := newTetherEgressGuard("192.168.49.1", "10.10.11.126/32, fd00::2/128")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	if !guard.allowDest(netip.MustParseAddr("2606:4700::1111"), routeTunnel) {
		t.Fatal("a dual-stack tunnel refused an IPv6 destination")
	}
}

// A nil guard is the tests' own escape hatch; production never has one.
func TestNilGuardAllowsEverything(t *testing.T) {
	var guard *tetherEgressGuard
	if !guard.allowDest(netip.MustParseAddr("127.0.0.1"), routeTunnel) {
		t.Fatal("nil guard refused a destination")
	}
	if err := guard.checkEgress(nil, routeTunnel); err != nil {
		t.Fatalf("nil guard checked egress: %v", err)
	}
}

// The whole promise of the feature in one test: a socket that did not leave
// through the tunnel is refused, and sharing is retired rather than left running
// with a hole in it.
func TestGuardTripsOnASocketThatMissedTheTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// The tunnel is 10.10.11.126; this socket is bound to loopback.
	guard, err := newTetherEgressGuard("192.168.49.1", "10.10.11.126/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	retired := make(chan struct{}, 4)
	guard.onLeak = func() { retired <- struct{}{} }

	if err := guard.checkEgress(c, routeTunnel); !errors.Is(err, errTetherEgressLeak) {
		t.Fatalf("checkEgress = %v, want errTetherEgressLeak", err)
	}
	select {
	case <-retired:
	case <-time.After(2 * time.Second):
		t.Fatal("sharing was not retired after a socket left outside the tunnel")
	}

	// Once, not once per connection: the log line and the teardown are only
	// interesting the first time.
	if err := guard.checkEgress(c, routeTunnel); !errors.Is(err, errTetherEgressLeak) {
		t.Fatalf("second checkEgress = %v, want errTetherEgressLeak", err)
	}
	select {
	case <-retired:
		t.Fatal("sharing was retired twice")
	case <-time.After(200 * time.Millisecond):
	}
}

// A socket whose local address IS the tunnel is exactly what should pass.
func TestGuardAcceptsASocketBoundToTheTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	guard, err := newTetherEgressGuard("192.168.49.1", "127.0.0.1/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	guard.onLeak = func() { t.Error("sharing was retired for a socket that did go through the tunnel") }
	if err := guard.checkEgress(c, routeTunnel); err != nil {
		t.Fatalf("checkEgress = %v, want nil", err)
	}
}

// A tethered client asking the proxy to reach the phone's own loopback must be
// refused before anything is dialled, not after.
func TestTetherDialRefusesABlockedDestination(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer target.Close()
	_, portStr, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portStr)

	guard, err := newTetherEgressGuard("192.168.49.1", "10.10.11.126/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	dial := newTetherDial(&stubLookup{addrs: []string{"127.0.0.1"}}, guard)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dial(ctx, "adb.local", port); !errors.Is(err, errTetherDestBlocked) {
		t.Fatalf("dial = %v, want errTetherDestBlocked", err)
	}
}

// Sharing that cannot verify its own egress does not start; the UI turns -4 into
// a plain failure instead of an access point with a hole behind it.
func TestStartTetherProxyRefusesWithoutTunnelAddresses(t *testing.T) {
	port := freePort(t)
	if rc := startTetherProxy("127.0.0.1", port, "", "", "", ""); rc != -4 {
		stopTetherProxy()
		t.Fatalf("startTetherProxy returned %d, want -4", rc)
	}
	if got := currentTetherStats().Port; got != 0 {
		stopTetherProxy()
		t.Fatalf("a proxy was left behind on port %d", got)
	}
}

// A CDN answer is a dozen addresses; walking all of them costs a dial timeout
// each when none of them work.
func TestTetherDialCandidatesAreCapped(t *testing.T) {
	var resolved []netip.Addr
	for _, a := range []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"} {
		resolved = append(resolved, netip.MustParseAddr(a))
	}
	got := tetherDialCandidates(nil, resolved, routeTunnel)
	if len(got) != tetherDialAttempts {
		t.Fatalf("got %d candidates, want %d", len(got), tetherDialAttempts)
	}
}

// A bind address that is not an address takes two things down with it: allowDest
// loses the check that stops a client dialling the proxy itself, and
// startTetherProxy hands the empty string to JoinHostPort, which listens on every
// interface the phone has — the tunnel included.
func TestNewTetherEgressGuardNeedsTheAccessPointAddress(t *testing.T) {
	if _, err := newTetherEgressGuard("", tunnelAddrsForTest); err == nil {
		t.Fatal("guard was created without an access point address")
	}
	if _, err := newTetherEgressGuard("not-an-ip", tunnelAddrsForTest); err == nil {
		t.Fatal("guard accepted an access point address that is not an IP")
	}
}

// The same refusal has to reach Kotlin as a start code, not as a proxy listening
// somewhere nobody asked for.
func TestStartTetherProxyRefusesAnUnparseableBindAddress(t *testing.T) {
	if rc := startTetherProxy("not-an-ip", freePort(t), "", tunnelAddrsForTest, "", ""); rc != -4 {
		stopTetherProxy()
		t.Fatalf("startTetherProxy returned %d, want -4", rc)
	}
	if got := currentTetherStats().Port; got != 0 {
		stopTetherProxy()
		t.Fatalf("a proxy was left behind on port %d", got)
	}
}

// A direct route is allowed to leave the tunnel — that is what it is for — but
// not to reach the phone itself or its hotspot, and it is not subject to the
// tunnel's address-family filter: the uplink's families are unknown here, and
// a wrong family fails its dial instantly.
func TestGuardAllowsDirectDestinationsWithoutTheFamilyFilter(t *testing.T) {
	guard, err := newTetherEgressGuard("192.168.49.1", "10.10.11.126/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	for _, tc := range []struct {
		ip    string
		allow bool
	}{
		{"77.88.8.8", true},
		{"2a02:6b8::1", true}, // IPv6 despite an IPv4-only tunnel
		{"127.0.0.1", false},
		{"192.168.49.1", false},
		{"192.168.49.7", false},
		{"10.10.11.126", false},
		{"224.0.0.1", false},
		// Private space is the phone's own LAN or the carrier's CGNAT when the
		// socket leaves over the uplink; the profile's geoip:private does not
		// get to open those to a hotspot client.
		{"192.168.1.1", false},
		{"10.20.30.40", false},
		{"172.16.5.5", false},
		{"100.64.1.1", false},
		{"fd00::5", false},
	} {
		if got := guard.allowDest(netip.MustParseAddr(tc.ip), routeDirect); got != tc.allow {
			t.Errorf("allowDest(%s, direct) = %v, want %v", tc.ip, got, tc.allow)
		}
	}
}

// A direct socket that stayed out of the tunnel is what the profile asked for,
// and a direct socket that fell INTO the tunnel is the safe kind of wrong: neither
// retires sharing.
func TestGuardNeverTripsOnADirectRoute(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Loopback is not the tunnel: outside it, as a direct socket should be.
	guard, err := newTetherEgressGuard("192.168.49.1", "10.10.11.126/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	guard.onLeak = func() { t.Error("sharing was retired for a direct socket that left outside the tunnel") }
	if err := guard.checkEgress(c, routeDirect); err != nil {
		t.Fatalf("checkEgress(direct, outside) = %v, want nil", err)
	}

	// Loopback IS the tunnel now: the direct socket went the safe way.
	inTunnel, err := newTetherEgressGuard("192.168.49.1", "127.0.0.1/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	inTunnel.onLeak = func() { t.Error("sharing was retired for a direct socket that went through the tunnel") }
	if err := inTunnel.checkEgress(c, routeDirect); err != nil {
		t.Fatalf("checkEgress(direct, in tunnel) = %v, want nil", err)
	}

	// The hotspot's own subnet is neither: the socket goes nowhere and is dropped,
	// but sharing survives.
	onAP, err := newTetherEgressGuard("127.0.0.1", "10.10.11.126/32")
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	onAP.onLeak = func() { t.Error("sharing was retired for a direct socket bound to the access point") }
	if err := onAP.checkEgress(c, routeDirect); !errors.Is(err, errTetherEgressUnknown) {
		t.Fatalf("checkEgress(direct, on AP) = %v, want errTetherEgressUnknown", err)
	}
}
