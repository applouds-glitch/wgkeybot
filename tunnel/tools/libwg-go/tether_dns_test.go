/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type stubLookup struct {
	addrs []string
	asked []string
	// err, when set, is what every lookup returns instead of addrs.
	err error
}

func (s *stubLookup) LookupHost(_ context.Context, host string) ([]string, error) {
	s.asked = append(s.asked, host)
	if s.err != nil {
		return nil, s.err
	}
	return s.addrs, nil
}

// Kotlin hands the tunnel's DNS servers down as a comma-separated list, and they
// arrive bare — dialling one needs a port.
func TestParseDNSServersAddsDefaultPort(t *testing.T) {
	got := parseDNSServers(" 1.1.1.1, 8.8.8.8:5353 ,, 2001:db8::1 ")
	want := []string{"1.1.1.1:53", "8.8.8.8:5353", "[2001:db8::1]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDNSServers = %v, want %v", got, want)
	}
}

// The resolver is asked only for the families the tunnel can carry: an AAAA
// answer on an IPv4-only tunnel is a wasted round trip through the relay.
func TestTetherLookupNetworkFollowsTunnelFamilies(t *testing.T) {
	cases := []struct {
		name  string
		addrs string
		want  string
	}{
		{"v4 only", "10.0.0.2/32", "ip4"},
		{"v6 only", "fd00::2/128", "ip6"},
		{"dual stack", "10.0.0.2/32,fd00::2/128", "ip"},
	}
	for _, tc := range cases {
		g, err := newTetherEgressGuard("192.168.43.1", tc.addrs)
		if err != nil {
			t.Fatalf("%s: guard: %v", tc.name, err)
		}
		if got := tetherLookupNetwork(g); got != tc.want {
			t.Errorf("%s: network = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := tetherLookupNetwork(nil); got != "ip" {
		t.Errorf("nil guard: network = %q, want ip", got)
	}
}

// Names are resolved on the phone, never by the client: that is what keeps a
// tethered device from leaking the sites it visits outside the tunnel.
func TestTetherDialResolvesNamesOnThePhone(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer target.Close()
	_, portStr, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portStr)

	lookup := &stubLookup{addrs: []string{"127.0.0.1"}}
	dial := newTetherDial(lookup, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dial(ctx, "example.com", port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if len(lookup.asked) != 1 || lookup.asked[0] != "example.com" {
		t.Fatalf("resolver was asked %v, want [example.com]", lookup.asked)
	}
}

// A literal address must not go through the resolver: doing so would turn every
// IP-based connection into a pointless DNS round trip inside the tunnel.
func TestTetherDialSkipsResolverForLiteralIP(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer target.Close()
	_, portStr, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(portStr)

	lookup := &stubLookup{addrs: []string{"127.0.0.1"}}
	dial := newTetherDial(lookup, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dial(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if len(lookup.asked) != 0 {
		t.Fatalf("resolver was consulted for a literal IP: %v", lookup.asked)
	}
}

// A config with no DNS line used to leave every name unresolvable while the
// sheet reported sharing as healthy. The fallback is dialled inside the tunnel
// like any other upstream, so it costs nothing in privacy.
func TestTetherDNSServersFallBackWhenTheConfigNamesNone(t *testing.T) {
	if got := tetherDNSServers("  , "); !reflect.DeepEqual(got, tetherFallbackDNS) {
		t.Fatalf("tetherDNSServers = %v, want the fallback %v", got, tetherFallbackDNS)
	}
	if got := tetherDNSServers("10.0.0.53"); !reflect.DeepEqual(got, []string{"10.0.0.53:53"}) {
		t.Fatalf("tetherDNSServers = %v, want the tunnel's own server", got)
	}
}
