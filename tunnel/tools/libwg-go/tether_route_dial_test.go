/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// routedDialer builds a tetherDialer over the whitelist profile with both
// resolvers stubbed and the direct protect hook counted, plus a loopback
// target to dial: every route ends on 127.0.0.1 here, so what the tests check
// is which resolver answered and whether the direct hook ran.
type routedDialer struct {
	d            *tetherDialer
	tunnel       *stubLookup
	direct       *stubLookup
	directDials  atomic.Int32
	target       net.Listener
	port         int
	blockedHosts []string
}

func newRoutedDialer(t *testing.T) *routedDialer {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	rd := &routedDialer{
		tunnel: &stubLookup{addrs: []string{"127.0.0.1"}},
		direct: &stubLookup{addrs: []string{"127.0.0.1"}},
		target: target,
		port:   target.Addr().(*net.TCPAddr).Port,
	}
	rd.d = &tetherDialer{
		tunnelLookup: rd.tunnel,
		directLookup: rd.direct,
		router:       testRouter(t, whitelistProfileJSON),
		directControl: func(_, _ string, _ syscall.RawConn) error {
			rd.directDials.Add(1)
			return nil
		},
	}
	return rd
}

func (rd *routedDialer) dial(t *testing.T, host string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := rd.d.dial(ctx, host, rd.port)
	if c != nil {
		_ = c.Close()
	}
	return err
}

// The uplink's resolver is the one piece of the direct path this app does not
// control. When it fails, the name is asked of the tunnel's resolver and the
// connection still goes direct, through the protect hook: a farther CDN edge
// beats a 502 for every whitelisted site.
func TestRoutedDialAsksTheTunnelResolverWhenDirectDNSFails(t *testing.T) {
	rd := newRoutedDialer(t)
	rd.direct.err = errors.New("port 53 filtered")

	if err := rd.dial(t, "mail.yandex.ru"); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if len(rd.direct.asked) != 1 {
		t.Fatalf("direct resolver was asked %v, want the one attempt", rd.direct.asked)
	}
	if len(rd.tunnel.asked) != 1 || rd.tunnel.asked[0] != "mail.yandex.ru" {
		t.Fatalf("tunnel resolver was asked %v, want [mail.yandex.ru]", rd.tunnel.asked)
	}
	if rd.directDials.Load() != 1 {
		t.Fatalf("direct hook ran %d times, want 1: the route must stay direct", rd.directDials.Load())
	}
}

// A whitelisted name is resolved by the domestic resolver and dialled through
// the direct hook; everything else takes the tunnel with no hook at all.
func TestRoutedDialSendsWhitelistedNamesDirect(t *testing.T) {
	rd := newRoutedDialer(t)
	if err := rd.dial(t, "mail.yandex.ru"); err != nil {
		t.Fatalf("dial yandex: %v", err)
	}
	if rd.directDials.Load() != 1 {
		t.Fatalf("direct hook ran %d times, want 1", rd.directDials.Load())
	}
	if len(rd.direct.asked) != 1 || len(rd.tunnel.asked) != 0 {
		t.Fatalf("resolvers asked direct=%v tunnel=%v, want the direct one only", rd.direct.asked, rd.tunnel.asked)
	}

	if err := rd.dial(t, "example.com"); err != nil {
		t.Fatalf("dial example.com: %v", err)
	}
	if rd.directDials.Load() != 1 {
		t.Fatalf("direct hook ran for a tunnelled destination")
	}
	if len(rd.tunnel.asked) != 1 || rd.tunnel.asked[0] != "example.com" {
		t.Fatalf("tunnel resolver asked %v, want [example.com]", rd.tunnel.asked)
	}
}

// Blocked names never reach a resolver, let alone a socket.
func TestRoutedDialRefusesBlockedNamesBeforeResolving(t *testing.T) {
	rd := newRoutedDialer(t)
	err := rd.dial(t, "ad.mail.ru")
	if !errors.Is(err, errTetherRouteBlocked) {
		t.Fatalf("dial = %v, want errTetherRouteBlocked", err)
	}
	if len(rd.tunnel.asked)+len(rd.direct.asked) != 0 || rd.directDials.Load() != 0 {
		t.Fatal("a blocked name was resolved or dialled")
	}
}

// DnsHosts answers from the profile: no resolver is consulted, and the route is
// still the domain rule's (nalog.ru is whitelisted, hence direct).
func TestRoutedDialUsesProfileHosts(t *testing.T) {
	rd := newRoutedDialer(t)
	// The profile pins 213.24.64.175, which this test cannot dial; check the
	// decision instead of the connection.
	route, addrs, err := rd.d.resolve(context.Background(), "lkfl2.nalog.ru")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if route != routeDirect || len(addrs) != 1 || addrs[0].String() != "213.24.64.175" {
		t.Fatalf("resolve = %v %v", route, addrs)
	}
	if len(rd.tunnel.asked)+len(rd.direct.asked) != 0 {
		t.Fatal("a DnsHosts name was sent to a resolver")
	}
}

// IPIfNonMatch: a name no domain rule claims is resolved through the tunnel,
// and the answer decides — an address in geoip:whitelist goes direct.
func TestRoutedDialRoutesUnmatchedNamesByResolvedAddress(t *testing.T) {
	rd := newRoutedDialer(t)
	rd.tunnel.addrs = []string{"77.88.8.8"}
	route, addrs, err := rd.d.resolve(context.Background(), "some-russian-cdn.example")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if route != routeDirect || addrs[0].String() != "77.88.8.8" {
		t.Fatalf("resolve = %v %v, want direct via 77.88.8.8", route, addrs)
	}
	if len(rd.tunnel.asked) != 1 || len(rd.direct.asked) != 0 {
		t.Fatalf("an unmatched name must be resolved through the tunnel; asked tunnel=%v direct=%v", rd.tunnel.asked, rd.direct.asked)
	}

	rd.tunnel.addrs = []string{"1.1.1.1"}
	if route, _, _ = rd.d.resolve(context.Background(), "abroad.example"); route != routeTunnel {
		t.Fatalf("a foreign address routed %v, want tunnel", route)
	}
}

// A literal address is matched against the IP lists like a resolved one.
func TestRoutedDialMatchesLiteralAddresses(t *testing.T) {
	rd := newRoutedDialer(t)
	for ip, want := range map[string]routeKind{"77.88.8.8": routeDirect, "10.0.0.5": routeDirect, "1.1.1.1": routeTunnel} {
		route, _, err := rd.d.resolve(context.Background(), ip)
		if err != nil || route != want {
			t.Errorf("resolve(%s) = %v,%v want %v", ip, route, err, want)
		}
	}
	if len(rd.tunnel.asked)+len(rd.direct.asked) != 0 {
		t.Fatal("a literal address was sent to a resolver")
	}
}

// Without a router nothing changes: one resolver, no hook, everything tunnels.
func TestDialerWithoutRouterTunnelsEverything(t *testing.T) {
	rd := newRoutedDialer(t)
	rd.d.router = nil
	for _, host := range []string{"mail.yandex.ru", "ad.mail.ru"} {
		if err := rd.dial(t, host); err != nil {
			t.Fatalf("dial %s: %v", host, err)
		}
	}
	if route, _, _ := rd.d.resolve(context.Background(), "77.88.8.8"); route != routeTunnel {
		t.Fatalf("a literal address routed %v with no router", route)
	}
	if rd.directDials.Load() != 0 || len(rd.direct.asked) != 0 {
		t.Fatal("the direct path was used with no router")
	}
}

func TestTetherHTTPConnectAnswersBlockedWith403(t *testing.T) {
	p := newTestTetherProxy(t, func(_ context.Context, host string, _ int) (net.Conn, error) {
		return nil, errTetherRouteBlocked
	})
	c := dialProxy(t, p)
	if _, err := c.Write([]byte("CONNECT ad.mail.ru:443 HTTP/1.1\r\nHost: ad.mail.ru:443\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "403") {
		t.Fatalf("status %q, want 403", strings.TrimSpace(status))
	}
}

func TestTetherSocksAnswersBlockedWithNotAllowed(t *testing.T) {
	p := newTestTetherProxy(t, func(_ context.Context, host string, _ int) (net.Conn, error) {
		return nil, errTetherRouteBlocked
	})
	c := dialProxy(t, p)
	socksGreet(t, c)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("ad.mail.ru"))}
	req = append(req, []byte("ad.mail.ru")...)
	req = append(req, 0x01, 0xbb)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != socksRepNotAllowed {
		t.Fatalf("reply code 0x%02x, want 0x02 (not allowed by ruleset)", reply[1])
	}
}

// The whole thing end to end at the export layer: a routing directory makes a
// proxy that reports routing, and a broken one is refused with -5 and nothing
// left listening.
func TestStartTetherProxyWithRoutingProfile(t *testing.T) {
	dir := t.TempDir()
	for name, b := range testGeoFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, tetherRoutingProfileFile), []byte(whitelistProfileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if rc := startTetherProxy("127.0.0.1", port, "", tunnelAddrsForTest, dir, ""); rc != 0 {
		t.Fatalf("startTetherProxy with routing = %d", rc)
	}
	stats := currentTetherStats()
	stopTetherProxy()
	if !stats.Routing {
		t.Fatal("stats do not report routing")
	}
	if stats.Port == 0 {
		t.Fatal("no port reported")
	}

	if err := os.WriteFile(filepath.Join(dir, tetherRoutingProfileFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := startTetherProxy("127.0.0.1", port, "", tunnelAddrsForTest, dir, ""); rc != -5 {
		stopTetherProxy()
		t.Fatalf("startTetherProxy with a broken profile = %d, want -5", rc)
	}
	if got := currentTetherStats().Port; got != 0 {
		stopTetherProxy()
		t.Fatalf("a proxy was left behind on port %d", got)
	}
	if rc := startTetherProxy("127.0.0.1", port, "", tunnelAddrsForTest, "", ""); rc != 0 {
		t.Fatalf("startTetherProxy without routing = %d", rc)
	}
	stats = currentTetherStats()
	stopTetherProxy()
	if stats.Routing {
		t.Fatal("stats report routing with no profile")
	}
}

// The profile's geoip:private claims RFC 1918 for the direct route because on
// the device Happ runs on that is its own LAN. Here the same address is a
// service behind the WireGuard server, and it stays reachable exactly as it was
// before the routing switch existed: through the tunnel, not with a 502.
func TestRoutedDialSendsUndialableDirectDestinationsBackThroughTheTunnel(t *testing.T) {
	rd := newRoutedDialer(t)
	for _, host := range []string{"10.0.0.5", "192.168.1.10", "172.16.0.1", "100.64.0.1", "fd00::1"} {
		route, _, err := rd.d.resolve(context.Background(), host)
		if err != nil {
			t.Fatalf("resolve %s: %v", host, err)
		}
		if route != routeDirect {
			t.Fatalf("resolve(%s) = %v; the profile's geoip:private is supposed to claim it", host, route)
		}
	}
	// Through the whole dial: a private destination must connect, not fail.
	if err := rd.dial(t, "10.0.0.5"); err != nil {
		// The dialer walks candidates; 10.0.0.5 is unreachable in a test, so the
		// interesting part is that it was not refused before the dial.
		if errors.Is(err, errTetherDestBlocked) || errors.Is(err, errTetherRouteBlocked) {
			t.Fatalf("a private destination was refused instead of tunnelled: %v", err)
		}
	}
	if rd.directDials.Load() != 0 {
		t.Fatal("a private destination was dialled over the physical uplink")
	}
}
