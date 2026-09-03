/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The RoscomVPN whitelist profile as published, minus the download URLs and
// the DoH fields (only DomesticDNSIP is read, and it is exercised separately).
const whitelistProfileJSON = `{
  "Name": "RoscomVPN Whitelist",
  "GlobalProxy": "true",
  "RemoteDns": "8.8.8.8",
  "DomesticDns": "77.88.8.8",
  "DnsHosts": {"lkfl2.nalog.ru": "213.24.64.175", "lknpd.nalog.ru": "213.24.64.181"},
  "RouteOrder": "block-proxy-direct",
  "DirectSites": ["geosite:private", "geosite:whitelist"],
  "DirectIp": ["geoip:private", "geoip:whitelist"],
  "ProxySites": [],
  "ProxyIp": [],
  "BlockSites": ["geosite:win-spy", "geosite:torrent", "geosite:category-ads"],
  "BlockIp": [],
  "DomainStrategy": "IPIfNonMatch",
  "FakeDNS": "false"
}`

// testGeoFiles is a geosite.dat / geoip.dat pair small enough to reason about,
// with the category names the whitelist profile uses.
func testGeoFiles() map[string][]byte {
	var site []byte
	site = append(site, encodeGeoSite("PRIVATE",
		encodeGeoDomain(geoDomainSuffix, "localhost"),
		encodeGeoDomain(geoDomainFull, "router.lan"),
	)...)
	site = append(site, encodeGeoSite("WHITELIST",
		encodeGeoDomain(geoDomainSuffix, "yandex.ru"),
		encodeGeoDomain(geoDomainSuffix, "nalog.ru"),
		encodeGeoDomain(geoDomainPlain, "gosuslugi"),
		encodeGeoDomain(geoDomainRegex, `^cdn\d+\.vk\.com$`),
	)...)
	site = append(site, encodeGeoSite("WIN-SPY", encodeGeoDomain(geoDomainSuffix, "telemetry.microsoft.com"))...)
	site = append(site, encodeGeoSite("TORRENT", encodeGeoDomain(geoDomainSuffix, "rutracker.org"))...)
	site = append(site, encodeGeoSite("CATEGORY-ADS", encodeGeoDomain(geoDomainSuffix, "ad.mail.ru"))...)
	// Unreferenced by the profile; must be skipped, not loaded.
	site = append(site, encodeGeoSite("YOUTUBE", encodeGeoDomain(geoDomainSuffix, "youtube.com"))...)

	var ip []byte
	// The same ranges the published geoip.dat puts in this category; the tests
	// below lean on a tethered client being kept out of every one of them.
	ip = append(ip, encodeGeoIP("PRIVATE",
		encodeCIDR("10.0.0.0/8"), encodeCIDR("172.16.0.0/12"), encodeCIDR("192.168.0.0/16"),
		encodeCIDR("100.64.0.0/10"), encodeCIDR("fc00::/7"))...)
	ip = append(ip, encodeGeoIP("WHITELIST", encodeCIDR("5.255.255.0/24"), encodeCIDR("77.88.0.0/18"), encodeCIDR("77.88.8.0/24"))...)
	return map[string][]byte{tetherRoutingGeoSiteFile: site, tetherRoutingGeoIPFile: ip}
}

func testRouter(t *testing.T, profile string) *tetherRouter {
	t.Helper()
	var prof happProfile
	if err := json.Unmarshal([]byte(profile), &prof); err != nil {
		t.Fatalf("profile: %v", err)
	}
	files := testGeoFiles()
	r, err := buildTetherRouter(&prof, func(name string) ([]byte, error) {
		b, ok := files[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	})
	if err != nil {
		t.Fatalf("buildTetherRouter: %v", err)
	}
	return r
}

func TestDomainMatcherTypes(t *testing.T) {
	m := newDomainMatcher()
	for _, d := range []geoDomain{
		{geoDomainSuffix, "Yandex.ru"},
		{geoDomainFull, "exactly.example"},
		{geoDomainPlain, "gosuslugi"},
		{geoDomainRegex, `^cdn\d+\.vk\.com$`},
	} {
		if err := m.add(d); err != nil {
			t.Fatalf("add %v: %v", d, err)
		}
	}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"yandex.ru", true},
		{"mail.yandex.ru", true},
		{"a.b.yandex.ru", true},
		{"YANDEX.RU.", true},
		{"notyandex.ru", false},
		{"yandex.ru.evil.com", false},
		{"exactly.example", true},
		{"sub.exactly.example", false},
		{"www.gosuslugi.ru", true},
		{"cdn12.vk.com", true},
		{"cdn.vk.com", false},
		{"ru", false},
	} {
		if got := m.match(normalizeHost(tc.host)); got != tc.want {
			t.Errorf("match(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	if !newDomainMatcher().empty() || m.empty() {
		t.Fatal("empty() disagrees with the contents")
	}
	if err := m.add(geoDomain{geoDomainRegex, "("}); err == nil {
		t.Fatal("a broken regexp was accepted")
	}
}

// Nested prefixes are the normal case in a geoip file; a search that lands on
// the inner range must still say yes for an address in the outer one.
func TestIPMatcherMergesNestedAndAdjacentPrefixes(t *testing.T) {
	m := newIPMatcher([]netip.Prefix{
		netip.MustParsePrefix("77.88.8.0/24"),
		netip.MustParsePrefix("77.88.0.0/18"),
		netip.MustParsePrefix("77.88.64.0/18"), // adjacent to the /18 above
		netip.MustParsePrefix("5.255.255.0/24"),
		netip.MustParsePrefix("2a02:6b8::/32"),
	})
	if got := len(m.v4); got != 2 {
		t.Fatalf("v4 ranges = %d (%v), want 2", got, m.v4)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"77.88.8.8", true},
		{"77.88.0.1", true},
		{"77.88.63.255", true},
		{"77.88.64.0", true},
		{"77.88.127.255", true},
		{"77.88.128.0", false},
		{"5.255.255.70", true},
		{"5.255.254.1", false},
		{"2a02:6b8:0:1::1", true},
		{"2a02:6b9::1", false},
		{"::ffff:77.88.8.8", true},
	} {
		if got := m.contains(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("contains(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if newIPMatcher(nil).contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("an empty matcher contained something")
	}
}

func TestParseRouteOrderCompletesPartialOrders(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []routeKind
	}{
		{"block-proxy-direct", []routeKind{routeBlock, routeTunnel, routeDirect}},
		{"direct-block", []routeKind{routeDirect, routeBlock, routeTunnel}},
		{"", []routeKind{routeBlock, routeTunnel, routeDirect}},
		{"Proxy-Proxy-Direct", []routeKind{routeTunnel, routeDirect, routeBlock}},
	} {
		got, err := parseRouteOrder(tc.in)
		if err != nil {
			t.Fatalf("parseRouteOrder(%q): %v", tc.in, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseRouteOrder(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	if _, err := parseRouteOrder("block-tunnel"); err == nil {
		t.Fatal("an unknown order entry was accepted")
	}
}

func TestHappBoolAcceptsStringsAndBooleans(t *testing.T) {
	var v struct {
		A, B, C, D happBool
	}
	if err := json.Unmarshal([]byte(`{"A":"true","B":true,"C":"false","D":""}`), &v); err != nil {
		t.Fatal(err)
	}
	if !v.A || !v.B || v.C || v.D {
		t.Fatalf("parsed %+v", v)
	}
	if err := json.Unmarshal([]byte(`{"A":"maybe"}`), &v); err == nil {
		t.Fatal("garbage parsed as a boolean")
	}
}

func TestWhitelistProfileRoutesLikeHapp(t *testing.T) {
	r := testRouter(t, whitelistProfileJSON)

	if r.fallback != routeTunnel {
		t.Fatalf("GlobalProxy=true must fall back to the tunnel, got %v", r.fallback)
	}
	if !r.resolveOnMiss {
		t.Fatal("IPIfNonMatch must resolve unmatched names")
	}
	if !reflect.DeepEqual(r.domesticDNS, []string{"77.88.8.8:53"}) {
		t.Fatalf("domesticDNS = %v", r.domesticDNS)
	}
	if got := r.hosts["lkfl2.nalog.ru"]; !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("213.24.64.175")}) {
		t.Fatalf("DnsHosts lkfl2.nalog.ru = %v", got)
	}

	for _, tc := range []struct {
		host string
		kind routeKind
		ok   bool
	}{
		{"mail.yandex.ru", routeDirect, true},
		{"www.gosuslugi.ru", routeDirect, true},
		{"router.lan", routeDirect, true},
		{"ad.mail.ru", routeBlock, true},
		{"tracker.rutracker.org", routeBlock, true},
		{"telemetry.microsoft.com", routeBlock, true},
		{"youtube.com", routeTunnel, false}, // in the file, not in the profile
		{"example.com", routeTunnel, false},
	} {
		kind, ok := r.routeHost(normalizeHost(tc.host))
		if kind != tc.kind || ok != tc.ok {
			t.Errorf("routeHost(%s) = %v,%v want %v,%v", tc.host, kind, ok, tc.kind, tc.ok)
		}
	}

	for _, tc := range []struct {
		addrs []string
		kind  routeKind
		ok    bool
	}{
		{[]string{"77.88.8.8"}, routeDirect, true},
		{[]string{"10.1.2.3"}, routeDirect, true},
		{[]string{"fd00::1"}, routeDirect, true},
		{[]string{"1.1.1.1", "5.255.255.70"}, routeDirect, true}, // any address in the set
		{[]string{"1.1.1.1"}, routeTunnel, false},
		{nil, routeTunnel, false},
	} {
		var addrs []netip.Addr
		for _, a := range tc.addrs {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		kind, ok := r.routeAddrs(addrs)
		if kind != tc.kind || ok != tc.ok {
			t.Errorf("routeAddrs(%v) = %v,%v want %v,%v", tc.addrs, kind, ok, tc.kind, tc.ok)
		}
	}
}

// The routing settings screen can name its own domestic resolver; blank means
// the profile's stays.
func TestOverrideDomesticDNS(t *testing.T) {
	r := testRouter(t, whitelistProfileJSON)
	overrideDomesticDNS(r, "  ")
	if !reflect.DeepEqual(r.domesticDNS, []string{"77.88.8.8:53"}) {
		t.Fatalf("a blank override changed the resolvers: %v", r.domesticDNS)
	}
	overrideDomesticDNS(r, "1.1.1.1, 9.9.9.9:5353")
	if !reflect.DeepEqual(r.domesticDNS, []string{"1.1.1.1:53", "9.9.9.9:5353"}) {
		t.Fatalf("override = %v", r.domesticDNS)
	}
	overrideDomesticDNS(nil, "1.1.1.1")
}

// A profile written for the DoH/DoT fields may leave the old DomesticDns blank;
// the address lives in DomesticDNSIP then. The transport fields next to it are
// not read — see happProfile.
func TestBuildTetherRouterReadsDomesticDNSIPWhenDomesticDnsIsBlank(t *testing.T) {
	prof := strings.Replace(whitelistProfileJSON,
		`"DomesticDns": "77.88.8.8"`,
		`"DomesticDns": "", "DomesticDNSType": "DoH", "DomesticDNSDomain": "https://1.1.1.1/dns-query", "DomesticDNSIP": "1.1.1.1"`, 1)
	r := testRouter(t, prof)
	if !reflect.DeepEqual(r.domesticDNS, []string{"1.1.1.1:53"}) {
		t.Fatalf("domesticDNS = %v, want DomesticDNSIP", r.domesticDNS)
	}
}

// A host in both a block list and a direct list goes where RouteOrder says.
func TestRouteOrderDecidesTies(t *testing.T) {
	profile := `{"GlobalProxy":"true","RouteOrder":"direct-block",
	  "DirectSites":["domain:yandex.ru"],"BlockSites":["domain:yandex.ru"]}`
	r := testRouter(t, profile)
	if kind, _ := r.routeHost("yandex.ru"); kind != routeDirect {
		t.Fatalf("direct-block order routed yandex.ru to %v", kind)
	}
}

func TestLiteralSelectorsAndNegation(t *testing.T) {
	profile := `{"GlobalProxy":"false","DomainStrategy":"AsIs",
	  "ProxySites":["full:only.example","keyword:tracker","regexp:^r\\d+\\.example$","plainword"],
	  "ProxyIp":["203.0.113.0/24","198.51.100.7"],
	  "DirectIp":["geoip:!whitelist"]}`
	r := testRouter(t, profile)
	if r.fallback != routeDirect {
		t.Fatalf("GlobalProxy=false must fall back to direct, got %v", r.fallback)
	}
	if r.resolveOnMiss {
		t.Fatal("AsIs must not resolve unmatched names")
	}
	for host, want := range map[string]bool{
		"only.example": true, "sub.only.example": false, "a.tracker.b": true,
		"r12.example": true, "r.example": false, "xplainwordx.tld": true, "other.tld": false,
	} {
		if kind, ok := r.routeHost(host); ok != want || (ok && kind != routeTunnel) {
			t.Errorf("routeHost(%s) = %v,%v want tunnel,%v", host, kind, ok, want)
		}
	}
	for ip, want := range map[string]routeKind{
		"203.0.113.9": routeTunnel, "198.51.100.7": routeTunnel,
		"1.1.1.1": routeDirect, // not in whitelist → geoip:!whitelist matches
	} {
		if kind, ok := r.routeAddrs([]netip.Addr{netip.MustParseAddr(ip)}); !ok || kind != want {
			t.Errorf("routeAddrs(%s) = %v,%v want %v", ip, kind, ok, want)
		}
	}
	// In the whitelist set, so the negated rule does not match and the (empty)
	// proxy list did not either.
	if _, ok := r.routeAddrs([]netip.Addr{netip.MustParseAddr("77.88.8.8")}); ok {
		t.Fatal("geoip:!whitelist matched an address inside the whitelist")
	}
}

func TestBuildTetherRouterRejectsUnknownCategories(t *testing.T) {
	for _, profile := range []string{
		`{"DirectSites":["geosite:nonexistent"]}`,
		`{"DirectIp":["geoip:nonexistent"]}`,
		`{"DirectSites":["ext:custom.dat:ru"]}`,
		`{"DirectIp":["not an address"]}`,
		`{"RouteOrder":"sideways"}`,
	} {
		var prof happProfile
		if err := json.Unmarshal([]byte(profile), &prof); err != nil {
			t.Fatal(err)
		}
		files := testGeoFiles()
		_, err := buildTetherRouter(&prof, func(name string) ([]byte, error) { return files[name], nil })
		if err == nil {
			t.Errorf("profile %s built without error", profile)
		}
	}
}

// A profile that never says geosite: must not need geosite.dat at all.
func TestBuildTetherRouterReadsOnlyReferencedFiles(t *testing.T) {
	var prof happProfile
	if err := json.Unmarshal([]byte(`{"GlobalProxy":"true","DirectSites":["domain:yandex.ru"]}`), &prof); err != nil {
		t.Fatal(err)
	}
	var asked []string
	if _, err := buildTetherRouter(&prof, func(name string) ([]byte, error) {
		asked = append(asked, name)
		return nil, errors.New("should not be read")
	}); err != nil {
		t.Fatalf("buildTetherRouter: %v", err)
	}
	if len(asked) != 0 {
		t.Fatalf("read %v for a profile with no geodata selectors", asked)
	}
}

func TestLoadTetherRouterFromDirectory(t *testing.T) {
	dir := t.TempDir()
	for name, b := range testGeoFiles() {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadTetherRouter(dir); err == nil {
		t.Fatal("loaded a router without a profile")
	}
	if err := os.WriteFile(filepath.Join(dir, tetherRoutingProfileFile), []byte(whitelistProfileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := loadTetherRouter(dir)
	if err != nil {
		t.Fatalf("loadTetherRouter: %v", err)
	}
	if kind, ok := r.routeHost("yandex.ru"); !ok || kind != routeDirect {
		t.Fatalf("yandex.ru routed %v,%v", kind, ok)
	}
	if err := os.WriteFile(filepath.Join(dir, tetherRoutingGeoIPFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTetherRouter(dir); err == nil || !strings.Contains(err.Error(), tetherRoutingGeoIPFile) {
		t.Fatalf("a corrupt geoip.dat loaded: %v", err)
	}
}
