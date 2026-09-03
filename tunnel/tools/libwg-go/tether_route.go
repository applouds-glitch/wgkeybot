/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Split routing for tethered clients, driven by a Happ routing profile — the
// JSON a Happ (Xray) client imports by URL, e.g. RoscomVPN's WHITELIST.JSON.
//
// The profile names three outcomes and the lists that select each: DirectSites
// / DirectIp, ProxySites / ProxyIp and BlockSites / BlockIp, with the lists
// spelled in Xray's rule vocabulary ("geosite:whitelist", "geoip:private",
// "domain:example.com", "full:", "keyword:", "regexp:", a bare CIDR). The
// geosite:/geoip: selectors point into the geosite.dat / geoip.dat files the
// profile itself links (Geositeurl / Geoipurl); Kotlin downloads those next to
// the profile, and loadTetherRouter reads all three from one directory.
//
// Decision order follows Xray, which is what the profile was written for:
//
//  1. Domain rules, in RouteOrder (block-proxy-direct by default); first list
//     with a match wins.
//  2. No domain rule matched and DomainStrategy is IPIfNonMatch (or
//     IPOnDemand): resolve the name and try the IP rules, in the same order.
//  3. Nothing matched: GlobalProxy decides — true means the tunnel.
//
// "Proxy" here is the tunnel, exactly what every tethered connection used to
// get. "Direct" is a socket protected out of the tunnel and bound to the
// physical uplink — the opposite of the sharing feature's founding promise, so
// this is opt-in and the sharing sheet says so while it is on. "Block" refuses
// the connection.

type routeKind uint8

const (
	routeTunnel routeKind = iota // Xray's "proxy"
	routeDirect
	routeBlock
	routeKinds = 3
)

func (k routeKind) String() string {
	switch k {
	case routeTunnel:
		return "tunnel"
	case routeDirect:
		return "direct"
	case routeBlock:
		return "block"
	}
	return fmt.Sprintf("route(%d)", uint8(k))
}

// errTetherRouteBlocked is the profile refusing a destination outright: an ad
// or tracking host, a torrent tracker. A refusal, not a failure.
var errTetherRouteBlocked = errors.New("destination blocked by the routing profile")

// domainMatcher holds one outcome's domain rules, merged: the order within a
// list does not matter, only which list matched first.
type domainMatcher struct {
	full   map[string]struct{}
	suffix map[string]struct{}
	plain  []string
	regex  []*regexp.Regexp
}

func newDomainMatcher() *domainMatcher {
	return &domainMatcher{full: make(map[string]struct{}), suffix: make(map[string]struct{})}
}

func (m *domainMatcher) add(d geoDomain) error {
	v := normalizeHost(d.value)
	if v == "" {
		// An empty rule is not a rule, it is a wildcard: strings.Contains(host,
		// "") is true for every host and so is an empty regexp. One blank entry
		// in DirectSites would therefore route the whole internet out the
		// physical uplink, and one in BlockSites would blackhole it — from a
		// "keyword:" with nothing after it, a lone dot, or a zero-length Domain
		// record in a third-party geosite.dat (proto3 omits both default
		// fields, so it decodes to plain/""). Everything else malformed in this
		// file is refused and surfaces as -5; so is this.
		return fmt.Errorf("empty domain rule (type %d)", d.typ)
	}
	switch d.typ {
	case geoDomainFull:
		m.full[v] = struct{}{}
	case geoDomainSuffix:
		m.suffix[v] = struct{}{}
	case geoDomainPlain:
		m.plain = append(m.plain, v)
	case geoDomainRegex:
		// The files are built for Xray, which compiles these with Go's regexp
		// too, so the dialects agree.
		re, err := regexp.Compile(d.value)
		if err != nil {
			return fmt.Errorf("regexp %q: %w", d.value, err)
		}
		m.regex = append(m.regex, re)
	default:
		return fmt.Errorf("unknown domain rule type %d", d.typ)
	}
	return nil
}

func (m *domainMatcher) empty() bool {
	return m == nil || (len(m.full) == 0 && len(m.suffix) == 0 && len(m.plain) == 0 && len(m.regex) == 0)
}

// match expects a host already passed through normalizeHost.
func (m *domainMatcher) match(host string) bool {
	if m == nil {
		return false
	}
	if _, ok := m.full[host]; ok {
		return true
	}
	// Suffix rules match the domain itself and anything below it, so walk up
	// one label at a time: "a.b.yandex.ru" tries itself, "b.yandex.ru",
	// "yandex.ru", "ru". A map lookup per label beats scanning 465 suffixes.
	for h := host; ; {
		if _, ok := m.suffix[h]; ok {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	for _, p := range m.plain {
		if strings.Contains(host, p) {
			return true
		}
	}
	for _, re := range m.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// normalizeHost lower-cases and strips the trailing dot of a fully-qualified
// name, so "Yandex.RU." and "yandex.ru" are one host.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// ipRange is an inclusive span of addresses of one family.
type ipRange struct {
	lo, hi netip.Addr
}

// ipMatcher answers "is this address in the set" for a few thousand prefixes:
// the prefixes are flattened into sorted, non-overlapping ranges and searched
// by bisection. Nested prefixes (a /24 inside a /16, which geoip files are full
// of) are merged, otherwise a bisection could land on the inner one and miss.
type ipMatcher struct {
	v4, v6 []ipRange
}

func newIPMatcher(prefixes []netip.Prefix) *ipMatcher {
	var v4, v6 []ipRange
	for _, p := range prefixes {
		r := prefixRange(p)
		if p.Addr().Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	return &ipMatcher{v4: mergeRanges(v4), v6: mergeRanges(v6)}
}

func prefixRange(p netip.Prefix) ipRange {
	p = p.Masked()
	lo := p.Addr()
	b := lo.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	hi, _ := netip.AddrFromSlice(b)
	return ipRange{lo: lo, hi: hi}
}

func mergeRanges(rs []ipRange) []ipRange {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo.Less(rs[j].lo) })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		// Overlapping or directly adjacent: extend the previous range.
		if r.lo.Compare(last.hi) <= 0 || r.lo.Compare(last.hi.Next()) == 0 {
			if r.hi.Compare(last.hi) > 0 {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func (m *ipMatcher) contains(ip netip.Addr) bool {
	if m == nil {
		return false
	}
	ip = ip.Unmap()
	rs := m.v6
	if ip.Is4() {
		rs = m.v4
	}
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi.Compare(ip) >= 0 })
	return i < len(rs) && rs[i].lo.Compare(ip) <= 0
}

// ipRule is one IP selector; negate is the "geoip:!ru" form, which matches
// every address NOT in the set.
type ipRule struct {
	set    *ipMatcher
	negate bool
}

func (r ipRule) match(ip netip.Addr) bool {
	return r.set.contains(ip) != r.negate
}

type tetherRouter struct {
	order   []routeKind
	domains [routeKinds]*domainMatcher
	ips     [routeKinds][]ipRule
	// hosts is the profile's DnsHosts: names answered from the profile instead
	// of any resolver. The whitelist profile uses it for nalog.ru endpoints
	// whose public DNS answers are unreliable.
	hosts map[string][]netip.Addr
	// fallback is where a destination no rule claimed goes: the tunnel when
	// GlobalProxy is true (every profile this was written against), direct
	// otherwise.
	fallback routeKind
	// resolveOnMiss is DomainStrategy other than AsIs: a name no domain rule
	// matched is resolved so the IP rules get their turn.
	resolveOnMiss bool
	// domesticDNS resolves names routed direct, over the physical network —
	// DNS-over-TLS first, plain UDP when that fails (newDirectResolver). From
	// the profile's DomesticDns, with a Russian public resolver as the default
	// since that is what every profile of this family names anyway.
	domesticDNS []string
}

// tetherDirectFallbackDNS is dialled OUTSIDE the tunnel (protected, bound to
// the uplink), so it must be one that answers from inside Russia.
var tetherDirectFallbackDNS = []string{"77.88.8.8:53"}

// overrideDomesticDNS replaces the profile's domestic resolvers with the
// user's, given as the same comma-separated list Kotlin uses for the tunnel's
// servers. An empty or unparseable list keeps the profile's.
func overrideDomesticDNS(r *tetherRouter, csv string) {
	if r == nil {
		return
	}
	if servers := parseDNSServers(csv); len(servers) > 0 {
		r.domesticDNS = servers
	}
}

// routeHost applies the domain rules. ok is false when none matched.
func (r *tetherRouter) routeHost(host string) (kind routeKind, ok bool) {
	for _, k := range r.order {
		if r.domains[k].match(host) {
			return k, true
		}
	}
	return routeTunnel, false
}

// routeAddrs applies the IP rules to a resolver's whole answer. Xray matches a
// rule when any resolved address is in the set, and the lists are tried in
// order, so the first list any address belongs to wins.
func (r *tetherRouter) routeAddrs(addrs []netip.Addr) (kind routeKind, ok bool) {
	for _, k := range r.order {
		for _, rule := range r.ips[k] {
			for _, ip := range addrs {
				if rule.match(ip) {
					return k, true
				}
			}
		}
	}
	return routeTunnel, false
}

// happBool is how Happ profiles spell booleans: as JSON strings ("true"),
// though a real boolean is accepted too.
type happBool bool

func (b *happBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(strings.TrimSpace(string(data)), `"`)
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		*b = true
	case "false", "0", "no", "", "null":
		*b = false
	default:
		return fmt.Errorf("not a boolean: %s", data)
	}
	return nil
}

// happProfile is the subset of a Happ routing profile that decides routes.
// Geoipurl / Geositeurl are read too, but by Kotlin, which does the
// downloading; here the files are expected next to the profile already.
type happProfile struct {
	Name string `json:"Name"`
	// A pointer so "absent" is distinguishable from "false". Absent must mean
	// the tunnel: the opposite default sends every unmatched destination out
	// the uplink, which is the one outcome this feature may never reach by
	// accident. Every profile of this family states it explicitly anyway.
	GlobalProxy    *happBool `json:"GlobalProxy"`
	RouteOrder     string    `json:"RouteOrder"`
	DomainStrategy string    `json:"DomainStrategy"`
	DomesticDNS    string    `json:"DomesticDns"`
	// DomesticDNSIP is the same resolver in the newer DoH/DoT fields (next to
	// DomesticDNSType and DomesticDNSDomain, which nothing here reads: the
	// transport is decided by newDirectResolver, and the DoH URL is not the
	// DoT name). Consulted when DomesticDns is blank.
	DomesticDNSIP string            `json:"DomesticDNSIP"`
	DirectSites   []string          `json:"DirectSites"`
	DirectIP      []string          `json:"DirectIp"`
	ProxySites    []string          `json:"ProxySites"`
	ProxyIP       []string          `json:"ProxyIp"`
	BlockSites    []string          `json:"BlockSites"`
	BlockIP       []string          `json:"BlockIp"`
	DNSHosts      map[string]string `json:"DnsHosts"`
}

// File names inside the routing directory Kotlin hands down. Kotlin writes
// them, Go reads them; the two sides agree on nothing else.
const (
	tetherRoutingProfileFile = "profile.json"
	tetherRoutingGeoSiteFile = "geosite.dat"
	tetherRoutingGeoIPFile   = "geoip.dat"
)

// loadTetherRouter reads profile.json plus whichever of geosite.dat and
// geoip.dat the profile's selectors actually reference. Any inconsistency is
// an error rather than a partial router: a profile with half its lists missing
// would route the missing half through the fallback, silently.
func loadTetherRouter(dir string) (*tetherRouter, error) {
	raw, err := os.ReadFile(filepath.Join(dir, tetherRoutingProfileFile))
	if err != nil {
		return nil, err
	}
	var prof happProfile
	if err := json.Unmarshal(raw, &prof); err != nil {
		return nil, fmt.Errorf("routing profile: %w", err)
	}
	return buildTetherRouter(&prof, func(name string) ([]byte, error) {
		return readGeoDataFile(filepath.Join(dir, name))
	})
}

// buildTetherRouter turns a parsed profile into a router. readFile fetches the
// geodata files by name, and is only called for the categories the profile
// names — a profile with no geosite: selector never opens geosite.dat.
func buildTetherRouter(prof *happProfile, readFile func(name string) ([]byte, error)) (*tetherRouter, error) {
	r := &tetherRouter{
		hosts: make(map[string][]netip.Addr),
		// See happProfile.GlobalProxy: the tunnel is the default, and only an
		// explicit "false" moves unmatched destinations off it.
		fallback: routeTunnel,
		// Xray's own default is AsIs, and so is this: naming the strategies that
		// resolve, rather than assuming any unrecognised value resolves, keeps a
		// typo from quietly handing every unmatched name to the IP rules — where
		// it can land on direct.
		resolveOnMiss: resolvesOnMiss(prof.DomainStrategy),
		domesticDNS:   tetherDirectFallbackDNS,
	}
	if prof.GlobalProxy != nil && !*prof.GlobalProxy {
		r.fallback = routeDirect
	}
	for _, s := range []string{prof.DomesticDNS, prof.DomesticDNSIP} {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if servers := parseDNSServers(s); len(servers) > 0 {
			r.domesticDNS = servers
			break
		}
	}
	order, err := parseRouteOrder(prof.RouteOrder)
	if err != nil {
		return nil, err
	}
	r.order = order

	for host, ipStr := range prof.DNSHosts {
		ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
		if err != nil {
			// Xray also allows a domain as the value (an alias); nothing here
			// resolves aliases, so the entry is skipped and said so.
			turnLog("[TETHER] routing profile: DnsHosts %q -> %q is not an address, ignored", host, ipStr)
			continue
		}
		h := normalizeHost(host)
		r.hosts[h] = append(r.hosts[h], ip.Unmap())
	}

	siteLists := [routeKinds][]string{routeTunnel: prof.ProxySites, routeDirect: prof.DirectSites, routeBlock: prof.BlockSites}
	ipLists := [routeKinds][]string{routeTunnel: prof.ProxyIP, routeDirect: prof.DirectIP, routeBlock: prof.BlockIP}

	// Collect the geodata categories first, so each file is read and decoded
	// once for every list that references it.
	wantSites, wantIPs := map[string]bool{}, map[string]bool{}
	for _, list := range siteLists {
		for _, sel := range list {
			if code, ok := geoSelector(sel, "geosite:"); ok {
				wantSites[code] = true
			}
		}
	}
	for _, list := range ipLists {
		for _, sel := range list {
			if code, ok := geoSelector(sel, "geoip:"); ok {
				wantIPs[strings.TrimPrefix(code, "!")] = true
			}
		}
	}
	var sites map[string][]geoDomain
	if len(wantSites) > 0 {
		b, err := readFile(tetherRoutingGeoSiteFile)
		if err != nil {
			return nil, err
		}
		if sites, err = parseGeoSite(b, wantSites); err != nil {
			return nil, fmt.Errorf("%s: %w", tetherRoutingGeoSiteFile, err)
		}
	}
	var ips map[string][]netip.Prefix
	if len(wantIPs) > 0 {
		b, err := readFile(tetherRoutingGeoIPFile)
		if err != nil {
			return nil, err
		}
		if ips, err = parseGeoIP(b, wantIPs); err != nil {
			return nil, fmt.Errorf("%s: %w", tetherRoutingGeoIPFile, err)
		}
	}

	for k := routeKind(0); k < routeKinds; k++ {
		m := newDomainMatcher()
		for _, sel := range siteLists[k] {
			if err := addSiteSelector(m, sel, sites); err != nil {
				return nil, err
			}
		}
		if !m.empty() {
			r.domains[k] = m
		}
		for _, sel := range ipLists[k] {
			rule, err := parseIPSelector(sel, ips)
			if err != nil {
				return nil, err
			}
			r.ips[k] = append(r.ips[k], rule)
		}
	}
	return r, nil
}

// resolvesOnMiss reports whether a name no domain rule matched should be
// resolved so the IP rules get their turn.
func resolvesOnMiss(strategy string) bool {
	switch strings.TrimSpace(strings.ToLower(strategy)) {
	case "ipifnonmatch", "ipondemand":
		return true
	}
	return false
}

// parseRouteOrder reads "block-proxy-direct" and its permutations. Kinds the
// string leaves out are appended in the default order, so a shorter string
// still yields a total order.
func parseRouteOrder(s string) ([]routeKind, error) {
	names := map[string]routeKind{"block": routeBlock, "proxy": routeTunnel, "direct": routeDirect}
	var out []routeKind
	seen := map[routeKind]bool{}
	for _, part := range strings.Split(strings.ToLower(strings.TrimSpace(s)), "-") {
		if part == "" {
			continue
		}
		k, ok := names[part]
		if !ok {
			return nil, fmt.Errorf("routing profile: unknown RouteOrder entry %q", part)
		}
		if !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	for _, k := range []routeKind{routeBlock, routeTunnel, routeDirect} {
		if !seen[k] {
			out = append(out, k)
		}
	}
	return out, nil
}

// geoSelector recognises "geosite:code" / "geoip:code" (and Xray's
// "geosite:code@attr" form, whose attribute filter is not supported: the whole
// category is used and the attribute ignored). The code comes back lower-cased.
func geoSelector(sel, prefix string) (string, bool) {
	sel = strings.TrimSpace(sel)
	if !strings.HasPrefix(strings.ToLower(sel), prefix) {
		return "", false
	}
	code := strings.ToLower(sel[len(prefix):])
	if i := strings.IndexByte(code, '@'); i >= 0 {
		turnLog("[TETHER] routing profile: attribute filter in %q is not supported; using the whole category", sel)
		code = code[:i]
	}
	return code, code != ""
}

func addSiteSelector(m *domainMatcher, sel string, sites map[string][]geoDomain) error {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return nil
	}
	if code, ok := geoSelector(sel, "geosite:"); ok {
		domains, found := sites[code]
		if !found {
			return fmt.Errorf("routing profile: geosite:%s is not in %s", code, tetherRoutingGeoSiteFile)
		}
		for _, d := range domains {
			if err := m.add(d); err != nil {
				return fmt.Errorf("geosite:%s: %w", code, err)
			}
		}
		return nil
	}
	lower := strings.ToLower(sel)
	switch {
	case strings.HasPrefix(lower, "ext:"):
		return fmt.Errorf("routing profile: external geodata selector %q is not supported", sel)
	case strings.HasPrefix(lower, "domain:"):
		return m.add(geoDomain{geoDomainSuffix, sel[len("domain:"):]})
	case strings.HasPrefix(lower, "full:"):
		return m.add(geoDomain{geoDomainFull, sel[len("full:"):]})
	case strings.HasPrefix(lower, "regexp:"):
		return m.add(geoDomain{geoDomainRegex, sel[len("regexp:"):]})
	case strings.HasPrefix(lower, "keyword:"):
		return m.add(geoDomain{geoDomainPlain, sel[len("keyword:"):]})
	}
	// Xray treats a bare string as a substring rule.
	return m.add(geoDomain{geoDomainPlain, sel})
}

func parseIPSelector(sel string, ips map[string][]netip.Prefix) (ipRule, error) {
	sel = strings.TrimSpace(sel)
	if code, ok := geoSelector(sel, "geoip:"); ok {
		negate := strings.HasPrefix(code, "!")
		code = strings.TrimPrefix(code, "!")
		prefixes, found := ips[code]
		if !found {
			return ipRule{}, fmt.Errorf("routing profile: geoip:%s is not in %s", code, tetherRoutingGeoIPFile)
		}
		return ipRule{set: newIPMatcher(prefixes), negate: negate}, nil
	}
	if strings.HasPrefix(strings.ToLower(sel), "ext:") {
		return ipRule{}, fmt.Errorf("routing profile: external geodata selector %q is not supported", sel)
	}
	if p, err := netip.ParsePrefix(sel); err == nil {
		return ipRule{set: newIPMatcher([]netip.Prefix{p})}, nil
	}
	if a, err := netip.ParseAddr(sel); err == nil {
		a = a.Unmap()
		return ipRule{set: newIPMatcher([]netip.Prefix{netip.PrefixFrom(a, a.BitLen())})}, nil
	}
	return ipRule{}, fmt.Errorf("routing profile: cannot parse IP rule %q", sel)
}
