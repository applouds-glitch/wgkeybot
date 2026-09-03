/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	tetherResolveTimeout = 5 * time.Second
	tetherDialTimeout    = 10 * time.Second

	// How many resolved addresses one dial is willing to walk through. A name
	// behind a large CDN answers with a dozen; if the first few cannot be reached
	// through the tunnel, the rest will not be either, and the client is left
	// waiting a dial timeout per address for an answer that is not coming.
	tetherDialAttempts = 4

	// Ceiling on the whole candidate walk, as opposed to one dial within it.
	// Per-address timeouts multiply: four candidates at ten seconds each is forty
	// seconds of a client connection held open with its deadline deliberately
	// cleared, long after every browser on the far side has given up and asked
	// again. Bounding the walk keeps a bad name from parking a goroutine and two
	// descriptors for the better part of a minute.
	tetherDialBudget = 20 * time.Second
)

// tetherFallbackDNS is used when the tunnel config names no DNS servers at all.
// These are dialled inside the tunnel like any other upstream, so the fallback
// leaks nothing — it only avoids the alternative, which was every name failing
// to resolve while the sheet cheerfully reported sharing as active.
var tetherFallbackDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}

// tetherLookup resolves names for tethered clients. An interface, so the dial
// path can be tested without standing up a DNS server.
type tetherLookup interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// parseDNSServers turns the comma-separated list Kotlin passes down (the
// tunnel's Interface.DnsServers) into dialable host:port pairs.
func parseDNSServers(csv string) []string {
	out := make([]string, 0, 4)
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		out = append(out, s)
	}
	return out
}

// tetherDNSServers is what the resolver ends up querying: the tunnel's own
// servers, or the fallback when the config named none.
//
// A config without a DNS line used to mean every name a tethered client asked
// for failed to resolve while the sheet reported sharing as perfectly healthy —
// the client saw "connected, no internet" and nothing anywhere said why.
func tetherDNSServers(dnsCsv string) []string {
	servers := parseDNSServers(dnsCsv)
	if len(servers) > 0 {
		return servers
	}
	turnLog("[TETHER] tunnel config names no DNS servers; falling back to %v", tetherFallbackDNS)
	return tetherFallbackDNS
}

// newTunnelResolver queries the tunnel's own DNS servers. Neither this dial nor
// the upstream one is protected: both must travel inside the tunnel. See the
// protect policy note at the top of tether_proxy.go.
func newTunnelResolver(servers []string) *net.Resolver {
	return (&dnsDialer{servers: servers, now: time.Now}).resolver()
}

// newDirectResolver queries the routing profile's domestic DNS over the
// physical uplink: names the profile routes direct are resolved where the
// connection will be made from, so a Russian CDN answers with its Russian
// edge rather than the one nearest the tunnel's exit. control is the protect
// hook (tetherDirectControl on device); the socket would otherwise fall into
// the tunnel like every other unprotected one.
//
// The uplink is the one network this app does not control, and plain DNS on
// port 53 is the one protocol every hotel Wi-Fi, carrier and corporate gateway
// feels entitled to intercept: answers rewritten to a captive portal, or
// dropped outright. Either way every whitelisted site would fail while the
// rest of the internet, resolved through the tunnel, worked — the routing
// switch would read as "breaks Russian sites". So each server is tried over
// DNS-over-TLS first (RFC 7858, port 853 — Yandex and every public resolver a
// profile of this family names serve it, with the address itself in the
// certificate) and only then as plain UDP; see dnsDialer for the ladder.
// roots is what the certificate is verified against: vkRootCAPool on device,
// so a resolver under a Минцифры certificate passes as well as a public one.
func newDirectResolver(servers []string, control socketControl, roots *x509.CertPool) *net.Resolver {
	return (&dnsDialer{servers: servers, control: control, tlsFirst: true, tlsRoots: roots, now: time.Now}).resolver()
}

// socketControl is net.Dialer.Control's shape: what protects a socket before it
// connects. nil leaves the socket alone, which on device means "into the tunnel".
type socketControl func(network, address string, c syscall.RawConn) error

const (
	// dotDialTimeout bounds the TCP connect plus TLS handshake of one
	// DNS-over-TLS attempt. Shorter than tetherResolveTimeout on purpose: this
	// is the optimistic rung of the ladder, and a network that filters 853
	// silently (no RST, just nothing) must not eat the whole lookup budget
	// before plain UDP gets its turn — Go's resolver gives one Dial about five
	// seconds.
	dotDialTimeout = 2 * time.Second

	// dotRetryAfter is how long a server that failed DNS-over-TLS is queried
	// over plain UDP before 853 is tried again. Long enough that a filtered
	// port costs one stall per window rather than one per lookup; short enough
	// that the phone walking from a hostile Wi-Fi onto mobile data is noticed
	// without a restart.
	dotRetryAfter = 10 * time.Minute
)

// tetherDoTPort is where DNS-over-TLS is spoken. A var so tests can point it at
// a listener of their own.
var tetherDoTPort = "853"

// dnsDialer is the Dial hook behind both tether resolvers.
//
// Go's resolver decides the wire framing by what Dial hands back: a PacketConn
// means RFC 1035 UDP messages, anything else the two-byte length prefix of RFC
// 7766 — which is DNS-over-TLS the moment the conn is a *tls.Conn. That is what
// makes DoT a small addition rather than a second resolver: the same
// LookupHost, the same A/AAAA handling and RFC 6724 ordering, the same cache on
// top. The ladder lives entirely in dial: TLS to the server's own address
// while that works, plain UDP for dotRetryAfter once it has failed.
type dnsDialer struct {
	servers []string
	control socketControl
	// tlsFirst turns the ladder on. Off for the tunnel resolver: its servers
	// are the tunnel's own, reached inside it, and nobody rewrites answers
	// there.
	tlsFirst bool
	tlsRoots *x509.CertPool
	// now is a field so the retry window can be tested without waiting it out.
	now func() time.Time

	// next is which server this resolver starts from, advanced on every Dial.
	// Trying the list in order inside one Dial looks like failover but is not: a
	// UDP DialContext performs no handshake, so it succeeds even for a server
	// that will never answer, and the loop below it could never reach the
	// second entry. A silent first server meant every lookup timed out with the
	// rest of the list untouched. Go calls Dial again for each retry, so
	// rotating here is what actually reaches the other servers.
	next atomic.Uint32
	// dotDownUntil is the end of the plain-UDP window after a failed DoT
	// attempt, in Unix nanoseconds; zero means DoT is worth trying.
	dotDownUntil atomic.Int64
	// sessions lets every TLS handshake after the first resume it: one round
	// trip fewer per query on a link where each costs a mobile RTT.
	sessions tls.ClientSessionCache
}

func (d *dnsDialer) resolver() *net.Resolver {
	if d.tlsFirst && d.sessions == nil {
		d.sessions = tls.NewLRUClientSessionCache(4)
	}
	return &net.Resolver{PreferGo: true, Dial: d.dial}
}

func (d *dnsDialer) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	if len(d.servers) == 0 {
		return nil, errors.New("no DNS servers configured")
	}
	start := int(d.next.Add(1)-1) % len(d.servers)

	if d.tlsFirst && d.now().UnixNano() >= d.dotDownUntil.Load() {
		// One server per Dial, not the whole list: an attempt may sit out
		// dotDialTimeout on a filtered port, and the query's own deadline is
		// only a few seconds. The rotation reaches the others on later calls,
		// and the window below is per resolver, not per server, because on
		// the network that filters 853 it is filtered for all of them.
		server := d.servers[start]
		c, err := d.dialTLS(ctx, server)
		if err == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			// The lookup was cancelled or timed out as a whole; that says
			// nothing about port 853.
			return nil, err
		}
		d.dotDownUntil.Store(d.now().Add(dotRetryAfter).UnixNano())
		turnLog("[TETHER] DNS over TLS to %s failed (%v); plain UDP for the next %v", server, err, dotRetryAfter)
	}

	dialer := net.Dialer{Timeout: tetherResolveTimeout, Control: d.control}
	var lastErr error
	for i := range d.servers {
		s := d.servers[(start+i)%len(d.servers)]
		c, err := dialer.DialContext(ctx, network, s)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// dialTLS opens a DNS-over-TLS session to server's address on tetherDoTPort.
//
// The certificate is verified against the address itself, never a name: a
// profile names its resolver by IP, and every public resolver that speaks DoT —
// Yandex, Cloudflare, Google, Quad9 — carries its addresses in the
// certificate's SAN for exactly this use. Go sends no SNI for an IP and matches
// it against the IP SANs. The DoH URL a profile may also carry
// (DomesticDNSDomain) is deliberately NOT used as the name: it belongs to the
// HTTPS endpoint, whose certificate need not cover the DoT one, and a wrong
// name here would fail verification and push every lookup to plain UDP — the
// opposite of what the ladder is for.
func (d *dnsDialer) dialTLS(ctx context.Context, server string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, dotDialTimeout)
	defer cancel()
	dialer := net.Dialer{Timeout: dotDialTimeout, Control: d.control}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, tetherDoTPort))
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            d.tlsRoots,
		ClientSessionCache: d.sessions,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// tetherLookupNetwork names the address families worth asking the resolver for:
// "ip4", "ip6", or "ip" for both. LookupHost asks for A and AAAA every time,
// and with an IPv4-only tunnel (the usual config) the guard threw the AAAA half
// away unread, so every cache miss cost two round trips down the TURN path for
// one usable answer. Asking only for what the tunnel carries halves that. A name
// that exists only in the other family now fails to resolve instead of being
// refused by the guard, which is the same outcome one step earlier.
func tetherLookupNetwork(g *tetherEgressGuard) string {
	switch {
	case g == nil, g.hasV4 && g.hasV6:
		return "ip"
	case g.hasV6:
		return "ip6"
	case g.hasV4:
		return "ip4"
	default:
		return "ip"
	}
}

// familyLookup is the tunnel's resolver asked only for the families the tunnel
// carries; see tetherLookupNetwork.
type familyLookup struct {
	r       *net.Resolver
	network string
}

func (f familyLookup) LookupHost(ctx context.Context, host string) ([]string, error) {
	ips, err := f.r.LookupNetIP(ctx, f.network, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.Unmap().String()
	}
	return out, nil
}

// newTetherDial builds the upstream half of the proxy for the plain case:
// resolve on the phone, then connect, every destination through the tunnel.
// See tetherDialer for what a routing profile adds.
//
// guard decides which of the resolved addresses may be dialled at all and
// verifies afterwards that the socket really did leave through the tunnel; see
// tether_guard.go. It may be nil in tests, and only there: startTetherProxy
// refuses to run without one.
func newTetherDial(lookup tetherLookup, guard *tetherEgressGuard) tetherDialFunc {
	return (&tetherDialer{tunnelLookup: lookup, guard: guard}).dial
}

// tetherDialer reaches the internet for one tethered connection, deciding per
// destination whether that means the tunnel, the physical uplink, or nothing.
//
// Without a router every destination takes the tunnel, which is the sharing
// feature's founding promise. With one, the profile's rules pick the route,
// and the two extra roads are:
//
//   - direct: the socket is protected AND bound to the physical network
//     (directControl — the same treatment a TURN dial gets, for the same
//     reason: it must leave over the uplink), and the name is resolved over
//     that uplink too, through the profile's domestic DNS;
//   - block: no socket at all; the caller answers the client with a refusal.
type tetherDialer struct {
	tunnelLookup tetherLookup
	// directLookup resolves names the router sends direct. nil falls back to
	// tunnelLookup, which is wrong for a CDN (see newDirectResolver) but never
	// unsafe: resolution never decides whether a socket is protected.
	directLookup tetherLookup
	// router is nil when sharing runs without a profile: everything tunnels.
	router *tetherRouter
	guard  *tetherEgressGuard
	// directControl protects and binds a direct socket. nil (host tests) dials
	// it like any other socket.
	directControl socketControl

	// activity counts what dial decided, for the proxy's summary line
	// (tether_activity.go). nil in tests that build a dialer by hand.
	activity *tetherActivity

	// directResolveFallback logs, once, the first time the uplink's resolver
	// failed and the tunnel's answered in its place; see resolve.
	directResolveFallback sync.Once
	// firstUpstream logs one line per route per sharing session, not per
	// process: the local address says whether the socket went into the tunnel
	// or out of the physical interface, and that answer is worth having again
	// after a restart. Per route, because with a profile in force the first
	// direct socket is a separate fact from the first tunnel one — it is the
	// line that shows the profile taking effect at all. Every further
	// connection is a number in the summary, not a line; the guard is what
	// checks the rest of them.
	firstUpstream [routeKinds]sync.Once
}

func (d *tetherDialer) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	route, resolved, err := d.resolve(ctx, host)
	if err != nil {
		d.activity.noteFailed()
		return nil, err
	}
	if route == routeBlock {
		d.activity.noteBlocked(host, port)
		return nil, fmt.Errorf("dial %s: %w", host, errTetherRouteBlocked)
	}
	if route == routeDirect && !anyDirectable(resolved) {
		// Nothing here can honestly leave over the uplink — private, CGNAT or
		// ULA space, which the profile's geoip:private claims for direct
		// because on a Happ device that is its own LAN. Behind the WireGuard
		// server it is an ordinary destination that worked before this switch
		// existed, so it keeps working: through the tunnel. See directableAddr.
		route = routeTunnel
	}

	candidates := tetherDialCandidates(d.guard, resolved, route)
	if len(candidates) == 0 {
		d.activity.noteFailed()
		return nil, fmt.Errorf("dial %s: %w", host, errTetherDestBlocked)
	}

	// The budget covers the walk, not the connection: DialContext stops
	// consulting the context the moment a dial succeeds, so cancelling here
	// cannot disturb the socket that is handed back.
	dialCtx, cancelDial := context.WithTimeout(ctx, tetherDialBudget)
	defer cancelDial()

	dialer := net.Dialer{Timeout: tetherDialTimeout}
	if route == routeDirect {
		dialer.Control = d.directControl
	}
	var lastErr error
	for _, a := range candidates {
		c, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err != nil {
			lastErr = err
			continue
		}
		if err := d.guard.checkEgress(c, route); err != nil {
			_ = c.Close()
			d.activity.noteFailed()
			// Not lastErr: a socket that missed the tunnel is a property of the
			// routing, not of this address, so the next candidate would miss it
			// too. Fail the connection outright — the guard has already begun
			// tearing sharing down.
			return nil, err
		}
		d.activity.noteOpened(route)
		d.firstUpstream[route].Do(func() {
			turnLog("[TETHER] first %s upstream %s -> %s (local %s)", route, host, c.RemoteAddr(), c.LocalAddr())
		})
		return c, nil
	}
	d.activity.noteFailed()
	return nil, lastErr
}

// resolve turns a destination into a route and the addresses to try. The
// route can depend on the addresses (IPIfNonMatch), so the two are decided
// together.
func (d *tetherDialer) resolve(ctx context.Context, host string) (routeKind, []netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		// A literal address: no name to match, no lookup to make.
		ip = ip.Unmap()
		route := routeTunnel
		if d.router != nil {
			if k, ok := d.router.routeAddrs([]netip.Addr{ip}); ok {
				route = k
			} else {
				route = d.router.fallback
			}
		}
		return route, []netip.Addr{ip}, nil
	}

	host = normalizeHost(host)
	if d.router == nil {
		addrs, err := d.lookup(ctx, d.tunnelLookup, host)
		return routeTunnel, addrs, err
	}

	route, decided := d.router.routeHost(host)
	if decided && route == routeBlock {
		return routeBlock, nil, nil
	}

	var addrs []netip.Addr
	if fixed, ok := d.router.hosts[host]; ok {
		addrs = fixed
	} else {
		viaDirect := decided && route == routeDirect && d.directLookup != nil
		lookup := d.tunnelLookup
		if viaDirect {
			lookup = d.directLookup
		}
		var err error
		addrs, err = d.lookup(ctx, lookup, host)
		if err != nil && viaDirect && ctx.Err() == nil {
			// The uplink's resolver is the one piece of the direct path this
			// app does not control (see newDirectResolver for what it does to
			// stay reachable). When it still fails, the tunnel's resolver
			// answers instead and the connection is dialled direct all the
			// same: its answer may point at a farther CDN edge, but nothing
			// about the route or its safety changes — resolution never decides
			// whether a socket is protected. A 502 for every whitelisted site
			// would be the alternative.
			d.directResolveFallback.Do(func() {
				turnLog("[TETHER] direct DNS failed for %s (%v); asking the tunnel's resolver instead", host, err)
			})
			addrs, err = d.lookup(ctx, d.tunnelLookup, host)
		}
		if err != nil {
			return routeTunnel, nil, err
		}
	}
	if !decided {
		route = d.router.fallback
		if d.router.resolveOnMiss {
			if k, ok := d.router.routeAddrs(addrs); ok {
				route = k
			}
		}
	}
	return route, addrs, nil
}

func (d *tetherDialer) lookup(ctx context.Context, lookup tetherLookup, host string) ([]netip.Addr, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, tetherResolveTimeout)
	defer cancel()
	raw, err := lookup.LookupHost(resolveCtx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	addrs := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		if ip, err := netip.ParseAddr(s); err == nil {
			addrs = append(addrs, ip.Unmap())
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	return addrs, nil
}

// tetherDialCandidates turns a resolver answer into the addresses worth dialling:
// those the guard permits for this route, capped at tetherDialAttempts.
//
// The resolver's own ordering is kept. Go sorts by RFC 6724, which is the right
// authority when the tunnel carries both families; when it carries only one, the
// guard has already dropped the other, so there is nothing left to reorder.
func tetherDialCandidates(guard *tetherEgressGuard, resolved []netip.Addr, route routeKind) []netip.Addr {
	out := make([]netip.Addr, 0, len(resolved))
	for _, ip := range resolved {
		if !guard.allowDest(ip, route) {
			turnLog("[TETHER] refusing destination %s", ip)
			continue
		}
		out = append(out, ip)
		if len(out) == tetherDialAttempts {
			break
		}
	}
	return out
}
