/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// Which server this resolver starts from, advanced on every Dial. Trying the
	// list in order inside one Dial looks like failover but is not: a UDP
	// DialContext performs no handshake, so it succeeds even for a server that
	// will never answer, and the loop below it could never reach the second
	// entry. A silent first server meant every lookup timed out with the rest of
	// the list untouched. Go calls Dial again for each retry, so rotating here is
	// what actually reaches the other servers.
	var next atomic.Uint32

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if len(servers) == 0 {
				return nil, errors.New("no tunnel DNS servers configured")
			}
			start := int(next.Add(1)-1) % len(servers)
			d := net.Dialer{Timeout: tetherResolveTimeout}
			var lastErr error
			for i := range servers {
				s := servers[(start+i)%len(servers)]
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// newTetherDial builds the upstream half of the proxy: resolve on the phone,
// then connect. Deliberately unprotected — that is what puts the tethered
// client's traffic inside the tunnel.
//
// guard decides which of the resolved addresses may be dialled at all and
// verifies afterwards that the socket really did leave through the tunnel; see
// tether_guard.go. It may be nil in tests, and only there: startTetherProxy
// refuses to run without one.
func newTetherDial(lookup tetherLookup, guard *tetherEgressGuard) tetherDialFunc {
	// One line per sharing session, not per process: the local address says
	// whether the first socket went into the tunnel or out of the physical
	// interface, and that answer is worth having again after a restart. Every
	// further line would be noise in a log already full of per-connection chatter
	// — the guard is what checks the rest of them.
	var firstUpstream sync.Once

	return func(ctx context.Context, host string, port int) (net.Conn, error) {
		resolved := []string{host}
		if net.ParseIP(host) == nil {
			resolveCtx, cancel := context.WithTimeout(ctx, tetherResolveTimeout)
			addrs, err := lookup.LookupHost(resolveCtx, host)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("resolve %s: %w", host, err)
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("resolve %s: no addresses", host)
			}
			resolved = addrs
		}

		candidates := tetherDialCandidates(guard, resolved)
		if len(candidates) == 0 {
			return nil, fmt.Errorf("dial %s: %w", host, errTetherDestBlocked)
		}

		// The budget covers the walk, not the connection: DialContext stops
		// consulting the context the moment a dial succeeds, so cancelling here
		// cannot disturb the socket that is handed back.
		dialCtx, cancelDial := context.WithTimeout(ctx, tetherDialBudget)
		defer cancelDial()

		d := net.Dialer{Timeout: tetherDialTimeout}
		var lastErr error
		for _, a := range candidates {
			c, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
			if err != nil {
				lastErr = err
				continue
			}
			if err := guard.checkEgress(c); err != nil {
				_ = c.Close()
				// Not lastErr: a socket that missed the tunnel is a property of the
				// routing, not of this address, so the next candidate would miss it
				// too. Fail the connection outright — the guard has already begun
				// tearing sharing down.
				return nil, err
			}
			firstUpstream.Do(func() {
				turnLog("[TETHER] first upstream %s -> %s (local %s)", host, c.RemoteAddr(), c.LocalAddr())
			})
			return c, nil
		}
		return nil, lastErr
	}
}

// tetherDialCandidates turns a resolver answer into the addresses worth dialling:
// those the guard permits, capped at tetherDialAttempts.
//
// The resolver's own ordering is kept. Go sorts by RFC 6724, which is the right
// authority when the tunnel carries both families; when it carries only one, the
// guard has already dropped the other, so there is nothing left to reorder.
func tetherDialCandidates(guard *tetherEgressGuard, resolved []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(resolved))
	for _, s := range resolved {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if !guard.allowDest(ip) {
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
