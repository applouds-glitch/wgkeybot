/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
)

// The sharing sheet promises a tethered client that nothing it does can leave
// the phone outside the tunnel. Everything else in this feature arranges for
// that to be true; this file is what checks it, and it does so twice.
//
// Before the dial, allowDest refuses destinations that could never travel
// through the tunnel in the first place: the phone's own loopback (where a
// curious client would find adb and every debug listener an app happens to
// run), the access point's own address (a client asking the proxy to connect to
// the proxy) and the rest of its subnet (a client asking for its neighbours on
// the hotspot), link-local and multicast, and — the interesting one — any address
// family the tunnel does not carry. That last check is what keeps a dual-stack
// name from wasting a dial on an AAAA record the IPv4-only tunnel cannot route.
//
// After the dial, checkEgress reads the socket's local address back. If it is
// not one of the tunnel's own, the packet did NOT go through the tunnel: the
// protect policy misfired, or AllowedIPs is not a default route and this
// destination fell outside it. Either way the connection is dropped and sharing
// is retired wholesale — a partial leak is still a leak, and the user was told
// it could not happen.

var (
	// errTetherDestBlocked is a refusal, not a failure: the destination is one a
	// tethered client has no business reaching through us.
	errTetherDestBlocked = errors.New("destination not reachable from a tethered client")
	// errTetherEgressLeak means a socket reached the internet without passing
	// through the tunnel. It retires sharing; see tetherEgressGuard.checkEgress.
	errTetherEgressLeak = errors.New("upstream socket did not leave through the tunnel")
)

var ipv4Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

type tetherEgressGuard struct {
	// tunnelIPs are the addresses of the tunnel interface, straight from the
	// config's Interface.Address. A socket that went into the tunnel has one of
	// them as its local address.
	tunnelIPs []netip.Addr
	hasV4     bool
	hasV6     bool
	// apIP is the access point's own address, i.e. what the proxy listens on.
	apIP netip.Addr
	// apNet is the subnet that address sits in — every other device on the
	// hotspot, in other words. Those addresses are on-link: they leave over the
	// access point interface and never through the tunnel, so checkEgress would
	// see a non-tunnel local address and retire sharing wholesale. Refusing them
	// up front is what keeps one curious client — a LAN scan, an app probing its
	// neighbours, someone typing a neighbour's IP into a SOCKS-configured
	// browser — from taking sharing down for everybody on the network.
	//
	// A /24 for the same reason pacLocalNetwork assumes one: a local-only hotspot
	// is always handed a /24, and the mask is not worth plumbing down from Kotlin.
	apNet netip.Prefix
	// onLeak retires sharing after checkEgress fails. A field for the same reason
	// tetherProxy.onFatal is one: this file stays free of the cgo half, and tests
	// can observe it.
	onLeak  func()
	tripped atomic.Bool
}

// parseTunnelAddrs reads the comma-separated Interface.Address list Kotlin hands
// down. Entries carry a prefix length ("10.10.11.126/32"); the address is what
// matters here, so the prefix is dropped.
func parseTunnelAddrs(csv string) []netip.Addr {
	out := make([]netip.Addr, 0, 2)
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out
}

// newTetherEgressGuard fails when the tunnel's addresses are unusable: with
// nothing to compare a socket's local address against, checkEgress could only
// wave everything through, and a guard that cannot refuse is worse than an
// honest refusal to start sharing at all.
func newTetherEgressGuard(bindIP, tunnelAddrsCsv string) (*tetherEgressGuard, error) {
	tunnelIPs := parseTunnelAddrs(tunnelAddrsCsv)
	if len(tunnelIPs) == 0 {
		return nil, errors.New("no tunnel addresses to verify egress against")
	}
	g := &tetherEgressGuard{tunnelIPs: tunnelIPs}
	for _, ip := range tunnelIPs {
		if ip.Is4() {
			g.hasV4 = true
		} else {
			g.hasV6 = true
		}
	}
	// An unparseable bind address used to be shrugged off, and the two things
	// that followed were both wrong: allowDest lost the check that keeps a client
	// from dialling the proxy itself, and startTetherProxy went on to hand the
	// empty string to JoinHostPort, which listens on EVERY interface — the tunnel
	// included. This file's whole posture is fail-closed; a proxy nobody can say
	// the address of does not start.
	ap, err := netip.ParseAddr(bindIP)
	if err != nil {
		return nil, fmt.Errorf("access point address %q is not an IP: %w", bindIP, err)
	}
	g.apIP = ap.Unmap()
	if g.apIP.Is4() {
		g.apNet = netip.PrefixFrom(g.apIP, 24).Masked()
	}
	return g, nil
}

// allowDest reports whether a tethered client may be connected to ip.
func (g *tetherEgressGuard) allowDest(ip netip.Addr) bool {
	if g == nil {
		// No guard configured (host builds and tests). Production always has one:
		// startTetherProxy refuses to run without it.
		return true
	}
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback(), ip.IsUnspecified(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsInterfaceLocalMulticast(),
		ip == ipv4Broadcast:
		return false
	}
	if g.apIP.IsValid() && ip == g.apIP {
		return false
	}
	if g.apNet.IsValid() && g.apNet.Contains(ip) {
		return false
	}
	for _, t := range g.tunnelIPs {
		if t == ip {
			return false
		}
	}
	if ip.Is4() && !g.hasV4 {
		return false
	}
	if !ip.Is4() && !g.hasV6 {
		return false
	}
	return true
}

// checkEgress verifies that an upstream socket left through the tunnel, and
// retires sharing when it did not.
func (g *tetherEgressGuard) checkEgress(c net.Conn) error {
	if g == nil {
		return nil
	}
	local := connLocalAddr(c)
	if !local.IsValid() {
		// Unreadable local address: fail closed. This is the one case where being
		// wrong is cheap (a dropped connection) and being permissive is not.
		g.trip("upstream socket has no readable local address")
		return errTetherEgressLeak
	}
	for _, t := range g.tunnelIPs {
		if t == local {
			return nil
		}
	}
	g.trip("upstream socket bound to " + local.String() + ", which is not a tunnel address")
	return errTetherEgressLeak
}

// trip logs and retires sharing, once. Repeating it per connection would bury
// the first (and only interesting) line under a wall of identical ones.
func (g *tetherEgressGuard) trip(why string) {
	if !g.tripped.CompareAndSwap(false, true) {
		return
	}
	turnLog("[TETHER] traffic would have left outside the tunnel (%s); shutting sharing down", why)
	if g.onLeak != nil {
		// Not inline: onLeak stops the proxy, which waits on connections this
		// goroutine may itself be serving.
		go g.onLeak()
	}
}

func connLocalAddr(c net.Conn) netip.Addr {
	addr := c.LocalAddr()
	if addr == nil {
		return netip.Addr{}
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}
