/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// Relays a config names on top of the ones VK hands out for its link
// (#@wgt:ExtraRelays).
//
// VK names two relays per call link, and the credentials it issues are not tied
// to them: on 2026-10-11 credentials from two links whose own relays were dead
// carried 10-16 Mbit/s through relays of other links, every allocation and
// handshake through. The same survey found our server's downlink good through
// all 11 relays it met in 95.163.34.0/24 and bad or dead through the other 26
// — and 9 of 19 links had no working relay at all. So a config can add relays
// known to be good. They join the link's list rather than replace it: the
// streams spread over all of them (assignRelays), and the judges keep the
// sessions away from whichever goes bad (relay_judge.go, turn_server_health.go).
// A TurnIP pin still pins.
//
// Since 2026-11-04 the extras carry the streams and the link's own relays are
// the reserve behind them (reserveRelays; the tiers of assignRelaysAround and
// moveHead). The link's own come from VK, wherever VK puts them, and the judges
// do not catch a relay that is merely weak: on the bench of 2026-11-04 (Pixel on
// LTE, berlin3, TCP, one inner TCP flow, four interleaved rounds) one such relay
// among the five of a config held the tunnel at 2.0 Mbit/s against 6.7 with it
// rested, lost 3.6% in one window and 0% in the next while the server dealt it
// the same share as the rest, and no verdict came in six sessions. The extras
// are what the operator measured from that server (the bot writes them from its
// per-server list), so they lead; the link's own stay in the list for when the
// extras are resting, demoted or crowded, so a config with extras never has
// fewer relays to fall back on than one without. The race after a failed head
// keeps that order too: the link's own are raced only once the other extras
// have failed or had their time (reserveSplit, runWithCreds).

// parseExtraRelays reads the ExtraRelays value: IP addresses, each with an
// optional port, separated by commas, semicolons or spaces. An entry without a
// port is returned bare and takes the link's port (withExtraRelays). Entries
// that are not an IP address, with a valid port if one is given, are returned
// apart so the caller can say so.
func parseExtraRelays(s string) (relays, bad []string) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	for _, f := range fields {
		if host, port, err := net.SplitHostPort(f); err == nil {
			if p, err := strconv.Atoi(port); err == nil && p >= 1 && p <= 65535 && net.ParseIP(host) != nil {
				relays = append(relays, net.JoinHostPort(host, port))
				continue
			}
		} else if ip := net.ParseIP(f); ip != nil {
			relays = append(relays, ip.String())
			continue
		}
		bad = append(bad, f)
	}
	return relays, bad
}

// extraRelayMatches reports whether addr (ip:port) is one of the configured
// extras: an extra with a port must match whole, a bare one by host.
func extraRelayMatches(addr string, extras []string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	for _, e := range extras {
		if _, _, err := net.SplitHostPort(e); err == nil {
			if e == addr {
				return true
			}
		} else if e == host {
			return true
		}
	}
	return false
}

// reserveRelays is the relays of addrs that are not configured extras — the
// link's own — when extras are configured and at least one of them is in addrs:
// the extras carry the streams and these are the reserve behind them
// (assignRelaysAround, moveHead). nil otherwise: with no extra in the list
// there is nothing to put the link's own behind, and a TurnIP pin has already
// collapsed the list to one.
func reserveRelays(addrs []string, extras []string) map[string]bool {
	if len(extras) == 0 {
		return nil
	}
	var reserve map[string]bool
	carried := false
	for _, a := range addrs {
		if extraRelayMatches(a, extras) {
			carried = true
			continue
		}
		if reserve == nil {
			reserve = map[string]bool{}
		}
		reserve[a] = true
	}
	if !carried {
		return nil
	}
	return reserve
}

// reserveSplit is where the relays of an attempt's order that wait behind the
// extras begin (runWithCreds): at the first of the link's own after a head that
// is an extra. What the order has behind it goes with it — the crowded extras,
// an avoided relay, the outage order — since the order put those behind the
// reserve too (relayTier). len(order) when there is no reserve, or the head is
// itself one of the link's own: the rest is then raced together, as it is
// without extras.
func reserveSplit(order []string, reserve map[string]bool) int {
	if len(order) == 0 || reserve[order[0]] {
		return len(order)
	}
	for i := 1; i < len(order); i++ {
		if reserve[order[i]] {
			return i
		}
	}
	return len(order)
}

// extraRelaysConfigured is the proxy's ExtraRelays as started, for the path
// that has no WorkerGroupConfig at hand: the move of a session off a rested
// relay (relay_rest.go), which picks the head among the session's relays.
var extraRelaysConfigured atomic.Pointer[[]string]

func setExtraRelaysConfigured(extras []string) {
	extraRelaysConfigured.Store(&extras)
}

func configuredExtraRelays() []string {
	if p := extraRelaysConfigured.Load(); p != nil {
		return *p
	}
	return nil
}

// withExtraRelays appends the configured extra relays the list does not hold
// yet, a bare one on the port of the list's first server. Returns a fresh slice
// when it adds anything — addrs may alias the cached ServerAddrs slice.
func withExtraRelays(addrs []string, cfg WorkerGroupConfig) []string {
	if len(cfg.ExtraRelays) == 0 || cfg.TurnIP != "" || len(addrs) == 0 {
		return addrs
	}
	_, port, _ := net.SplitHostPort(addrs[0])
	out := append([]string(nil), addrs...)
	for _, r := range cfg.ExtraRelays {
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, port)
		}
		dup := false
		for _, a := range out {
			if a == r {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, r)
		}
	}
	return out
}
