/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"strconv"
	"strings"
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
