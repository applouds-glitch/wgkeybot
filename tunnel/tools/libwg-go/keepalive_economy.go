/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// The keepalive economy: with the screen off and the relays reached over TCP,
// the keepalive grid is 50 s instead of 25.
//
// What an idle tunnel costs the battery on a cellular network is the radio, and
// the radio is held up by the grid: one burst of ~2.5 s per keepaliveInterval,
// each followed by the modem's tail of 5-10 s. Measured on 2026-11-12 (Pixel 6a,
// LTE, relays over TCP, screen off, deep Doze, the tunnel idle, ten streams;
// info/bench/radio-20261112, info/bench/economy-20261112): at 25 s the modem
// was receiving 53% of the time, at 50 s 36%. The night before, the same phone
// lost 74% of its battery in 9h47m to an idle tunnel.
//
// Only over TCP. The interval is what holds the NAT mapping of the flow to the
// relay, and a mobile NAT forgets an idle UDP flow in tens of seconds (25 s was
// chosen under that); an established TCP connection it keeps for minutes. And
// only while the host asks (wgTurnProxySetEconomy: the screen is off and the
// user has not switched the setting off): with the screen on the radio is up
// for the user's own traffic anyway, and a relay gone quiet should be found at
// the usual pace.
//
// Not wider than 50 s, because the relays would wake the radio themselves: a VK
// relay sends a TCP keepalive probe on a socket it has heard nothing on for
// about 60 s. Seen on 2026-11-12 with a 200 s grid tried for the screen off ten
// minutes (a "deep sleep", with the server's leave for the silence on a test
// build on a spare port): 59-60 s after each of our
// bursts ten packets came in and ten went out, a probe and our ACK on every
// relay socket, and again 60 s later — four radio wakes per 200 s, as many as
// at 50 s. It was taken out again the same day.
//
// Every rule that reads "one keepalive interval and some slack" moves with the
// grid, or it would fire between two bursts of a healthy tunnel and wake the
// radio itself — which is all this is for:
//
//   - the dispatcher's stale age and the WGH1 report built on it (staleAfter):
//     at 35 s every stream of an idle tunnel would be benched 15 s before its
//     next echo, one by one across the spread, each change a report to the
//     server;
//   - the silence of the whole path (wholePathGap) and the newest echo that
//     says the path is there (darkUpQuietAt), for the same reason;
//   - the dead-stream detector (deadStreamAfter): three windows, as at 25 s;
//   - the kernel's keepalive on the relay's socket (relayTCPKeepAlive), which
//     is set at the dial and so is past the wide grid always;
//   - the backstop of a TURN transaction pion would send more often than the
//     grid comes round (refreshGrid.backstopAfter).
//
// The server (vk-turn-proxy) needs nothing for it: it closes a stream after
// 180 s without a packet from the client (3 × streamReadTimeout) — past the
// 150 s detector here, and three keepalives lost in a row — and lets a WGH1
// report stand for 75 s (feedbackTTL), one report per grid. Its own stale age
// stays 35 s: between the 35th second and the next burst it sees every stream
// of an idle session as stale and sends to all of them, which is what it did
// before it had the rule.
//
// What is given up: a relay that goes quiet under an idle tunnel is doubted
// after 60 s and its stream replaced after 150 s, not 35 and 90. Under load
// nothing changes — data is heard on every stream, and silence among it has its
// own judge and probe (silent_under_load.go, under_load_probe.go).
const (
	economyKeepaliveInterval = 2 * keepaliveInterval
	// One interval, the spread and a mobile round trip, as dispatchStaleAfter
	// is to keepaliveInterval.
	economyStaleAfter = economyKeepaliveInterval + (dispatchStaleAfter - keepaliveInterval)
)

// economyDeadStreamTimeout is deadStreamTimeout for the wide grid: three
// missed windows. Below the server's 180 s, so the client still replaces a
// silent stream before the server closes it under a session the client thinks
// healthy.
//
// A var for the host tests, as deadStreamTimeout is.
var economyDeadStreamTimeout = 3 * economyKeepaliveInterval

// keepaliveEconomy is the mode's state. asked is the host's word; on is
// whether the grid is wide now — asked, and the dials going over TCP. It is
// settled by whoever reads it next (keepaliveEconomyOn), not at the two events
// that change it: the transport changes under networkSwitch's lock, the
// proxy's own start and stop change activeUseUDP, and a reader that settles it
// needs neither to remember this.
//
// looseUntil (UnixNano) keeps the wide grid's ages in force for a while after
// the grid has narrowed again. A stream that sent its last keepalive 40 s ago
// is healthy on the wide grid and stale on the narrow one; without the grace,
// the screen coming on would bench every stream at once, send the server a
// report saying so and hold WireGuard's next initiation (thawHold) — at the
// moment the user picks the phone up. By the end of it every stream has had
// two points of the narrow grid to be heard at.
var keepaliveEconomy struct {
	asked      atomic.Bool
	on         atomic.Bool
	looseUntil atomic.Int64
	mu         sync.Mutex
}

// setKeepaliveEconomyAsked is the host's word (wgTurnProxySetEconomy).
func setKeepaliveEconomyAsked(asked bool) {
	keepaliveEconomy.asked.Store(asked)
}

// keepaliveEconomyOn reports whether the grid is wide at now, and settles the
// state if what it follows has changed.
func keepaliveEconomyOn(now time.Time) bool {
	want := keepaliveEconomy.asked.Load() && relayTransportInUse()
	if keepaliveEconomy.on.Load() == want {
		return want
	}
	keepaliveEconomy.mu.Lock()
	defer keepaliveEconomy.mu.Unlock()
	if keepaliveEconomy.on.Load() == want {
		return want
	}
	if want {
		turnLog("[KEEPALIVE] economy on: the screen is off and the relays are reached over TCP — keepalives every %v instead of %v, a silent stream doubted after %v and replaced after %v",
			economyKeepaliveInterval, keepaliveInterval, economyStaleAfter, economyDeadStreamTimeout)
	} else {
		// Before the flag: no reader may see the grid narrow and the grace not
		// yet there.
		keepaliveEconomy.looseUntil.Store(now.Add(economyStaleAfter).UnixNano())
		turnLog("[KEEPALIVE] economy off — keepalives every %v again", keepaliveInterval)
	}
	keepaliveEconomy.on.Store(want)
	return want
}

// economyAges reports whether the wide grid's ages are in force at now: the
// grid is wide, or it narrowed less than economyStaleAfter ago.
func economyAges(now time.Time) bool {
	return keepaliveEconomyOn(now) || now.UnixNano() < keepaliveEconomy.looseUntil.Load()
}

// keepaliveEvery is the grid's interval at now.
func keepaliveEvery(now time.Time) time.Duration {
	if keepaliveEconomyOn(now) {
		return economyKeepaliveInterval
	}
	return keepaliveInterval
}

// staleAfter is how long a ready stream may go without a packet from its relay
// before it is doubted (dispatchStaleAfter), on the grid in force at now.
func staleAfter(now time.Time) time.Duration {
	if economyAges(now) {
		return economyStaleAfter
	}
	return dispatchStaleAfter
}

// deadStreamAfter is the dead-stream detector's age (deadStreamTimeout) on the
// grid in force at now.
func deadStreamAfter(now time.Time) time.Duration {
	if economyAges(now) {
		return economyDeadStreamTimeout
	}
	return deadStreamTimeout
}

// resetKeepaliveEconomy puts the mode back to off with no grace: for the tests.
func resetKeepaliveEconomy() {
	keepaliveEconomy.mu.Lock()
	defer keepaliveEconomy.mu.Unlock()
	keepaliveEconomy.asked.Store(false)
	keepaliveEconomy.on.Store(false)
	keepaliveEconomy.looseUntil.Store(0)
}
