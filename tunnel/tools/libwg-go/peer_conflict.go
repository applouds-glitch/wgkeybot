/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"sync"
	"time"
)

// peerConflict tells, from WireGuard's own handshake lines, that the config is
// in use on another device at the same time.
//
// One WireGuard key, one device: the server sends a peer's traffic to wherever
// the last authenticated packet came from. With the same config up on two
// phones each one's handshake takes the session from the other, and each sees
// what the Pixel's journal showed on 2026-11-14 02:31-02:40 (the user had
// connected a second phone): "Retrying handshake because we stopped hearing
// back after 15 seconds", the response back within a quarter of a second, and
// fifteen to thirty seconds later the same again — seventeen times in nine
// minutes, while the relays, the streams and their echoes were healthy and no
// rule of ours saw anything wrong. The other phone, for its part, started its
// proxy five times over (berlin3's log, the same relay layout).
//
// The mark is a retry for silence that the server answers at once, again and
// again. A path that is down answers no handshake ("did not complete after 5
// seconds"), and one lost packet is one retry: on a healthy tunnel an answered
// retry for silence is rare — two in a day in that same journal. So
// peerConflictRetries of them inside peerConflictWindow is the conflict, and a
// peerConflictWindow without one is its end.
//
// Read off the device's log (wgLogThinner, which every WireGuard line passes),
// because wireguard-go has no event for it; keyed on the format strings, so an
// upstream rewording leaves the watch silent, never wrong.
type peerConflict struct {
	mu sync.Mutex
	// retryAt is when a retry for silence was sent and not yet answered; zero
	// if none is pending.
	retryAt time.Time
	// answered is when each answered retry for silence was answered, the last
	// peerConflictWindow of them.
	answered []time.Time
	// since is when the conflict was found; zero while there is none.
	since time.Time
	logf  func(format string, args ...any)
}

const (
	wgFormatRetrySilence     = "%s - Retrying handshake because we stopped hearing back after %d seconds"
	wgFormatHandshakeTimeout = "%s - Handshake did not complete after %d seconds, retrying (try %d)"
	wgFormatHandshakeGiveUp  = "%s - Handshake did not complete after %d attempts, giving up"
	wgFormatResponse         = "%v - Received handshake response"
)

// Vars so that a test can shrink them; nothing else writes them.
var (
	peerConflictRetries = 3
	peerConflictWindow  = 3 * time.Minute
	// A response this soon after the retry answers it. Measured: 0.11-0.45 s
	// through the relays; a handshake that takes longer is retried by WireGuard
	// itself at 5 s.
	peerConflictAnswerWithin = 2 * time.Second
)

// activePeerConflict is the watch of the device that is up now (wgTurnOn); nil
// while none is.
var activePeerConflict struct {
	sync.Mutex
	w *peerConflict
}

func newPeerConflict(logf func(string, ...any)) *peerConflict {
	return &peerConflict{logf: logf}
}

// note is the device log's call for every line, before it is formatted.
func (c *peerConflict) note(format string, now time.Time) {
	if c == nil {
		return
	}
	switch format {
	case wgFormatRetrySilence, wgFormatResponse, wgFormatHandshakeTimeout, wgFormatHandshakeGiveUp:
	default:
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch format {
	case wgFormatRetrySilence:
		c.retryAt = now
	case wgFormatHandshakeTimeout, wgFormatHandshakeGiveUp:
		// The retry was not answered: a path that is down, not another device.
		c.retryAt = time.Time{}
	case wgFormatResponse:
		if !c.retryAt.IsZero() && now.Sub(c.retryAt) <= peerConflictAnswerWithin {
			c.answered = append(c.answered, now)
			c.pruneLocked(now)
			if c.since.IsZero() && len(c.answered) >= peerConflictRetries {
				c.since = now
				if c.logf != nil {
					c.logf("[WG] the server answered %d handshakes in %v at once and went quiet again each time within seconds — the config looks to be in use on another device too: one key, one device",
						len(c.answered), now.Sub(c.answered[0]).Round(time.Second))
				}
			}
		}
		c.retryAt = time.Time{}
	}
}

func (c *peerConflict) pruneLocked(now time.Time) {
	i := 0
	for i < len(c.answered) && now.Sub(c.answered[i]) > peerConflictWindow {
		i++
	}
	c.answered = c.answered[i:]
}

// seconds is how long the conflict has lasted at now, 0 if there is none. A
// conflict ends when no answered retry for silence has come for
// peerConflictWindow.
func (c *peerConflict) seconds(now time.Time) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if c.since.IsZero() {
		return 0
	}
	if len(c.answered) == 0 {
		if c.logf != nil {
			c.logf("[WG] no handshake taken over for %v — the conflict with another device is over (it lasted %v)",
				peerConflictWindow, now.Sub(c.since).Round(time.Second))
		}
		c.since = time.Time{}
		return 0
	}
	return max(1, int(now.Sub(c.since)/time.Second))
}

// setActivePeerConflict installs the watch of the device coming up.
func setActivePeerConflict(c *peerConflict) {
	activePeerConflict.Lock()
	activePeerConflict.w = c
	activePeerConflict.Unlock()
}

// clearActivePeerConflict removes c when its device goes down — c only: the
// next device may already be up with a watch of its own.
func clearActivePeerConflict(c *peerConflict) {
	activePeerConflict.Lock()
	if activePeerConflict.w == c {
		activePeerConflict.w = nil
	}
	activePeerConflict.Unlock()
}

// peerConflictSeconds is the active device's conflict, 0 if none or no device.
func peerConflictSeconds(now time.Time) int {
	activePeerConflict.Lock()
	c := activePeerConflict.w
	activePeerConflict.Unlock()
	return c.seconds(now)
}
