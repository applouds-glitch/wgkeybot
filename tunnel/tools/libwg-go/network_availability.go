/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
)

// The network gate: new TURN connection work waits while Android has no
// physical network at all, and for nothing else. Existing relay sessions never
// wait here.
//
// Without it, losing every network left the workers dialing a route that did
// not exist — a fresh ENETUNREACH every half second per stream, and every
// failure aging a backoff streak over a network that was not even there.
//
// It used to weigh two more signals, and both are gone on purpose. Android's
// NET_CAPABILITY_VALIDATED closed the gate on networks the system does not
// validate, with "transport proof" (a packet received over TURN in the last
// three minutes) as the way to keep it open and one probe a minute by a single
// worker as the way back. That is exactly the wrong trade for the networks this
// client exists for: behind a whitelist Google's connectivity check fails while
// VK's relays answer, so validation says nothing about our path — both field
// logs of 2026-09-18 ran on cellular networks that never validated. Once a
// relay went dark there, proof expired after three minutes and recovery was
// throttled to one dial a minute; if that dial landed on a relay that allocates
// but carries nothing, the minute was burnt, and the handshake watchdog took
// the VPN down before anything could reconnect. v1.6.0, which people remember
// as holding a connection better, had no gate: its workers simply retried with
// backoff — which is what reconnectDelay and the per-error pacing in runWorker
// already do here.
//
// pathAbsent is stored negated so that its zero value leaves the gate open on
// hosts that never report a path (tests, other platforms).
var networkGate = struct {
	sync.Mutex
	pathAbsent bool
	pathBack   chan struct{}
}{pathBack: make(chan struct{})}

// setPhysicalPath records whether Android has any physical network and reports
// whether that changed. A returning path wakes every parked worker. Reports
// that change nothing are no-ops: the Android side pushes on every path change,
// re-addressing of a network that never went away included.
func setPhysicalPath(present bool) bool {
	networkGate.Lock()
	defer networkGate.Unlock()

	if networkGate.pathAbsent == !present {
		return false
	}
	networkGate.pathAbsent = !present
	if present {
		close(networkGate.pathBack)
		networkGate.pathBack = make(chan struct{})
	}
	return true
}

// isNetworkAvailable reports whether there is a physical network to dial over.
func isNetworkAvailable() bool {
	networkGate.Lock()
	defer networkGate.Unlock()
	return !networkGate.pathAbsent
}

// waitForNetwork blocks while there is no physical network. It reports false
// if ctx ends first.
func waitForNetwork(ctx context.Context) bool {
	for {
		networkGate.Lock()
		if !networkGate.pathAbsent {
			networkGate.Unlock()
			return true
		}
		pathBack := networkGate.pathBack
		networkGate.Unlock()

		select {
		case <-pathBack:
		case <-ctx.Done():
			return false
		}
	}
}
