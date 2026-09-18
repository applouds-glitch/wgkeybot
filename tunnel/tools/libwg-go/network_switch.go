/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"time"
)

// Moving to another physical network.
//
// The Kotlin side used to restart the whole proxy on every settled path change.
// Native had long since learned to follow the network on its own — wgSetNetwork
// rebinds every new dial and swaps the resolvers the moment Android reports a
// path, and parks the workers while there is none — so by the time the restart
// landed the workers had already reconnected on the new network. The restart
// then tore those fresh sessions down and dialed the same relay again before VK
// had processed their release: on the device on 2026-09-18 every Wi-Fi drop
// ended in a 486 on the relay the streams had just recovered on.
//
// What the restart still did that nothing else does is here instead, without
// touching the sessions that are already where they should be:
//
//   - a session dialed on another network is recycled: cancelled, so its relay
//     closes (sending the release while the old network still carries it) and
//     its worker reconnects over the new one straight away. A handover that
//     leaves the old network up — Wi-Fi arriving while mobile data stays on —
//     would otherwise keep the tunnel on the old network for as long as it lasts;
//   - server health and the election start over: what a relay did over the old
//     network says nothing about the new path to it;
//   - transport proof is dropped (it was earned over the old network), and so is
//     the DNS cache.
//
// Only a move to a different network counts. Losing the network parks the
// workers and changes nothing else — if the same network comes back, the
// sessions on it may well have survived. A re-addressing that keeps the network
// (a new DHCP lease) is not seen here at all: a connected socket whose source
// address is gone fails its next write, and its worker reconnects.

var networkSwitch = struct {
	sync.Mutex
	current  int64 // network our dials bind to now; 0 = none
	last     int64 // the last network we were on; stays put while there is none
	nextID   uint64
	attempts map[uint64]*networkAttempt
}{attempts: map[uint64]*networkAttempt{}}

// networkAttempt is one worker attempt — dial, allocate and the session that
// follows — tagged with the network it was started on.
type networkAttempt struct {
	network int64
	cancel  context.CancelFunc
	moved   bool // recycled by a move to another network
}

// beginNetworkAttempt returns the context for one worker attempt, tagged with
// the network the dials bind to now, and the call that ends it. The end call
// reports whether a move to another network is what ended the attempt.
func beginNetworkAttempt(parent context.Context) (context.Context, func() (moved bool)) {
	ctx, cancel := context.WithCancel(parent)
	networkSwitch.Lock()
	id := networkSwitch.nextID
	networkSwitch.nextID++
	a := &networkAttempt{network: networkSwitch.current, cancel: cancel}
	networkSwitch.attempts[id] = a
	networkSwitch.Unlock()

	return ctx, func() bool {
		networkSwitch.Lock()
		delete(networkSwitch.attempts, id)
		moved := a.moved
		networkSwitch.Unlock()
		cancel()
		return moved
	}
}

// noteNetworkSwitch records the network our dials now bind to (0 = none) and,
// on a move to a different one, recycles every attempt started elsewhere and
// resets what was learned over the old network.
func noteNetworkSwitch(handle int64) {
	networkSwitch.Lock()
	networkSwitch.current = handle
	if handle == 0 {
		networkSwitch.Unlock()
		return
	}
	from := networkSwitch.last
	networkSwitch.last = handle
	if from == 0 || from == handle {
		networkSwitch.Unlock()
		return
	}
	var recycled []*networkAttempt
	for _, a := range networkSwitch.attempts {
		if a.network != handle && !a.moved {
			a.moved = true
			recycled = append(recycled, a)
		}
	}
	networkSwitch.Unlock()

	resetServerHealth()
	clearTransportProof()
	ClearCache()
	turnLog("[NETWORK] moved from network %d to %d: %d session(s) on the old one recycled; server health, path proof and DNS cache reset",
		from, handle, len(recycled))
	for _, a := range recycled {
		a.cancel()
	}
}

// setBoundNetwork is everything a bound-network report from wgSetNetwork does,
// in order: the allocations left on a network we are leaving are marked first,
// so that no retry heads for a relay they fill; then sessions on another
// network are recycled; the network gate opens or closes last, so parked
// workers wake to all of the above already in place.
func setBoundNetwork(handle int64, now time.Time) {
	noteBoundNetwork(handle, now)
	noteNetworkSwitch(handle)
	if setPhysicalPath(handle != 0) {
		logNetworkAvailability()
	}
}
