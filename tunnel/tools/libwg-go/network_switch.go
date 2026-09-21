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
//   - the DNS cache is dropped.
//
// Only a move to a different network counts. Losing the network parks the
// workers and changes nothing else — if the same network comes back, the
// sessions on it may well have survived. A re-addressing that keeps the network
// (a new DHCP lease) is not seen here at all: a connected socket whose source
// address is gone fails its next write, and its worker reconnects.

var networkSwitch = struct {
	sync.Mutex
	current  int64     // network our dials bind to now; 0 = none
	last     int64     // the last network we were on; stays put while there is none
	leftAt   time.Time // when a network we were bound to was last lost or left
	nextID   uint64
	attempts map[uint64]*networkAttempt
}{attempts: map[uint64]*networkAttempt{}}

// networkAttempt is one worker attempt — dial, allocate, the session that
// follows and the wait after it — tagged with the network it was started on and
// the relay transport it runs over.
type networkAttempt struct {
	network int64
	overTCP bool // the transport this attempt dials with, decided once, here
	useUDP  bool // its group's #@wgt:UseUDP, for what "as configured" means to it
	cancel  context.CancelFunc
	moved   bool // recycled by a move to another network or transport
}

// attemptHandle is a worker's hold on its registered attempt.
type attemptHandle struct {
	ctx     context.Context
	overTCP bool
	id      uint64
	a       *networkAttempt
}

// beginAttempt registers one worker attempt, tagged with the network the dials
// bind to now and the relay transport in force now. Both are read under the
// lock that setNetworkState changes them under, and the attempt dials with the
// transport decided here (WorkerGroupConfig.pinTransport) rather than reading it
// again at the dial: a tag that said UDP on an attempt that then dialed TCP
// would be recycled for running over the transport it is already leaving.
func beginAttempt(parent context.Context, cfg WorkerGroupConfig) *attemptHandle {
	ctx, cancel := context.WithCancel(parent)
	networkSwitch.Lock()
	id := networkSwitch.nextID
	networkSwitch.nextID++
	a := &networkAttempt{
		network: networkSwitch.current,
		overTCP: transportOverTCP(relayTransportChoice.Load(), cfg.UseUDP),
		useUDP:  cfg.UseUDP,
		cancel:  cancel,
	}
	networkSwitch.attempts[id] = a
	networkSwitch.Unlock()
	return &attemptHandle{ctx: ctx, overTCP: a.overTCP, id: id, a: a}
}

// moved reports whether the attempt has been recycled, without ending it.
func (h *attemptHandle) moved() bool {
	networkSwitch.Lock()
	defer networkSwitch.Unlock()
	return h.a.moved
}

// end unregisters the attempt and reports whether a move to another network or
// transport is what ended it.
func (h *attemptHandle) end() bool {
	networkSwitch.Lock()
	delete(networkSwitch.attempts, h.id)
	moved := h.a.moved
	networkSwitch.Unlock()
	h.a.cancel()
	return moved
}

// beginNetworkAttempt is beginAttempt for callers that need only the context.
func beginNetworkAttempt(parent context.Context) (context.Context, func() (moved bool)) {
	h := beginAttempt(parent, WorkerGroupConfig{UseUDP: true})
	return h.ctx, h.end
}

// noteNetworkSwitch records the network the dials bind to now, keeping the
// relay transport as it is.
func noteNetworkSwitch(handle int64) {
	noteNetworkState(handle, relayTransportChoice.Load())
}

// noteNetworkState records the network the dials bind to now and how its relays
// are reached, and recycles every attempt that is somewhere else: started on
// another network, or running over the other transport.
//
// The two arrive in one report (wgSetNetwork) and are taken in one step. Taken
// apart — the transport first, then the network — a worker could register its
// next attempt in between, on the new transport and the old network, only to be
// recycled a second time a moment later.
//
// The transport half is what makes the setting take effect: until 2026-09-21 it
// only changed what the next dial would read. Sessions that were up stayed on
// the old transport, and a worker sitting out a reconnect delay slept on — up to
// half a minute of nothing after choosing TCP on a network where UDP carries no
// session, which is exactly where the choice is made. What is compared is the
// transport in effect, not the setting: "as configured" to "UDP" over a config
// that says UDP moves nobody. Relay health starts over with it: a relay demoted
// for what it did over UDP has said nothing about TCP. The DNS cache, the
// connect pacing and the marks on relays holding our allocations stay — the
// network is the same. Credentials and everything guarding VK are not touched:
// a quota does not come free because the client changed how it dials.
//
// Nothing is recycled for its transport while the network is away (A→0): Auto
// reports "as configured" with no network to ask, and the sessions may well
// survive the gap; the report that brings a network back compares them then.
func noteNetworkState(handle int64, choice int32) {
	choice = normaliseRelayTransport(choice)

	networkSwitch.Lock()
	if networkSwitch.current != 0 && networkSwitch.current != handle {
		networkSwitch.leftAt = time.Now()
	}
	networkSwitch.current = handle
	from := networkSwitch.last
	away := handle == 0 && from != 0
	if handle != 0 {
		networkSwitch.last = handle
	}
	networkMoved := handle != 0 && from != 0 && from != handle
	choiceChanged := relayTransportChoice.Swap(choice) != choice

	var recycled []*networkAttempt
	overTransport := 0
	if !away {
		for _, a := range networkSwitch.attempts {
			switch {
			case a.moved:
			case networkMoved && a.network != handle:
				a.moved = true
				recycled = append(recycled, a)
			case a.overTCP != transportOverTCP(choice, a.useUDP):
				a.moved = true
				recycled = append(recycled, a)
				overTransport++
			}
		}
	}
	networkSwitch.Unlock()

	if choiceChanged {
		turnLog("[NETWORK] relay transport: %s", relayTransportName(choice))
	}
	switch {
	case networkMoved:
		resetServerHealth()
		resetRelayConnectPacing()
		ClearCache()
		turnLog("[NETWORK] moved from network %d to %d: %d attempt(s) begun elsewhere recycled (sessions, dials and reconnect delays); server health and DNS cache reset",
			from, handle, len(recycled))
	case overTransport > 0:
		resetServerHealth()
		turnLog("[NETWORK] relay transport is now %s: %d attempt(s) on the other one recycled (sessions, dials and reconnect delays); server health reset",
			relayTransportName(choice), overTransport)
	}
	for _, a := range recycled {
		a.cancel()
	}
}

// setNetworkState is everything a report from wgSetNetwork does, in order: the
// allocations left on a network we are leaving are marked first, so that no
// retry heads for a relay they fill; then sessions on another network or the
// other transport are recycled; the network gate opens or closes last, so parked
// workers wake to all of the above already in place.
func setNetworkState(handle int64, choice int32, now time.Time) {
	noteBoundNetwork(handle, now)
	noteNetworkState(handle, choice)
	if setPhysicalPath(handle != 0) {
		if handle != 0 {
			turnLog("[NETWORK] physical network is back — workers released")
		} else {
			turnLog("[NETWORK] no physical network — workers parked until one returns")
		}
	}
}

// setBoundNetwork is setNetworkState with the relay transport left as it is.
func setBoundNetwork(handle int64, now time.Time) {
	setNetworkState(handle, relayTransportChoice.Load(), now)
}
