/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"sync/atomic"
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
	// transportMoves counts the moves of the dials to the other transport
	// (relayTransportState).
	transportMoves uint64
}{attempts: map[uint64]*networkAttempt{}}

// networkStamp is the network our dials bind to, when one was last lost or
// left, and which resolver list is in force. Two stamps that are the same say
// no network event came between them: none appeared, none went away, none
// replaced another — not even for a moment, a network lost and back again moves
// leftAt — and the resolvers stayed the same.
//
// What it cannot see: a new address on the same network (Kotlin does not pass
// addresses down), and the instant inside one wgSetNetwork between the bind
// moving (jni.c) and this stamp moving — the dials there already go out on
// the new network while the stamp still names the old one.
type networkStamp struct {
	current int64
	leftAt  time.Time
	dns     uint64
}

func currentNetworkStamp() networkStamp {
	networkSwitch.Lock()
	defer networkSwitch.Unlock()
	return networkStamp{current: networkSwitch.current, leftAt: networkSwitch.leftAt, dns: dnsListGen.Load()}
}

func (s networkStamp) same(o networkStamp) bool {
	return s.current == o.current && s.leftAt.Equal(o.leftAt) && s.dns == o.dns
}

// networkAttempt is one worker attempt — dial, allocate, the session that
// follows and the wait after it — tagged with the network it was started on and
// the relay transport it runs over.
type networkAttempt struct {
	seq     uint64 // in the order the attempts began
	network int64
	overTCP bool // the transport this attempt dials with, decided once, here
	useUDP  bool // its group's #@wgt:UseUDP, for what "as configured" means to it
	cancel  context.CancelFunc
	moved   bool // recycled by a move to another network or transport
	// stale is moved, or over a transport left, for the session's downlink to
	// read without the lock: such an attempt books no more loss
	// (observeDownlink), as its session may run on for a while — over a
	// transport left, after the loss judge has let the window of the move go
	// (relayLoss.dropTail; Codex, 2026-11-06).
	stale atomic.Bool
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
		seq:     id,
		network: networkSwitch.current,
		overTCP: transportOverTCP(relayTransportChoice.Load(), cfg.UseUDP),
		useUDP:  cfg.UseUDP,
		cancel:  cancel,
	}
	networkSwitch.attempts[id] = a
	networkSwitch.Unlock()
	return &attemptHandle{ctx: ctx, overTCP: a.overTCP, id: id, a: a}
}

// recycleAttempt ends one attempt the way a move to another network does: its
// worker reconnects at once and counts no failure. Used to move the sessions
// off a relay that has been rested (relay_rest.go).
func recycleAttempt(a *networkAttempt) {
	networkSwitch.Lock()
	if a.moved {
		networkSwitch.Unlock()
		return
	}
	a.moved = true
	a.stale.Store(true)
	networkSwitch.Unlock()
	a.cancel()
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
	prevChoice := relayTransportChoice.Swap(choice)
	choiceChanged := prevChoice != choice
	// The running proxy's dials go over the other transport now, whether or
	// not an attempt is there to recycle: a worker fetching its credential has
	// none, and the dark of the transport left stayed behind with it — the
	// screen said silent over a transport that worked (Codex review, 19.10).
	useUDP := activeUseUDP.Load()
	transportMoved := transportOverTCP(prevChoice, useUDP) != transportOverTCP(choice, useUDP)
	if transportMoved {
		networkSwitch.transportMoves++
	}

	var recycled []*networkAttempt
	overTransport := 0
	if !away {
		for _, a := range networkSwitch.attempts {
			switch {
			case a.moved:
			case networkMoved && a.network != handle:
				a.moved = true
				a.stale.Store(true)
				recycled = append(recycled, a)
			case a.overTCP != transportOverTCP(choice, a.useUDP):
				a.moved = true
				a.stale.Store(true)
				recycled = append(recycled, a)
				overTransport++
			}
		}
	}
	// With no network the attempts wait to be recycled until one is back, but
	// those over the transport left book no more loss from now on: the loss
	// judge lets this window go at the move it sees now, and their downlink
	// queued meanwhile filled the next one, the move done by the time the
	// network was back (Codex, 2026-11-06). One that the transport comes back
	// to before it was recycled books again: kept stale, a session that rode
	// out the outage was left out of the judges for good (Codex, the same day).
	for _, a := range networkSwitch.attempts {
		a.stale.Store(a.moved || a.overTCP != transportOverTCP(choice, a.useUDP))
	}
	networkSwitch.Unlock()

	if choiceChanged {
		turnLog("[NETWORK] relay transport: %s", relayTransportName(choice))
	}
	switch {
	case networkMoved:
		resetServerHealth()
		resetRelayConnectPacing()
		resetDarkPaths()
		ClearCache()
		turnLog("[NETWORK] moved from network %d to %d: %d attempt(s) begun elsewhere recycled (sessions, dials and reconnect delays); server health and DNS cache reset",
			from, handle, len(recycled))
	case overTransport > 0:
		resetServerHealth()
		resetDarkPaths()
		turnLog("[NETWORK] relay transport is now %s: %d attempt(s) on the other one recycled (sessions, dials and reconnect delays); server health reset",
			relayTransportName(choice), overTransport)
	case transportMoved:
		resetDarkPaths()
	}
	for _, a := range recycled {
		a.cancel()
	}
}

// relayTransportState is how many times the running proxy's dials have moved
// from one transport to the other, and the transport they go over now, read
// together under the lock both change under (setNetworkState) — for the loss
// judge's windows (relayLossWindows): a window booked across a move is not one
// path, and two moves between two of its reads leave the transport as it was.
func relayTransportState() (moves uint64, overTCP bool) {
	networkSwitch.Lock()
	defer networkSwitch.Unlock()
	return networkSwitch.transportMoves, transportOverTCP(relayTransportChoice.Load(), activeUseUDP.Load())
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
		// Whatever the path was before, the one after a loss is another.
		resetDarkPaths()
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
