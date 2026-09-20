/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// TCP connects to one relay are spaced in time, never sent as a burst.
//
// At a proxy start they already are: WorkerGroup staggers its workers by
// workerStagger. Nothing did afterwards. When the network comes back every
// parked worker is released at once, a move to another network redials every
// session at once, and over TCP the connect comes before the Allocate slot that
// paces everything else — so ten SYNs to one address left within a millisecond.
// On the network TCP is here for that is the worst thing to send (field log
// 19.09, mobile Rostelecom behind the whitelist): of the attempts made alone 56%
// ended in an allocation, of those made 2-3 at a time 37%, of those made four
// or more at a time 14% — and twice, straight after the network returned, 0 of
// 20. What punishes it is not known. The censor's known rule of this shape is on
// bursts of parallel connections to one host, its penalty a connect that passes
// and a server→client direction that stays dark for a minute or more
// (net4people/bbs#546) — which is what a hung Allocate looks like from here;
// other clients on these networks tell their users to run fewer connections and
// to wait between them. Whatever it is, a burst is what the start never sends
// and the start is what works there.
//
// So the spacing is the start's own: workerStagger plus the same jitter — the
// one cadence this network has been seen to take (ten streams up in ~10s). Per
// relay, like the Allocate slots and for their reason: the dial that races a
// silent relay must not queue behind the connects still going to it. A lone
// reconnect never waits — a slot in the past is taken at once — and UDP is not
// paced at all: a UDP "dial" sends nothing, and its Allocates have their slots.
//
// The cost is on the healthy network with TCP forced: ten streams back in ~5s
// after an outage instead of ~2. The first one still goes at once, and the
// tunnel works on one.
var relayConnectPacing = struct {
	sync.Mutex
	next    map[string]time.Time // per relay: when its next connect may leave
	waiting map[string]int
}{next: map[string]time.Time{}, waiting: map[string]int{}}

// relayConnectGap is the distance to the next connect after one that leaves now.
// A var for the tests, which pin the jitter.
var relayConnectGap = func() time.Duration {
	return workerStagger + time.Duration(rand.Intn(200))*time.Millisecond
}

// resetRelayConnectPacing clears the spacing left by the previous network or
// proxy run. The first connect on the new one can leave immediately.
func resetRelayConnectPacing() {
	relayConnectPacing.Lock()
	relayConnectPacing.next = map[string]time.Time{}
	relayConnectPacing.Unlock()
}

// awaitRelayConnectSlot holds a TCP connect to addr until its turn; false if ctx
// ended first. Each admission starts a fresh gap. Waiters recheck under the lock
// after waking: reserving future slots would let all expired timers release
// their connects together after a process pause. Cancelled waiters reserve no
// slots and leave no extra delay behind.
func awaitRelayConnectSlot(ctx context.Context, addr string) bool {
	p := &relayConnectPacing
	waiting := false
	defer func() {
		if waiting {
			p.Lock()
			p.waiting[addr]--
			p.Unlock()
		}
	}()

	for {
		p.Lock()
		if ctx.Err() != nil {
			p.Unlock()
			return false
		}
		now := time.Now()
		at := p.next[addr]
		if !now.Before(at) {
			p.next[addr] = now.Add(relayConnectGap())
			p.Unlock()
			return true
		}
		first := false
		if !waiting {
			waiting = true
			p.waiting[addr]++
			first = p.waiting[addr] == 1
		}
		p.Unlock()

		// One line per burst, from whoever is first to be held.
		if first {
			turnLog("[NETWORK] TCP connects to %s are being spaced %v apart instead of leaving at once", addr, workerStagger)
		}
		if !waitUntil(ctx, at) {
			return false
		}
	}
}
