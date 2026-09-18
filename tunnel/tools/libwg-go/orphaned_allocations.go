/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"sync"
	"time"
)

// Allocations orphaned by a lost network.
//
// VK allows about ten simultaneous allocations per (credential, relay), and a
// session puts all of its streams on one relay, so the pair is full while the
// session lives. When the physical network the session's sockets are bound to
// goes away, none of them can send the Refresh(0) that would release their
// allocation: the relay keeps all of them for the allocation lifetime while
// nobody holds them. Every reconnect on the same credential then opened with a
// 486 from that relay on every stream before fanning out to the other one —
// seen on the device on 2026-09-18 after each Wi-Fi drop, ten 486s per
// recovery — and a second drop within ten minutes filled the other relay too,
// which cost a fresh credential from VK.
//
// Such a (credential, relay) is marked orphaned for the allocation lifetime,
// and attempts on that credential try its other relays first. Only the order
// changes — an orphaned relay stays in the list, last — so a mark can never make
// a working relay unreachable; if the others fail, the orphaned one is still
// dialed and answers for itself. Two events mark it, each covering what the
// other cannot see:
//
//   - a close whose Refresh(0) did not leave the socket. pion sends it once,
//     without waiting, and returns the write error from Close, so that error is
//     exactly "the release never went out". It is also the only trigger that
//     sees the streams that die first: one failed write ends a session, and on
//     a Wi-Fi drop the kernel starts refusing writes before Android reports the
//     loss — the field log of 2026-09-18 has "network is unreachable" ~100 ms
//     ahead of wgSetNetwork(null), with those allocations already closed;
//   - leaving the network the sockets are bound to, for every allocation still
//     live at that moment. Their release may yet be "sent" into a link that is
//     gone without a write error (carrier lost, route not yet removed).
//
// A release that went out on a live network is not marked: VK frees those
// (confirmed on the device the same day). A process restart needs nothing: it
// starts from a fresh credential, and the quota is per credential.

// orphanedAllocationLifetime is how long VK keeps an allocation whose client is
// gone: its lifetime, counted from its last refresh. When that refresh happened
// is not known here, so the whole lifetime is counted from the loss — a relay
// may be tried last a little longer than necessary, never tried first while
// provably full.
const orphanedAllocationLifetime = 600 * time.Second

type relayIdentity struct {
	user  string // TURN username: one VK identity
	relay string // TURN server address
}

var allocationBook = struct {
	sync.Mutex
	boundNetwork int64 // the physical network our sockets are bound to; 0 = none
	live         map[relayIdentity]int
	orphanedTill map[relayIdentity]time.Time
	announced    map[relayIdentity]bool // this mark has already been logged as steering a dial
}{
	live:         map[relayIdentity]int{},
	orphanedTill: map[relayIdentity]time.Time{},
	announced:    map[relayIdentity]bool{},
}

// trackedRelay counts one live allocation until it is closed. The relay conn is
// closed from several places (the session's defer, an early close that unblocks
// its reads, a losing failover candidate, a reaped race), sometimes at once; only
// the first close sends the release, so only its outcome counts, and the count
// is released exactly once.
type trackedRelay struct {
	net.PacketConn
	key    relayIdentity
	mu     sync.Mutex
	closed bool
}

func trackAllocation(relay net.PacketConn, user, addr string) net.PacketConn {
	key := relayIdentity{user: user, relay: addr}
	allocationBook.Lock()
	allocationBook.live[key]++
	allocationBook.Unlock()
	return &trackedRelay{PacketConn: relay, key: key}
}

func (r *trackedRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.PacketConn.Close() // pion: "already closed"
	}
	r.closed = true
	err := r.PacketConn.Close()
	releaseAllocation(r.key, err, time.Now())
	return err
}

// releaseAllocation drops one live allocation from the count; unreleased is the
// error of its Refresh(0) write, nil when the release went out.
func releaseAllocation(key relayIdentity, unreleased error, now time.Time) {
	allocationBook.Lock()
	if allocationBook.live[key]--; allocationBook.live[key] <= 0 {
		delete(allocationBook.live, key)
	}
	fresh := unreleased != nil && orphanLocked(key, now)
	allocationBook.Unlock()

	// One line per mark: a dying network fails all of a session's releases.
	if fresh {
		turnLog("[QUOTA] release of our allocation on %s did not go out (%v) — creds %s held there for %v, other relays go first",
			key.relay, unreleased, credsTag(key.user), orphanedAllocationLifetime)
	}
}

// orphanLocked marks key until its newest orphan expires and reports whether
// this starts a mark (none was in force). A mark that is only extended keeps
// its steering line already logged.
func orphanLocked(key relayIdentity, now time.Time) bool {
	till, marked := allocationBook.orphanedTill[key]
	fresh := !marked || !now.Before(till)
	allocationBook.orphanedTill[key] = now.Add(orphanedAllocationLifetime)
	if fresh {
		delete(allocationBook.announced, key)
	}
	return fresh
}

// noteBoundNetwork records the physical network our sockets are now bound to
// (0 when there is none). Leaving a network orphans every allocation still
// counted live: their sockets are bound to it and can no longer release them.
// Arriving on a network from none, or hearing about the same one again (a
// re-addressing reported with the same handle), orphans nothing.
func noteBoundNetwork(handle int64, now time.Time) {
	allocationBook.Lock()
	prev := allocationBook.boundNetwork
	allocationBook.boundNetwork = handle
	if prev == 0 || prev == handle {
		allocationBook.Unlock()
		return
	}
	type orphaned struct {
		key   relayIdentity
		count int
	}
	var marked []orphaned
	for key, count := range allocationBook.live {
		orphanLocked(key, now)
		marked = append(marked, orphaned{key, count})
	}
	allocationBook.Unlock()

	// Durations, not clock times: Go logs in UTC on the device, logcat in local
	// time, and "until 09:07" next to a 12:57 line only confuses.
	for _, m := range marked {
		turnLog("[QUOTA] network lost under %d allocation(s) on %s (creds %s) — orphaned for %v, other relays go first",
			m.count, m.key.relay, credsTag(m.key.user), orphanedAllocationLifetime)
	}
}

// attemptOrder is the server order for one attempt on user's credential: the
// session's order (assignServers — election, stand-downs, canonical order),
// with relays still holding our orphaned allocations for this credential moved
// to the end. Callers comparing "where would the next attempt go" must use this
// too, not assignServers alone, or they see a different head than the attempt.
func attemptOrder(user string, addrs []string, now time.Time) []string {
	return orderAroundOrphans(user, assignServers(addrs), now)
}

// orderAroundOrphans moves the relays holding orphaned allocations for user to
// the end, keeping the order within both parts. It returns a new slice.
func orderAroundOrphans(user string, addrs []string, now time.Time) []string {
	allocationBook.Lock()
	var clean, orphaned []string
	var orphanKeys []relayIdentity
	for _, addr := range addrs {
		key := relayIdentity{user: user, relay: addr}
		till, ok := allocationBook.orphanedTill[key]
		if ok && !now.Before(till) {
			delete(allocationBook.orphanedTill, key)
			delete(allocationBook.announced, key)
			ok = false
		}
		if ok {
			orphaned = append(orphaned, addr)
			orphanKeys = append(orphanKeys, key)
		} else {
			clean = append(clean, addr)
		}
	}
	if len(orphaned) == 0 || len(clean) == 0 {
		// Nothing to steer around, or nowhere else to go: the order stands.
		allocationBook.Unlock()
		return append([]string(nil), addrs...)
	}
	// One line per mark, not per worker: ten streams consult this at once.
	type steer struct {
		key  relayIdentity
		left time.Duration
	}
	var steered []steer
	for _, key := range orphanKeys {
		if !allocationBook.announced[key] {
			allocationBook.announced[key] = true
			steered = append(steered, steer{key, allocationBook.orphanedTill[key].Sub(now).Round(time.Second)})
		}
	}
	allocationBook.Unlock()

	for _, s := range steered {
		turnLog("[QUOTA] %s still holds our orphaned allocations for creds %s (%v left) — dialing %v first",
			s.key.relay, credsTag(s.key.user), s.left, clean)
	}
	return append(clean, orphaned...)
}

// credsTag names a credential in the log without writing the whole username.
func credsTag(user string) string {
	if len(user) <= 4 {
		return "…" + user
	}
	return "…" + user[len(user)-4:]
}
