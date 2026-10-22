/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// Allocations orphaned by a lost network.
//
// VK allows about ten simultaneous allocations per (credential, relay), and a
// session then put all of its streams on one relay, so the pair was full while
// the session lived. When the physical network the session's sockets are bound to
// goes away, none of them can send the Refresh(0) that would release their
// allocation: the relay keeps all of them for the allocation lifetime while
// nobody holds them. Every reconnect on the same credential then opened with a
// 486 from that relay on every stream before fanning out to the other one —
// seen on the device on 2026-09-18 after each Wi-Fi drop, ten 486s per
// recovery — and a second drop within ten minutes filled the other relay too,
// which cost a fresh credential from VK.
//
// Such a (credential, relay) is marked orphaned for the allocation lifetime,
// with a count of the ghosts it holds, and once they fill half the quota
// (orphanSteerAt) attempts on that credential try its other relays first. Only
// the order changes — a crowded relay stays in the list, last — so a mark can
// never make a working relay unreachable; if the others fail, the crowded one is
// still dialed and answers for itself. Three events mark it, each covering what
// the others cannot see — and each allocation counts once under a mark,
// whichever reports it first (trackedRelay.ghostOf); a later report only
// extends the mark, and under a mark that has run out it counts again:
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
//     gone without a write error (carrier lost, route not yet removed);
//   - a session that ended out of the relay's reach (noteOutOfReach).
//
// A release that went out on a live network is not marked: VK frees those
// (confirmed on the device the same day). A process restart needs nothing: it
// starts from a fresh credential, and the quota is per credential.
//
// Half the quota, not one ghost: since 2026-10-10 a session spreads its streams
// over the relays (assignRelays), so a loss leaves one to four ghosts on each
// relay instead of ten on one. Steering around every marked relay then piled
// the streams up on the relays left — periodic-download run on 18.10
// (Rostelecom on Tele2's 3G, TCP): a two-minute dark at 21:16 left one to four
// ghosts on five relays, and 8 of the 10 streams came back on the sixth; the
// dark at 21:30 left eight on one relay and one each on two more, and 5 came
// back on one of the three left, the order rotated over all six before the
// marked ones were moved out of it (assignRelaysAround). Streams that did land
// among a few ghosts drew no 486 in that run or the one before. A key's ghosts
// all expire with the newest of them.

// orphanedAllocationLifetime is how long VK keeps an allocation whose client is
// gone: its lifetime, counted from its last refresh. When that refresh happened
// is not known here, so the whole lifetime is counted from the loss — a relay
// may be tried last a little longer than necessary, never tried first while
// provably full.
const orphanedAllocationLifetime = 600 * time.Second

// A release that did go out is not instant either. On the device on 2026-09-18
// the Kotlin restart closed ten fresh allocations on a live network, every
// Refresh(0) sent, and the first Allocate on the same credential and relay 0.6s
// later drew a 486; the same stop with a 6s pause before the start got all ten
// back. The worker read that 486 as a full credential: it force-expired it and
// fetched a new one from VK — the trip that can cost a captcha — to cure a
// quota that was seconds from freeing itself.
//
// So a 486 from a relay where one of our releases went out less than
// releaseSettleWindow ago retries the same credential after releaseSettleRetry,
// instead of rotating it. The window bounds the cost of a wrong guess: past it,
// a 486 takes the usual path.
const releaseSettleWindow = 10 * time.Second

// releaseSettleRetry is the pause before trying the same credential again: two
// or three tries fit before the 6s it took on the device, and a refusal costs
// the relay nothing.
func releaseSettleRetry() time.Duration {
	return 1500*time.Millisecond + time.Duration(rand.Intn(1001))*time.Millisecond
}

type relayIdentity struct {
	user  string // TURN username: one VK identity
	relay string // TURN server address
}

var allocationBook = struct {
	sync.Mutex
	boundNetwork int64 // the physical network our sockets are bound to; 0 = none
	live         map[relayIdentity]int
	tracked      map[*trackedRelay]bool // the allocations live now, for the network trigger
	orphanedTill map[relayIdentity]time.Time
	orphans      map[relayIdentity]int       // the ghosts counted under the mark in force
	markOf       map[relayIdentity]uint64    // the mark in force, by number (lastMark)
	lastMark     uint64                      // the number of the newest mark on any key
	announced    map[relayIdentity]bool      // this mark has already been logged as steering a dial
	releasedAt   map[relayIdentity]time.Time // when our latest release there went out
	succeeded    map[string]bool             // credentials at least one allocation was ever accepted on (quota_breaker.go)
}{
	live:         map[relayIdentity]int{},
	tracked:      map[*trackedRelay]bool{},
	orphanedTill: map[relayIdentity]time.Time{},
	orphans:      map[relayIdentity]int{},
	markOf:       map[relayIdentity]uint64{},
	announced:    map[relayIdentity]bool{},
	releasedAt:   map[relayIdentity]time.Time{},
	succeeded:    map[string]bool{},
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

	// ghostOf is the mark this allocation was counted under as a ghost on key,
	// 0 if none. Guarded by allocationBook.
	ghostOf uint64
}

func trackAllocation(relay net.PacketConn, user, addr string) net.PacketConn {
	key := relayIdentity{user: user, relay: addr}
	r := &trackedRelay{PacketConn: relay, key: key}
	allocationBook.Lock()
	allocationBook.live[key]++
	allocationBook.tracked[r] = true
	allocationBook.succeeded[user] = true
	allocationBook.Unlock()
	return r
}

// trackedAllocation finds the allocation under a session's relay conn: the
// trackedRelay itself, or beneath the close budget over TCP (boundRelayClose).
func trackedAllocation(pc net.PacketConn) *trackedRelay {
	for {
		switch c := pc.(type) {
		case *trackedRelay:
			return c
		case *boundedCloseRelay:
			pc = c.PacketConn
		default:
			return nil
		}
	}
}

func (r *trackedRelay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.PacketConn.Close() // pion: "already closed"
	}
	r.closed = true
	err := r.PacketConn.Close()
	releaseAllocation(r.key, err, time.Now(), r)
	return err
}

// releaseAllocation drops one live allocation from the count; unreleased is the
// error of its Refresh(0) write, nil when the release went out. r is the
// allocation, so that a ghost the loss of its network already counted is not
// counted again; nil for one known only by its key.
func releaseAllocation(key relayIdentity, unreleased error, now time.Time, r *trackedRelay) {
	allocationBook.Lock()
	if allocationBook.live[key]--; allocationBook.live[key] <= 0 {
		delete(allocationBook.live, key)
	}
	delete(allocationBook.tracked, r)
	fresh := false
	if unreleased == nil {
		allocationBook.releasedAt[key] = now
	} else {
		fresh = countGhostLocked(key, r, now)
	}
	allocationBook.Unlock()

	// One line per mark: a dying network fails all of a session's releases.
	if fresh {
		turnLog("[QUOTA] release of our allocation on %s did not go out (%v) — creds %s held there for %v",
			key.relay, unreleased, credsTag(key.user), orphanedAllocationLifetime)
	}
}

// countGhostLocked counts allocation r as a ghost on key, or only extends the
// mark if r was counted under it already (countedLocked), and reports whether a
// mark starts (orphanLocked). The same allocation reported again later — its
// network left once more after it came back with its sessions alive
// (network_switch.go), its release failing after that — is held longer, not
// twice (Codex review, 18.10).
func countGhostLocked(key relayIdentity, r *trackedRelay, now time.Time) bool {
	if r != nil && countedLocked(key, r, now) {
		orphanLocked(key, now, 0)
		return false
	}
	fresh := orphanLocked(key, now, 1)
	if r != nil {
		r.ghostOf = allocationBook.markOf[key]
	}
	return fresh
}

// countedLocked reports whether allocation r is counted under the mark on key
// in force at now.
func countedLocked(key relayIdentity, r *trackedRelay, now time.Time) bool {
	till, marked := allocationBook.orphanedTill[key]
	return marked && now.Before(till) && r.ghostOf != 0 && r.ghostOf == allocationBook.markOf[key]
}

// orphanLocked counts n more ghosts on key, marks it until the newest of them
// expires, and reports whether this starts a mark (none was in force: the count
// starts again from these, under a new number). A mark that is only extended
// keeps its steering line already logged.
func orphanLocked(key relayIdentity, now time.Time, n int) bool {
	till, marked := allocationBook.orphanedTill[key]
	fresh := !marked || !now.Before(till)
	if fresh {
		allocationBook.lastMark++
		allocationBook.markOf[key] = allocationBook.lastMark
		allocationBook.orphans[key] = 0
		delete(allocationBook.announced, key)
	}
	allocationBook.orphans[key] += n
	// Never earlier than it was: a wall clock stepped back must not cut short
	// the ghosts already counted.
	if t := now.Add(orphanedAllocationLifetime); fresh || t.After(till) {
		allocationBook.orphanedTill[key] = t
	}
	return fresh
}

// noteOutOfReach marks (user, relay) orphaned after a session whose allocation
// the relay no longer answered to: 400 on CreatePermission after a thaw, or no
// echo to the post-wake probe (outOfReachError). The socket woke under a new
// NAT mapping while the allocation lives on under the old 5-tuple (anton48's
// stand, build 432): the Refresh(0) the close sent went out on the new one,
// which the relay does not know, so the seat is held for the rest of the
// allocation's lifetime — and the release "went out", so releasedAt would read a
// 486 from there as our release settling. The ghost counts towards steering the
// next attempts to the other relays, and settlingQuotaError leaves an orphaned
// relay out. r is the session's allocation (trackedAllocation): one its failed
// release already counted is not counted twice.
func noteOutOfReach(user, relay string, r *trackedRelay, now time.Time) {
	key := relayIdentity{user: user, relay: relay}
	allocationBook.Lock()
	fresh := countGhostLocked(key, r, now)
	allocationBook.Unlock()
	if fresh {
		turnLog("[QUOTA] our allocation on %s was out of reach (the relay no longer knew its socket) — creds %s held there for %v",
			relay, credsTag(user), orphanedAllocationLifetime)
	}
}

// outOfReachError reports whether a session ended because the relay no longer
// knew its socket: the relay's own 400 to a CreatePermission (permWatch, the
// allocation check), or the post-wake probe's verdict. The periodic detector's
// verdict is not one — a relay silent for 90s on a network that is still there
// may just as well have dropped the allocation, and a lost network marks the
// allocations itself (noteBoundNetwork).
func outOfReachError(err error) bool {
	if err == nil {
		return false
	}
	var dead *deadStreamError
	if errors.As(err, &dead) {
		return dead.probe
	}
	return strings.Contains(err.Error(), permBadRequestMarker)
}

// noteBoundNetwork records the physical network our sockets are now bound to
// (0 when there is none). Leaving a network orphans every allocation still
// live: their sockets are bound to it and can no longer release them — each
// counted once under a mark (countGhostLocked). Arriving on
// a network from none, or hearing about the same one again (a re-addressing
// reported with the same handle), orphans nothing.
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
	byKey := map[relayIdentity][]*trackedRelay{}
	for r := range allocationBook.tracked {
		byKey[r.key] = append(byKey[r.key], r)
	}
	var marked []orphaned
	for key, rs := range byKey {
		uncounted := 0
		for _, r := range rs {
			if !countedLocked(key, r, now) {
				uncounted++
			}
		}
		orphanLocked(key, now, uncounted)
		for _, r := range rs {
			r.ghostOf = allocationBook.markOf[key]
		}
		marked = append(marked, orphaned{key, len(rs)})
	}
	allocationBook.Unlock()

	// Durations, not clock times: Go logs in UTC on the device, logcat in local
	// time, and "until 09:07" next to a 12:57 line only confuses.
	for _, m := range marked {
		turnLog("[QUOTA] left network %d with %d allocation(s) on %s (creds %s) — orphaned for %v",
			prev,
			m.count, m.key.relay, credsTag(m.key.user), orphanedAllocationLifetime)
	}
}

// noteCredsFromEarlierProcess takes user, a credential read back from disk
// (turn_creds_store.go), as one with ghosts on every one of relays: the process
// that fetched it may have died with its allocations up, and nothing says how
// many, on which relays or how long ago. Each relay is marked crowded — counted
// as orphanSteerAt ghosts, half the quota — for the whole allocation lifetime
// from now, under the rules a lost network applies to the allocations it
// strands (orphanLocked): a mark already in force only grows. And the
// credential counts as one allocations were accepted on, so that a 486 on it is
// its own quota, not a relay refusing fresh credentials (quota_breaker.go).
//
// With every relay of the credential crowded the dial order stands as it is
// (assignRelaysAround): there is nowhere better to go, and a 486 takes the
// ordinary rotation. The marks keep the book honest meanwhile — a 486 beside an
// orphan mark is never read as our own release settling (settlingQuotaError).
func noteCredsFromEarlierProcess(user string, relays []string, now time.Time) {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	allocationBook.succeeded[user] = true
	for _, relay := range relays {
		orphanLocked(relayIdentity{user: user, relay: relay}, now, orphanSteerAt)
	}
}

// orphanSteerAt is how many of a credential's ghosts on a relay make it crowded:
// half of VK's quota of about ten (see above). Beside fewer there is room for
// the one or two streams the spread sends there.
const orphanSteerAt = 5

// crowdedRelays returns the relays of addrs that hold orphanSteerAt or more of
// user's ghosts, sweeping the marks that have expired; nil if none does.
func crowdedRelays(user string, addrs []string, now time.Time) map[string]bool {
	allocationBook.Lock()
	defer allocationBook.Unlock()
	var crowded map[string]bool
	for _, addr := range addrs {
		key := relayIdentity{user: user, relay: addr}
		till, ok := allocationBook.orphanedTill[key]
		if ok && !now.Before(till) {
			delete(allocationBook.orphanedTill, key)
			delete(allocationBook.announced, key)
			delete(allocationBook.orphans, key)
			delete(allocationBook.markOf, key)
			continue
		}
		if ok && allocationBook.orphans[key] >= orphanSteerAt {
			if crowded == nil {
				crowded = map[string]bool{}
			}
			crowded[addr] = true
		}
	}
	return crowded
}

// announceCrowded logs each crowded relay an attempt's order steered around —
// one in order behind a head that is not crowded — once per mark: ten streams
// consult this at once.
func announceCrowded(user string, crowded map[string]bool, order []string, now time.Time) {
	if len(crowded) == 0 || len(order) == 0 || crowded[order[0]] {
		return
	}
	var clean []string
	for _, addr := range order {
		if !crowded[addr] {
			clean = append(clean, addr)
		}
	}
	type steer struct {
		key   relayIdentity
		count int
		left  time.Duration
	}
	var steered []steer
	allocationBook.Lock()
	for _, addr := range order {
		key := relayIdentity{user: user, relay: addr}
		// Looked at again: another worker may have swept the mark since, or a
		// new one have started in its place.
		till, marked := allocationBook.orphanedTill[key]
		if !crowded[addr] || allocationBook.announced[key] || !marked || !now.Before(till) || allocationBook.orphans[key] < orphanSteerAt {
			continue
		}
		allocationBook.announced[key] = true
		steered = append(steered, steer{key, allocationBook.orphans[key], till.Sub(now).Round(time.Second)})
	}
	allocationBook.Unlock()

	for _, s := range steered {
		turnLog("[QUOTA] %s still holds %d of our orphaned allocations for creds %s (%v left) — dialing %v first",
			s.key.relay, s.count, credsTag(s.key.user), s.left, clean)
	}
}

// credsTag names a credential in the log without writing the whole username.
func credsTag(user string) string {
	if len(user) <= 4 {
		return "…" + user
	}
	return "…" + user[len(user)-4:]
}

// settlingQuotaError reports whether err, the outcome of an attempt on user's
// credential over addrs, is a 486 that our own recent release explains: one of
// those relays — of the ones that answered 486, where the error says which did
// (quotaAnsweredBy): a release on one relay explains nothing about another's
// quota — saw a release of ours go out less than releaseSettleWindow ago and
// holds no orphans of ours. It names that relay and the release's age. An
// orphaned relay is left out on purpose: its 486 is our ghosts, which will not
// be gone in seconds.
func settlingQuotaError(err error, user string, addrs []string, now time.Time) (string, time.Duration, bool) {
	if err == nil || !isQuotaError(err) {
		return "", 0, false
	}
	answers := quotaAnsweredBy(err, addrs)
	allocationBook.Lock()
	defer allocationBook.Unlock()
	for _, answer := range answers {
		addr := answer.addr
		key := relayIdentity{user: user, relay: addr}
		at, ok := allocationBook.releasedAt[key]
		if !ok {
			continue
		}
		// Every worker of the group comes back with an attempt of its own, some
		// long after the 486 in it came in (a fallback can queue for an Allocate
		// slot behind a silent relay), so the first to ask must not take the
		// entry from the rest: it is judged by the 486's own time below, and
		// only swept here once it is as old as an orphan mark gets.
		if now.Sub(at) >= orphanedAllocationLifetime {
			delete(allocationBook.releasedAt, key)
			continue
		}
		// Judged at the moment the relay said 486, not when the attempt ended:
		// another relay's silence can hold the attempt open for eight seconds
		// more, and the window would run out on a 486 that was well inside it.
		// A 486 from before the release is explained by it all the more.
		heard := answer.at
		if heard.IsZero() {
			heard = now
		}
		age := max(heard.Sub(at), 0)
		if age >= releaseSettleWindow {
			continue
		}
		if till, orphaned := allocationBook.orphanedTill[key]; orphaned && now.Before(till) {
			continue
		}
		return addr, age, true
	}
	return "", 0, false
}
