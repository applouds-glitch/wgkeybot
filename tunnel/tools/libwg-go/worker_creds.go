/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"time"
)

// fetchCreds fetches TURN credentials for a specific group via the shared cache.
// groupID selects the correct credential cache slot (groupID * streamsPerCred),
// so all streams in a group share one credential. getCredsCached handles cache
// freshness, single-flight on a miss, and the VK re-fetch when the slot is
// expired or force-expired by refreshGroupCreds. Uses globalGetCreds
// (initialised by wgTurnProxyStart).
func fetchCreds(ctx context.Context, link string, groupID int) (user, pass string, addrs []string, err error) {
	streamID := groupID * streamsPerCredValue()
	u, p, a, e := globalGetCreds(ctx, link, streamID)
	if e != nil {
		err = fmt.Errorf("fetchCreds: %w", e)
		return
	}

	if len(a) == 0 {
		err = fmt.Errorf("fetchCreds: no TURN servers returned")
		return
	}
	if host, _, splitErr := net.SplitHostPort(a[0]); splitErr != nil || host == "" {
		err = fmt.Errorf("fetchCreds: invalid addr %q", a[0])
		return
	}

	user = u
	pass = p
	addrs = a
	return
}

// assignRelays returns the TURN servers a stream should try, its own first, over
// UDP and TCP alike: stream i prefers the (i mod n)-th of the n usable servers,
// so ten streams split 5/5 over the two relays VK hands out, and the rest of the
// list are its failover candidates.
//
// The list is sorted into a canonical order so the same physical server gets the
// same index in every group, regardless of the order VK returned the urls in for
// that group's link. Servers with a verdict against them — demoted for failing a
// data-plane handshake, standing down under a penalty, or resting from a bad
// downlink (relay_rest.go) — are dropped outright rather than demoted to the
// back: runWithCreds fans out to addrs[1:] all at once when the head fails to
// Allocate, so a dead host left anywhere in the list can still win that race and
// cost the stream another session. A healthy session is never moved, except off
// a relay that is being rested.
//
// If every server has a verdict against it the whole list stands. That is an
// outage, not a bad host, and an empty list would leave the stream nothing to
// dial; the next attempts re-probe all of them. Not in canonical order, though:
// outageOrder puts a server that failed only Allocates ahead of one that
// allocated and then failed the data plane, because the latter never fails over,
// and spreads the streams' heads over the servers that carried. A relay that is
// only resting (relay_rest.go) is not in an outage — it carries, it loses a
// little — so the streams spread over the resting relays as over live ones, and
// the outage order is for the demoted and the penalized behind them.
//
// UDP used to route every stream to one elected relay. Spread, the downlink of
// each relay pair carries half the traffic, and when one relay's downlink goes
// bad the judge has the other to compare it with (relay_judge.go) — a single
// relay going bad under every stream looked healthy to every check the session
// had (bench, 2026-10-10).
//
// Returns a fresh slice — addrs may alias the cached ServerAddrs slice (returned
// by reference on a cache hit), so it must not be mutated in place.
func assignRelays(addrs []string, streamID int, now time.Time) []string {
	return assignRelaysAround(addrs, streamID, now, nil, nil, nil, nil)
}

// The tiers of an attempt's order and of a move's pick, dialed first to last
// (assignRelaysAround, moveHead).
const (
	tierClean         = iota // an extra, or a link's own with no extra to lead
	tierLosing               // losing downlink in the window (relay_move.go), or crowded with a seat left (seatedRelays)
	tierReserve              // the link's own behind the extras (relay_extra.go)
	tierReserveLosing        //
	tierFull                 // crowded with the credential's ghosts and no seat left, or at quota
	tierReserveFull          //
	tierCount
)

// relayTier is the tier of a relay by what is held against it: full (crowded
// with the credential's ghosts, or holding its quota at a move) last whatever
// else, since a 486 against it costs a session; the reserve behind the losing
// extras — the link's own in reserve carried nothing, so no window speaks for
// them, and where the extras lose, the link's own from the same server tend to
// lose too (relay_move.go, bench 2026-10-22). A crowded relay with a seat left
// for the credential is not full: it goes with the losing (tierOf).
func relayTier(full, losing, reserve bool) int {
	switch {
	case full && reserve:
		return tierReserveFull
	case full:
		return tierFull
	case reserve && losing:
		return tierReserveLosing
	case reserve:
		return tierReserve
	case losing:
		return tierLosing
	}
	return tierClean
}

// tierOf is relay's tier in an attempt's order: relayTier, with a crowded relay
// that has a seat left for the credential (seated, seatedRelays) taken out of
// the full and put with the losing — behind the clean relays, where the ghosts
// have always put it, and ahead of the link's own in reserve, which a seat on
// an extra is better than (orphaned_allocations.go, "crowded is not full").
func tierOf(relay string, crowded, seated, lossy, reserve map[string]bool) int {
	return relayTier(crowded[relay] && !seated[relay], lossy[relay] || seated[relay], reserve[relay])
}

// assignRelaysAround is assignRelays with the relays in crowded — full of a
// credential's ghosts (orphaned_allocations.go) — put behind the rest, those
// in lossy — losing downlink in the window a session was moved off a rested
// relay in (relay_move.go) — behind the clean ones, ahead of the crowded: a
// window's loss is a moment's evidence, the ghosts hold the relay's quota for
// the allocation lifetime; those in seated — of the crowded, the ones with a
// seat left for the credential (seatedRelays) — with the losing; and those in
// reserve — the link's own relays when the config names extras
// (relay_extra.go) — behind the extras, losing or not, ahead of the crowded
// that have no seat left (relayTier). The streams are spread over each tier,
// rotated among its relays: rotated first and moved after, every crowded relay
// would hand its streams to the relay behind it, the heads of six streams over
// A…F with B C D crowded coming out A E E E E F instead of A E F A E F.
// Periodic-download run 18.10, the dark at 21:30: with one relay crowded and
// two more marked, 5 of the 10 streams came back on one of the three left.
// The outage order takes the crowded whole, a seat left or not, as it did.
func assignRelaysAround(addrs []string, streamID int, now time.Time, crowded, seated, lossy, reserve map[string]bool) []string {
	sorted := append([]string(nil), addrs...)
	sort.Strings(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) < 2 {
		return sorted
	}
	live := make([]string, 0, len(sorted))
	var resting []string // held back by a rest alone (relay_rest.go)
	for _, addr := range sorted {
		switch {
		case relayUsable(addr, now):
			live = append(live, addr)
		case !serverDemoted(addr) && !serverPenalized(addr, now):
			resting = append(resting, addr)
		}
	}
	// Every relay with a verdict against it. The relays merely resting carry —
	// they lose a little — so the streams spread over them as over live ones,
	// and only the demoted and the penalized go in the outage order, behind.
	// Before this, a fresh process with every relay of the config resting
	// (marks kept on disk) had no proof of any of them, and the outage order
	// stood as sorted: all ten streams on the first address by sort, which was
	// the weakest relay of the five, with nothing left to judge it against
	// (Pixel on RTK LTE, 2026-11-04, 0.9 and 0.2 Mbit/s against 2.4 spread).
	fallback := len(live) == 0
	if fallback {
		if len(resting) == 0 {
			return outageOrder(sorted, streamID, crowded)
		}
		live = resting
	}
	var tiers [tierCount][]string
	for _, addr := range live {
		t := tierOf(addr, crowded, seated, lossy, reserve)
		tiers[t] = append(tiers[t], addr)
	}
	out := make([]string, 0, len(sorted))
	for _, tier := range tiers {
		if len(tier) > 0 {
			out = append(out, rotateServers(tier, streamID%len(tier))...)
		}
	}
	if fallback && len(live) < len(sorted) {
		behind := slices.DeleteFunc(slices.Clone(sorted), func(addr string) bool { return slices.Contains(live, addr) })
		out = append(out, outageOrder(behind, streamID, crowded)...)
	}
	return out
}

// relayUsable reports whether addr has no verdict against it: not demoted, not
// penalized, not resting.
func relayUsable(addr string, now time.Time) bool {
	return !serverDemoted(addr) && !serverPenalized(addr, now) && !relayResting(addr, now)
}

// hasOtherUsableRelay reports whether a session on addr, dialed from relays,
// has another usable relay to go to (relay_rest.go).
func hasOtherUsableRelay(relays []string, addr string, now time.Time) bool {
	for _, r := range relays {
		if r != addr && relayUsable(r, now) {
			return true
		}
	}
	return false
}

// streamAttemptOrder is the order an attempt of the stream on user's credential
// dials addrs in: its own relay first (assignRelays), with the relays crowded
// with the credential's ghosts behind the rest, and the link's own behind the
// config's extras (relay_extra.go) — behind a crowded extra too, while the
// credential has a seat left on it (seatedRelays).
func streamAttemptOrder(user string, addrs []string, streamID int, cfg WorkerGroupConfig, now time.Time) []string {
	return streamAttemptOrderAround(user, addrs, streamID, cfg, now, nil)
}

// streamAttemptOrderAround is streamAttemptOrder for the attempt of a stream
// just moved off a rested relay (relay_move.go): the relays losing at the move
// dialed after the others that are not crowded, those the move found full for
// the credential with the crowded — while the attempt is on that credential —
// and the head the move picked first while it is in the first tier. A move
// older than relayMoveLossyFresh is gone by now (takeMove), and the attempt
// orders as any other.
func streamAttemptOrderAround(user string, addrs []string, streamID int, cfg WorkerGroupConfig, now time.Time, move *relayMove) []string {
	var lossy map[string]bool
	if move != nil {
		lossy = move.lossy
	}
	crowded := crowdedRelays(user, addrs, now)
	full := crowded
	if move != nil && move.user == user && len(move.full) > 0 {
		full = make(map[string]bool, len(crowded)+len(move.full))
		for relay := range crowded {
			full[relay] = true
		}
		for relay := range move.full {
			full[relay] = true
		}
	}
	reserve := reserveRelays(addrs, cfg.ExtraRelays)
	// Of the crowded, those with a seat left — by the count as it is now, the
	// Allocates of the streams dialing beside this one in it. Not one the move
	// found full with its picks: that count is the move's.
	seated := seatedRelays(user, crowded, reserve, now)
	if move != nil && move.user == user {
		for relay := range move.full {
			delete(seated, relay)
		}
	}
	order := assignRelaysAround(addrs, streamID, now, full, seated, lossy, reserve)
	if move != nil {
		order = headFirst(order, move.head, full, seated, lossy, reserve, now)
	}
	announceCrowded(user, crowded, order, now) // the ghosts only: a quota is no ghost
	announceSeated(user, seated, reserve, order, now)
	return order
}

// relayLast is order with relay moved to its end, the rest as they were; order
// itself if relay is not in it or is all of it.
func relayLast(order []string, relay string) []string {
	i := slices.Index(order, relay)
	if i < 0 || len(order) < 2 {
		return order
	}
	out := make([]string, 0, len(order))
	out = append(append(out, order[:i]...), order[i+1:]...)
	return append(out, relay)
}

// rotateServers returns list rotated so idx comes first, leaving the rest in
// canonical order behind it as failover candidates.
func rotateServers(list []string, idx int) []string {
	out := make([]string, 0, len(list))
	out = append(out, list[idx:]...)
	out = append(out, list[:idx]...)
	return out
}
