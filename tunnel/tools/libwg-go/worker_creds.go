/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
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

// serversForAttempt orders VK's relay list for one connect attempt of one
// stream: the list rotated by start, minus the relays that have already
// answered this identity with 486 (see noteCredentialRelayQuota). The first
// entry is dialed; runWithCreds falls over to the rest only if its Allocate
// fails.
//
// start is the stream's id plus its own failure shift (stream.addrShift), so
// the streams of a group spread evenly over the relays. That spread is the
// point, not a throughput trick: VK counts its ten-allocation quota per
// (identity, relay), so ten streams on two relays sit at five of ten on each.
// A recycled stream whose old allocation lingers as a ghost still fits, and so
// does a whole group reconnecting after an uplink outage that turned all ten
// into ghosts. With every stream on the first relay the group ran at ten of
// ten, and any reconnect that could not confirm its deallocate was a 486.
//
// Nothing here remembers how a relay behaved. This used to be a health ledger
// (strikes, penalties, demotions, sibling proof — five rewrites between
// 2026-06-18 and 2026-09-16), and every rule in it was a way for an uplink
// outage to leave a scar: in the 2026-09-17 log a dark uplink demoted the one
// relay the credential still had quota on, for the rest of the connection. A
// stream that fails on a relay simply starts its next attempt from the next
// one (see runWorker); a bad relay costs each of its streams one short attempt.
//
// An empty result means every relay has refused this identity: the credential
// is spent and the caller rotates it without dialing. The cached address slice
// is never modified.
func serversForAttempt(addrs []string, start int, user, pass string, now time.Time) []string {
	n := len(addrs)
	if n == 0 {
		return nil
	}
	start = ((start % n) + n) % n
	order := make([]string, 0, n)
	for i := 0; i < n; i++ {
		addr := addrs[(start+i)%n]
		if credentialRelaySaturated(user, pass, addr, now) {
			continue
		}
		order = append(order, addr)
	}
	return order
}

// noteRelayOutcome is the whole of this client's relay failover policy. A
// session that lasted pins the stream to the relay that carried it, so a
// reconnect hours later goes back to what worked; a short one moves the next
// attempt on to the next relay. The shift is per stream and says nothing about
// the relay to anyone else: two streams can disagree about a relay, and an
// uplink outage, which fails every attempt alike, only walks each stream round
// the list and back.
func (s *stream) noteRelayOutcome(vkAddrs []string, lasted bool) {
	if !lasted {
		s.addrShift++
		return
	}
	if i := addrIndex(vkAddrs, s.serverAddr); i >= 0 {
		s.addrShift = i - s.id
	}
}

// addrIndex returns addr's position in addrs, or -1.
func addrIndex(addrs []string, addr string) int {
	for i, a := range addrs {
		if a == addr {
			return i
		}
	}
	return -1
}
