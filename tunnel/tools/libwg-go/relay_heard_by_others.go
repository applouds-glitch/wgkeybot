/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Over TCP a data-plane handshake that fails is first of all the FLOW's failure.
//
// Over UDP a relay that allocates and then carries nothing is a fact about the
// relay, and one failed handshake takes it out of the rotation at once
// (noteServerHandshakeFailure). On the network that needs TCP every connection
// has a fate of its own: half of them hang for seconds beside neighbours to the
// same address that answer in 200ms (field log 19.09). There the same rule ruled
// on relays that were working as it spoke — 193.203.43.23 "out of rotation" with
// four live streams on it — and its stand-down clause is worse: "another server
// completed a handshake during this attempt" is true all the time when flows
// hang at random, so a single hung flow could stand a working relay down for
// five minutes.
//
// So over TCP the verdict needs the relay to have no alibi: if another stream is
// on it right now and hearing it — ready, and heard from within
// dispatchStaleAfter, the dispatcher's own measure — the relay's data plane
// works and the flow is what failed. Nothing is recorded. A relay nobody hears
// gets the verdict as before, so one that allocates and never carries a byte is
// still out after its first handshake. What this gives up: a relay that serves
// its old sessions and fails every NEW one keeps being dialed until the old ones
// go. The same evidence excuses TCP connect/Allocate transport failures, but
// never an explicit TURN refusal or a malformed response.
//
// Over UDP the handshake verdict takes the same alibi (22.10). A flow was
// thought to have no fate of its own there; the Rostelecom mobile network says
// otherwise. Bench of 2026-10-22 (Pixel 6a, Rostelecom on 250-20, UDP chosen in
// the settings, ten streams over four relays): stream 6's new allocation on
// 95.163.34.190 got its permission in 48ms and no reply through it for 8s,
// while stream 2 on the same relay carried the tunnel all along — and the one
// failure took .190 out of the session's rotation and stood it down for five
// minutes. Over TCP the same failure of stream 2 on .190, minutes later, was
// the flow's, and its redial to the same relay went through. A relay nobody on
// it hears still gets the verdict on its first handshake, over UDP as over TCP:
// one that allocates and carries nothing is out as before. The price is the
// TCP one: a relay that serves its old sessions and fails every new one keeps
// being dialed until the old ones go — by the other streams, that is: a stream
// whose handshake has failed flowFailsBeforeAvoid times in a row on one relay
// under this alibi dials that relay last until a session of its own gets
// through (avoidedRelay), the verdict against the relay still withheld. Over
// UDP that is the price this change brought: a stream used to leave such a
// relay at its first failure, and without this one could keep dialing it for
// as long as the old session there lived (codex review). The connect and
// Allocate alibi below (tcpAttemptFailureIsIsolated) stays TCP's: over UDP a
// silent Allocate is one strike of three, not a verdict.
var liveSessions = struct {
	sync.Mutex
	byRelay map[string]map[*stream]struct{}
}{byRelay: map[string]map[*stream]struct{}{}}

// trackLiveSession books s as running a session on addr until the returned func
// is called.
func trackLiveSession(addr string, s *stream) func() {
	liveSessions.Lock()
	set := liveSessions.byRelay[addr]
	if set == nil {
		set = map[*stream]struct{}{}
		liveSessions.byRelay[addr] = set
	}
	set[s] = struct{}{}
	liveSessions.Unlock()

	return func() {
		liveSessions.Lock()
		delete(set, s)
		if len(liveSessions.byRelay[addr]) == 0 {
			delete(liveSessions.byRelay, addr)
		}
		liveSessions.Unlock()
	}
}

// flowFailsBeforeAvoid is how many handshakes in a row a stream fails on one
// relay others hear before it dials that relay last: one is chance — the
// field's redials to the very same relay went through — two are a pattern.
const flowFailsBeforeAvoid = 2

// flowFailRun is a stream's run of handshakes failed on one relay under the
// alibi of the streams hearing it.
type flowFailRun struct {
	relay string
	n     int
}

// noteFlowFailure counts a handshake s failed on relay while others heard it
// and returns how many in a row that makes on relay.
func (s *stream) noteFlowFailure(relay string) int {
	run := &flowFailRun{relay: relay, n: 1}
	if prev := s.flowFails.Load(); prev != nil && prev.relay == relay {
		run.n = prev.n + 1
	}
	s.flowFails.Store(run)
	return run.n
}

// avoidedRelay is the relay s dials last for its run of flow failures there,
// "" if there is none to avoid. notePathProven ends the run.
func (s *stream) avoidedRelay() string {
	if run := s.flowFails.Load(); run != nil && run.n >= flowFailsBeforeAvoid {
		return run.relay
	}
	return ""
}

// relayHeardByOthers reports whether a stream other than except is ready on addr
// and has heard from it within dispatchStaleAfter. A ready stream that has not
// published its clock yet is no witness: only a received packet is.
func relayHeardByOthers(addr string, except *stream, now time.Time) bool {
	liveSessions.Lock()
	defer liveSessions.Unlock()
	for s := range liveSessions.byRelay[addr] {
		if s == except || !s.ready.Load() {
			continue
		}
		if a := s.activity.Load(); a != nil && a.heardAge(now) <= dispatchStaleAfter {
			return true
		}
	}
	return false
}

// tcpAttemptFailureIsIsolated keeps a failed new TCP flow from penalizing a
// relay that another stream is receiving from. Server replies remain meaningful
// even while old allocations work: a full or rejecting server may still carry
// their traffic.
func tcpAttemptFailureIsIsolated(addr string, s *stream, err error) bool {
	if err == nil {
		return false
	}
	if _, ok := turnErrorCode(err); ok {
		return false
	}
	if !isTransportError(err) && !errors.Is(err, io.EOF) &&
		!errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) &&
		!pionTransactionLost(err) {
		return false
	}
	if !relayHeardByOthers(addr, s, time.Now()) {
		return false
	}
	turnLog("[STREAM %d] TCP attempt to %s failed while another stream is receiving; no relay penalty: %v", s.id, addr, err)
	return true
}
