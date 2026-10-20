/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// A relay is not held to account for a silence the whole path shared.
//
// Periodic-download run on 18.10 (Pixel 6a, Rostelecom on Tele2's 3G, TCP):
// twice in an hour the modem went after an LTE cell that carried nothing, and
// the path was dark for about two minutes with Android none the wiser — the
// network CONNECTED and VALIDATED throughout, the same address, no switch.
// Every flow was given up after relayTCPUserTimeout, the lookout of
// path_revival.go went with them, and the workers redialled into the dark: every
// connect to every relay timed out, and each timeout struck its relay.
// serverFailCoalesce only slowed that down — 30s into the redials all six relays
// VK had given us were stood down for five minutes, re-armed every ten seconds
// until the light came back. With every relay stood down assignRelays falls back
// to outageOrder: once the path was back, 8 of the 10 streams came up on one
// relay, and 13 minutes later they were still on it.
//
// So a failure that was only silence (silentFailure) counts against its relay
// only if some relay was heard over the same transport while it was failing: a
// TCP connect accepted or refused, or anything read from a relay's socket — a
// TURN answer, a challenge or a refusal included, or data. A relay that is down while others
// answer is still struck; so is one that accepted the connect and then never
// answered the Allocate, the connect being the relay heard
// (TestSilentTCPAllocateAloneStillCounts). With nothing heard the silence is
// the path's or the relay's and nothing tells which, so it is not counted: an
// attempt that raced the other relays and heard none of them either, a stream
// alone on a dead relay. If every relay really has gone, standing them all down
// changes nothing anyway — the whole list comes back (assignRelays).
//
// Heard is counted per transport, the dark of one says nothing about the
// other's, and as a sequence rather than a clock: an attempt notes where the
// count stood when it began and asks, when it fails, whether it has moved.
//
// VK's own API calls keep relayNotToBlame alone (vk_calls.go): their silence is
// VK's or a filter's in front of it, and the legacy chain is the fallback.

// relayHeard counts, per transport (proofTransport), the times a relay was
// heard; relayHeardAt is when it last was, on the monotonic clock since
// relayHeardBase (0: never), for how long the path has been silent
// (pathSilence).
var (
	relayHeard     [2]atomic.Uint64
	relayHeardAt   [2]atomic.Int64
	relayHeardBase = time.Now()
)

// noteRelayHeard records a relay heard over the transport.
func noteRelayHeard(overTCP bool) {
	i := proofTransport(overTCP)
	relayHeard[i].Add(1)
	relayHeardAt[i].Store(int64(time.Since(relayHeardBase)))
}

// sinceRelayHeard is how long ago a relay was last heard over the transport,
// 0 if one never was.
func sinceRelayHeard(overTCP bool, now time.Time) time.Duration {
	at := relayHeardAt[proofTransport(overTCP)].Load()
	if at == 0 {
		return 0
	}
	return now.Sub(relayHeardBase) - time.Duration(at)
}

// relayHeardMark is where the count over the transport stands now.
func relayHeardMark(overTCP bool) uint64 {
	return relayHeard[proofTransport(overTCP)].Load()
}

// silentFailure reports whether err is a failure in which nothing came back
// from the relay: a connect or a deadline of ours timing out, a TURN
// transaction pion gave up (every retransmission unanswered, or one it could not
// write — an ICMP refusal behind that is the relay heard, see relayHeardConn), a
// relay proof unanswered, a flow the kernel gave up — even if a write then met
// the broken pipe it leaves behind. Not a reset or a broken pipe of any other kind (the
// relay's packet, or what one leaves), not a refusal or any TURN answer, and not
// a failure it does not recognise: pathWideFailure's silences, without its
// torn flows.
func silentFailure(err error) bool {
	if err == nil {
		return false
	}
	if _, answered := turnErrorCode(err); answered || errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	if errors.Is(err, errRelayFlowTimedOut) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return false
	}
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, errRelayNeverAnswered):
		return true
	case errors.As(err, &netErr) && netErr.Timeout():
		return true
	}
	return pionTransactionLost(err)
}

// silenceNotToBlame reports whether an attempt over the transport, begun when
// its count stood at mark and ended in err, failed in a silence no relay broke
// meanwhile, and says so once in a while.
func silenceNotToBlame(err error, overTCP bool, mark uint64, addr string) bool {
	if !silentFailure(err) || relayHeardMark(overTCP) != mark {
		return false
	}
	logSilenceExcused(overTCP, addr, err)
	return true
}

// A dark path fails every attempt to every relay: one line per transport every
// silenceLogEvery, not one per attempt.
const silenceLogEvery = 30 * time.Second

// silenceLogged holds, per transport, when the line last went out, on the
// monotonic clock since silenceLogBase: a wall clock stepped back by the network
// would keep it quiet, and it is the one trace an excuse leaves.
var (
	silenceLogBase = time.Now()
	silenceLogged  [2]atomic.Int64
)

func logSilenceExcused(overTCP bool, addr string, err error) {
	i := proofTransport(overTCP)
	now := int64(time.Since(silenceLogBase))
	last := silenceLogged[i].Load()
	if (last != 0 && now-last < int64(silenceLogEvery)) || !silenceLogged[i].CompareAndSwap(last, now) {
		return
	}
	transport := "UDP"
	if overTCP {
		transport = "TCP"
	}
	turnLog("[TURN HEALTH] %s: %v — no relay heard over %s while it failed: a silence the whole path shares is held against no relay (logged once per %v)",
		addr, err, transport, silenceLogEvery)
}

// relayHeardConn counts every read from a relay's socket as the relay heard,
// and an ICMP refusal reported on a read or a write as well: it crossed the
// path, which is lit. pion drops the errno on the way (a failed retransmit
// becomes "turn: failed to retransmit transaction", its read loop just ends), so
// an Allocate refused this way would otherwise read as silence — and a relay
// whose port is closed would never be stood down (Codex review, 18.10).
type relayHeardConn struct {
	net.PacketConn
	overTCP bool
}

func (c relayHeardConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		noteRelayHeard(c.overTCP)
	}
	return n, addr, err
}

func (c relayHeardConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if errors.Is(err, syscall.ECONNREFUSED) {
		noteRelayHeard(c.overTCP)
	}
	return n, err
}
