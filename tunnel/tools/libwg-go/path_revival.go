/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"
)

// A worker backing off from a dark path is woken when the path is back.
//
// On the network TCP is here for, the radio path goes dark for 5-40s at a time
// and takes every socket to every relay with it (field log 17.10, Rostelecom,
// TCP). The workers whose sessions die in it, or whose redials go into it, run
// up a streak — connects timing out, Allocates unanswered, flows the kernel
// gives up, and once the light is back VK resetting every TCP session it held
// through the dark — and back off for up to half a minute (reconnectDelay).
// Nothing cut that wait short but a move to another network or transport, and a
// network that was only dark is neither: the log has "retry in 16s" and "retry
// in 14s" straight after its stalls. Reproduced on 18.10 (Pixel 6a on the same
// operator, the app's traffic cut for 2-8s at a time with 1-4s of light between,
// for 100s): once the light stayed, the tunnel moved again on the streams that
// were up within 0.3s, and the pool of ten was full 21.5s later.
//
// So the first fresh session to carry a round trip through a relay — its relay
// proof, or its DTLS or SRTP handshake — wakes the workers sleeping out a delay
// the dark earned them, and they reconnect at once with the streak cleared, as
// after a move.
//
// Which delays: an ordinary reconnect delay after a failure that every
// connection on a dark path meets alike (pathWideFailure). Not the cooldown
// after a 486 on a credential that is still current, which nothing cuts short
// (wakeable), nor the credential and captcha backoffs, which are not waited out
// here at all. Nor a failure that was a relay's answer — a TURN error, a
// refusal — which the path coming back does not change. A relay stood down for
// its own failures is skipped by the next attempt's order whatever woke it
// (assignRelays), and its stand-down runs on.
//
// Which proofs: over the transport the worker dials with, and made after the
// worker's own session came down if it came up at all, after its attempt began
// if it did not. A stream's own proof wakes only its siblings.
//
// One at a time: a proof wakes every such worker in the same instant, and
// they reconnect at the start's cadence, the first at once (awaitRevivalSlot).
// Over TCP the connects to one relay are spaced anyway (relay_connect_pacing.go),
// but over UDP nothing else would stop nine Allocates leaving together, three to
// each relay through its slots — and a burst is what that network punishes.
// The spacing also keeps a wake-up from costing a credential: a 486 that a full
// quota gives the first woken worker has usually come back, and rotated the
// credential or been held by the breaker (quota_breaker.go), before the next is
// let go — the same as at a start; the worker that drew it sits out its cooldown,
// which no proof cuts. Each attempt's order still steers around a relay the dark
// left crowded with orphaned allocations (orphaned_allocations.go).

// proofWaits holds, per transport, the channel the next proof over it closes.
var proofWaits = struct {
	sync.Mutex
	next [2]chan struct{} // UDP, TCP
}{next: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}

func proofTransport(overTCP bool) int {
	if overTCP {
		return 1
	}
	return 0
}

// nextPathProof returns a channel closed by the next proof over the transport.
func nextPathProof(overTCP bool) <-chan struct{} {
	proofWaits.Lock()
	defer proofWaits.Unlock()
	return proofWaits.next[proofTransport(overTCP)]
}

// notePathProven is called by a transport whose fresh session has just carried
// its first round trip through the relay.
func (s *stream) notePathProven() {
	s.pathProofs.Add(1)
	s.flowFails.Store(nil) // a session of its own got through (relay_heard_by_others.go)
	litPath(s.overTCP.Load())
	i := proofTransport(s.overTCP.Load())
	proofWaits.Lock()
	close(proofWaits.next[i])
	proofWaits.next[i] = make(chan struct{})
	proofWaits.Unlock()
}

// errRelayNeverAnswered and errRelayFlowTimedOut are two of the silences
// pathWideFailure reads: a relay proof unanswered, and a flow the kernel gave
// up (relayTCPUserTimeout).
var (
	errRelayNeverAnswered = errors.New("relay never answered")
	errRelayFlowTimedOut  = errors.New("TCP flow to the relay timed out")
)

// pathWideFailure reports whether a worker's attempt ended in a failure that
// every connection on a dark path meets alike, so that a session getting
// through afterwards takes the blame off it:
//
//   - silence: a connect or a deadline of ours timing out, an Allocate whose
//     retransmissions all went unanswered, a relay proof or a handshake
//     unanswered, a session gone deaf;
//   - a flow torn: reset by the relay (VK resets every TCP session it held
//     through a blackout once the path is back), or given up by the kernel;
//   - a write the phone's own stack refused (localNetworkError).
//
// A relay that answered — any TURN error, a refused connect — is not in it,
// whatever the relay said: the path carried the answer. Nor is any failure not
// recognised here; such a worker sleeps out its delay as before. An attempt
// that raced several relays counts only if every one of them failed this way: a
// single relay answering says the path was there.
func pathWideFailure(err error) bool {
	if err == nil {
		return false
	}
	var race *raceError
	if errors.As(err, &race) {
		for _, a := range race.attempts {
			if !pathWideFailure(a.err) {
				return false
			}
		}
		return len(race.attempts) > 0
	}
	if _, answered := turnErrorCode(err); answered || errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	var dead *deadStreamError
	var netErr net.Error
	switch {
	case localNetworkError(err):
		return true
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, errRelayFlowTimedOut):
		return true
	case errors.As(err, &dead), errors.Is(err, errRelayNeverAnswered):
		return true
	case errors.As(err, &netErr) && netErr.Timeout():
		// A dial's i/o timeout, a deadline of ours, a handshake's context
		// deadline (context.DeadlineExceeded is a net.Error too).
		return true
	}
	return pionTransactionLost(err)
}

// pionTransactionLost reports whether err is pion giving up a TURN transaction
// without an answer: every retransmission unanswered, or one that could not be
// written. Pion v5.0.13 wraps these private sentinels without a net.Error, and
// the failed retransmit discards the socket's own error. Only the unwrapped
// sentinel is matched — not response text, addresses, transaction IDs or
// unrelated protocol errors.
func pionTransactionLost(err error) bool {
	cause := err
	for errors.Unwrap(cause) != nil {
		cause = errors.Unwrap(cause)
	}
	switch cause.Error() {
	case "all retransmissions failed for", "turn: failed to retransmit transaction":
		return true
	}
	return false
}

// revivalPacing spaces the reconnects of the workers a proof has woken.
var revivalPacing struct {
	sync.Mutex
	next time.Time // when the next woken worker may go
}

// revivalGap is the start's cadence (WorkerGroup): workerStagger plus the same
// jitter. A var for the tests, which pin it.
var revivalGap = func() time.Duration {
	return workerStagger + time.Duration(rand.Intn(200))*time.Millisecond
}

// awaitRevivalSlot holds a woken worker until its turn to reconnect, or until
// deadline — the end of the delay it was sleeping out — if that comes first;
// false if ctx ended first. As in awaitRelayConnectSlot, each admission starts a
// fresh gap and waiters recheck under the lock after waking: slots reserved
// ahead would let a process pause release every waiting worker together. A
// worker that goes at its own deadline takes no slot.
func awaitRevivalSlot(ctx context.Context, deadline time.Time) bool {
	p := &revivalPacing
	for {
		p.Lock()
		if ctx.Err() != nil {
			p.Unlock()
			return false
		}
		now := time.Now()
		if !now.Before(p.next) {
			p.next = now.Add(revivalGap())
			p.Unlock()
			return true
		}
		at := p.next
		p.Unlock()

		if !now.Before(deadline) {
			return true
		}
		if deadline.Before(at) {
			at = deadline
		}
		if !waitUntil(ctx, at) {
			return false
		}
	}
}

// While the whole path is dark, a worker that fails into it is parked.
//
// Blackout runs on 18.10 (the same phone and operator, TCP): through a blackout
// that takes the whole path, the workers whose sessions die in it go on
// redialing into it. Every dial times out, each failure grows the streak — the
// backoffs reach 10-19s, which is what the proof above has to cut — and counts
// against a relay that did nothing; and an Allocate that gets through in a
// flicker dies with the next dark, its release written into a dead socket: six
// "release of our allocation … did not go out" in the 17.10 log, each an
// orphaned allocation that holds a seat at its relay and a 486 in waiting.
//
// Dark is what the streams that are still up say (pathLooksDark): one of them
// at least is over TCP with its socket stalled — what it sends is not being
// acknowledged (relay_tcp_watch.go) — and none has heard its relay for
// pathDarkQuiet. Those sockets are the lookout: the kernel goes on
// retransmitting on them at no cost to anyone, and the moment the path carries
// again one of them moves or hears. A dark found holds after the lookout is
// gone, and is found without one too — over UDP, where nothing stalls — by an
// attempt that heard no relay at all; then one parked worker scouts it
// (dark_scout.go).
//
// Who is parked: a worker whose failure was the dark's (pathWideFailure), but
// not a reset. A reset is the relay's packet reaching us, so the light is back:
// under load VK resets every TCP session 5-9s after a blackout of 5s or more,
// even one whose socket has moved again since, when its own retransmissions run
// into its write deadline — and the redial after it goes at once, as before.
//
// Released, the failure uncounted and the streak cleared, one at a time like the
// workers a proof wakes: by a proof; by the path no longer dark — a stream heard
// its relay, or a relay was heard over the transport since the dark was found
// and no scout's attempt is still to tell what it was; by a move to another
// network or transport. While the dark holds, pathDarkParkMax no longer ends a
// park: a relay set that has really died is still dialed, by the scouts.

var (
	pathDarkQuiet   = 2 * time.Second // no relay heard for this long, with a socket stalled, is dark
	pathDarkPoll    = 250 * time.Millisecond
	pathDarkParkMax = 60 * time.Second // a var for the tests
)

// parksInTheDark reports whether a worker whose attempt ended in err is one to
// park while the path is dark: a failure of the dark's that was not a reset. A
// flow the kernel gave up is the dark's even if a write then met the broken pipe
// it leaves behind.
//
// An attempt that raced several relays parks only if none of them reset: one
// relay's reset is the light back, whichever relay's failure came in last. The
// race's own chain carries only its spokesman (raceError.Unwrap), so asked
// through it, a reset followed by a silence parked and a silence followed by a
// reset did not (Codex review, 18.10).
func parksInTheDark(err error) bool {
	if !pathWideFailure(err) {
		return false
	}
	var race *raceError
	if errors.As(err, &race) {
		for _, a := range race.attempts {
			if !parksInTheDark(a.err) {
				return false
			}
		}
		return len(race.attempts) > 0
	}
	if errors.Is(err, errRelayFlowTimedOut) {
		return true
	}
	return !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE)
}

// pathLooksDark reports whether the streams that are up say the path is dark:
// at least one of them is over TCP with its socket stalled, and none has heard
// its relay for pathDarkQuiet. A stream that is up but has published no clock
// yet has heard nothing.
func pathLooksDark(streams []*stream, now time.Time) bool {
	stalled := false
	for _, s := range streams {
		if !s.ready.Load() {
			continue
		}
		if a := s.activity.Load(); a != nil && a.heardAge(now) < pathDarkQuiet {
			return false
		}
		stalled = stalled || (s.overTCP.Load() && s.sendStalled.Load())
	}
	return stalled
}

// activeStreamSet is the stream set of the proxy that is running; nil if none.
func activeStreamSet() []*stream {
	if set := activeStreams.Load(); set != nil {
		return *set
	}
	return nil
}

// parkInTheDark holds a worker whose attempt failed into a dark path until the
// path is back (see above), and reports whether the worker is to stop.
//
// The proof it waits for is the next one from now. The wait attemptOnce took
// at the start of the attempt would also take a proof made earlier in it: a
// sibling getting through in a lit gap of a flapping path, before this
// attempt failed into the next dark — and a park entered just now, the path
// found dark, would end the moment it began (Codex review, 18.10). A proof
// between that finding and the wait taken here is not lost either: the
// lookout below sees the path no longer dark within pathDarkPoll.
func (s *stream) parkInTheDark(ctx context.Context, attempt *attemptHandle, st *workerBackoff) (stop bool) {
	proven := nextPathProof(attempt.overTCP)
	workerWaits(workerWait{stream: s.id, delay: pathDarkParkMax, wakeable: true, revivable: true, parked: true})
	waitInTheDark(s, attempt.overTCP)
	defer stopWaitingInTheDark(s, attempt.overTCP)
	start := time.Now()
	limit := time.NewTimer(pathDarkParkMax)
	defer limit.Stop()
	poll := time.NewTicker(pathDarkPoll)
	defer poll.Stop()

	why := ""
	for why == "" {
		select {
		case <-ctx.Done():
			return true
		case <-attempt.ctx.Done():
			if ctx.Err() != nil {
				return true
			}
			why = "the network or the relay transport changed"
		case <-proven:
			why = "another stream's session got through"
		case <-poll.C:
			now := time.Now()
			if heardWithin(attempt.overTCP, activeStreamSet(), now, pathDarkQuiet) {
				litPath(attempt.overTCP)
				why = "a stream heard its relay"
				break
			}
			if darkReleases(attempt.overTCP, now) {
				why = "the path is no longer dark"
				break
			}
			// Back in line every time: a reset of the dark (a network lost or
			// back, the same handle) empties the line without waking anybody,
			// and a dark found again before this worker looked would leave it
			// waiting outside it for good (Codex review, 18.10).
			waitInTheDark(s, attempt.overTCP)
			if taken, changed := takeDarkScout(s, attempt.overTCP, now); taken {
				if changed {
					turnLog("[WORKER %d] its turn to scout the dark path over %s: dialing it while the others wait",
						s.id, relayTransportLabel(attempt.overTCP))
				}
				st.failStreak = 0
				st.scouting = true
				return false
			}
		case <-limit.C:
			if pathStillDark(attempt.overTCP) || darkScouted(s, attempt.overTCP, time.Now()) {
				// The scouts dial it: nobody else needs to.
				limit.Reset(pathDarkParkMax)
				break
			}
			why = "parked for as long as a park may last"
		}
	}
	// Out of the line before the wait for a slot: a dark found again meanwhile
	// is not to wait on a worker that has already left.
	stopWaitingInTheDark(s, attempt.overTCP)
	if !awaitRevivalSlot(attempt.ctx, time.Now().Add(pathDarkParkMax)) && ctx.Err() != nil {
		return true
	}
	st.failStreak = 0
	turnLog("[WORKER %d] %s — reconnecting after %v parked", s.id, why, time.Since(start).Round(100*time.Millisecond))
	return false
}
