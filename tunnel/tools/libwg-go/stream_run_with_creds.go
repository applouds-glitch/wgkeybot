/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"
)

// errDataPlaneHandshake marks the one failure the static assignment used to be
// blind to: Allocate succeeded, so the control plane and the credential are
// fine, and the transport handshake through the relay still never completed.
// Every transport wraps its handshake failure with this so runSession can tell
// it apart from a session that ran and then broke.
var errDataPlaneHandshake = errors.New("data-plane handshake failed")

// sessionVerdict is what a finished session says about the server it ran on.
type sessionVerdict int

const (
	// verdictNone: the session says nothing — we tore it down ourselves, it ended
	// cleanly without lasting long enough to prove anything, or its relay went
	// silent on it before it had (see sessionOutcome).
	verdictNone sessionVerdict = iota
	verdictSuccess
	verdictFailure
	// verdictHandshakeFailure: allocated, then never completed the transport
	// handshake. Acted on immediately rather than through the streak.
	verdictHandshakeFailure
)

func (v sessionVerdict) String() string {
	switch v {
	case verdictSuccess:
		return "success"
	case verdictFailure:
		return "failure"
	case verdictHandshakeFailure:
		return "handshake-failure"
	default:
		return "none"
	}
}

// sessionOutcome grades a finished session for the health accounting in
// turn_server_health.go.
//
// A blackholed allocation is the clearest verdict there is: the control plane
// answered, so the credential and the path are fine, and the host still ate the
// traffic. Otherwise a session that ran for a while proves the server works, and
// a short one that ended in an error counts against it. Teardowns are excluded —
// cancelled means cancelled by us, not by the server.
//
// "Ran" is counted up to the last packet the relay delivered, not to the end of
// the session's existence. The dead-stream detector ends
// a session only after deadStreamTimeout of silence, which is longer than
// healthySessionDuration: a relay that completed the handshake and never
// delivered another packet was booked as a success every time — each round of
// it wiped the strikes the relay had, and lifted a stand-down. The silence at
// the end (counted from the last packet that really arrived, freezes included)
// is taken off before the length is judged.
//
// What is left of such a session, if it is short, is no verdict at all rather
// than a failure. One stream going deaf does not say whose fault it was — its
// allocation, its path, the server behind the relay or the relay — and telling
// them apart takes a witness. While UDP put every stream on the one relay, the
// witness could only be a neighbour there, asked to excuse the death, and three
// deaf streams would have stood the relay down under those still running. Both
// ways of picking the neighbour were tried and dropped on 2026-09-21: any
// neighbour heard lately lets streams that reconnect in turn vouch for one
// another on the strength of their handshakes alone, and only a neighbour with
// traffic since its handshake leaves a healthy relay without witnesses for half
// a minute after every reconnect. A relay that is really gone still earns its
// strikes where the evidence is its own: on the redial, at the Allocate or the
// handshake.
//
// Since 2026-10-10 UDP spreads the streams over the relays (assignRelays), and
// there is a witness to be had on ANOTHER relay: a stream there that has heard
// its own through the whole silence says the path was up. That is weighed apart
// from this grade (relay_deaf.go), and what it leads to is a rest, not a strike:
// in the field logs of 2026-10-20/21 one relay of a pair went deaf under nine
// sessions in a few minutes, its streams redialing it straight back each time,
// and most of those sessions had carried for over a minute before the silence —
// graded here as successes, which wipe a relay's strikes.
//
// A blackhole is graded by what the watchdog ended the session for (hole). The
// relay going silent on the session — ChannelBind, a refresh unanswered — is
// the failure above. The relay answering that it no longer knows this socket
// (blackholeOutOfReach, a 400) is not: it answered within a round trip, and
// what it lost track of is ours to have lost — a mapping the translator forgot
// in a freeze, an allocation that lapsed in one. That is the fact the post-wake
// probe finds too, and its verdict is graded as any deaf session is: by how
// long the relay was heard. So is this one, silent being how long the relay
// had been silent when the session ended. It used to be a failure, whatever
// the session had carried — an hour-long one cut by a 400 at a thaw added a
// strike instead of clearing them, and three thaws stood a working relay down.
func sessionOutcome(cancelled bool, hole blackholeKind, dur, silent time.Duration, err error) sessionVerdict {
	var dead *deadStreamError
	deaf := errors.As(err, &dead)
	if deaf {
		dur -= dead.silent
	}
	switch {
	case cancelled:
		return verdictNone
	case hole == blackholeOutOfReach:
		if !deaf {
			dur -= silent
		}
		if dur >= healthySessionDuration {
			return verdictSuccess
		}
		return verdictNone
	case hole == blackholeRelay:
		return verdictFailure
	case dur >= healthySessionDuration:
		return verdictSuccess
	case errors.Is(err, errDataPlaneHandshake):
		return verdictHandshakeFailure
	case deaf:
		return verdictNone
	case err != nil:
		return verdictFailure
	default:
		return verdictNone
	}
}

// sessionSilence is how long the relay had been silent when the session that
// began at started ended at now — what an out-of-reach end is graded by
// (sessionOutcome); a is the stream's clock. A session whose transport never
// published its own leaves the last session's, older than this one, and that
// grades it as having carried nothing, which is so.
//
// So does a stream's first session, which leaves none. DTLS and SRTP publish
// the clock only after their handshake, and a first handshake frozen past
// healthySessionDuration — the process frozen while connecting — then cut by a
// 400 at the thaw (alloc_check.go) was graded on its whole length: a success,
// which wipes the relay's strikes, for a session that never carried a packet
// (Codex review of the iOS port, 23.10).
func sessionSilence(a *streamActivity, started, now time.Time) time.Duration {
	if a == nil {
		return now.Sub(started)
	}
	return a.heardAge(now)
}

// blackholeKind is what, if anything, the control-plane watchdog (permWatch)
// ended a session for.
type blackholeKind int

const (
	noBlackhole blackholeKind = iota
	// blackholeRelay: the relay went silent on the session — a ChannelBind or
	// a refresh nothing answered.
	blackholeRelay
	// blackholeOutOfReach: the relay answered that it has no allocation for
	// this socket, a 400 on CreatePermission (permWatch.unreachable).
	blackholeOutOfReach
)

// sessionBlackhole is the kind of blackhole perm ended its session for.
//
// Fired first, then the kind: the kind is stored before dead is closed, so a
// watchdog seen fired shows its kind. Asked the other way round, a 400 the
// allocation check latched between the two reads came out as a silent relay
// (Codex review, 23.10). runSession takes it once and grades the session and
// marks its seat (outOfReachSeated) off that one reading.
func sessionBlackhole(perm *permWatch) blackholeKind {
	switch {
	case !perm.fired():
		return noBlackhole
	case perm.unreachable.Load():
		return blackholeOutOfReach
	default:
		return blackholeRelay
	}
}

// winner holds a successfully allocated TURN session from the race in
// runWithCreds. The fields are the live resources handed off to the session:
// runSession owns them and is responsible for closing them.
type winner struct {
	client *turn.Client
	raw    net.Conn       // underlying dialed UDP/TCP conn
	relay  net.PacketConn // relay allocation from client.Allocate()
	addr   string         // TURN server the session runs on
	rtt    time.Duration  // Dial → Allocate latency
	perm   *permWatch     // control-plane blackhole detector for this session
	user   string         // the TURN username it was allocated with
}

// runWithCreds establishes one TURN session with pre-fetched credentials on the
// stream's own server, addrs[0] (see assignRelays). There is no latency
// race: only if that server fails to Allocate are the remaining candidates
// dialed, all at once, and the first of those to complete Allocate takes the
// session while the others are cancelled/closed. The assignment is per attempt,
// so the next reconnect goes back to the stream's own server. Retry and
// credential rotation are managed by the calling WorkerGroup.
//
// With #@wgt:ExtraRelays and an extra at the head, the candidates are raced in
// two stages: the other extras first, and the link's own relays — the reserve
// behind them (relay_extra.go), with whatever the order has behind those — only
// once every extra raced has failed, or none has won relayHeadStart after the
// last step one of them took on the network, or relayReserveCap after they were
// raced at the latest. Raced at once, the link's own won as often as the extras
// did whenever the head failed or was slow, and a session that wins a relay
// keeps it: the weak relay of 2026-11-04 that the extras are there to keep the
// streams off got them back on every failed head (audit, 2026-11-06).
func (s *stream) runWithCreds(ctx context.Context, user, pass string, addrs []string, cfg WorkerGroupConfig) error {
	s.ready.Store(false)
	// Not ready first, so the dispatcher stops adding; then what it had added for
	// the session that just ended goes (see drainOutbound).
	defer func() {
		s.ready.Store(false)
		if n := s.drainOutbound(); n > 0 {
			turnLog("[STREAM %d] dropped %d packet(s) still queued for the session that ended", s.id, n)
		}
	}()

	// raceCtx is cancelled the moment a winner is chosen (or ctx dies) so the
	// losing failover candidates stop dialing / abort their semaphore wait
	// promptly.
	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	var once sync.Once
	winCh := make(chan winner, 1)
	errCh := make(chan relayAttemptError, len(addrs))
	var wg sync.WaitGroup

	// allocating carries the first relay's Allocate slot to the loop below at the
	// moment its request goes out: that is when its head start begins.
	allocating := make(chan *allocSlot, 1)
	// Over TCP the relay can be silent a step earlier, on the connect, and gets a
	// head start for that too.
	connecting := make(chan struct{}, 1)
	// Only for the log line when the head start runs out: whether the first
	// relay had taken the TCP connection by then. Not a phase of the clock — see
	// headStartExpired.
	var headConnected atomic.Bool

	// The extras raced after the head, and the link's own behind them
	// (reserveSplit): extras is raced when the head fails or its head start
	// runs out, behind once the extras have had their chance.
	split := reserveSplit(addrs, reserveRelays(addrs, cfg.ExtraRelays))
	extras, behind := addrs[1:split], addrs[split:]
	// extraSteps carries a step an extra's dial takes on the network — its TCP
	// connect leaving, its Allocate going out — to the loop below: the reserve's
	// wait runs from the extras' steps, not through their queues. Two a dial at
	// most, so a send never blocks.
	extraSteps := make(chan extraStep, 2*len(addrs))

	launch := func(addr string, extra bool) {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			opts := dialOpts{session: ctx}
			switch {
			case addr == addrs[0]:
				opts.allocating = func(slot *allocSlot) { allocating <- slot }
				opts.connecting = func() { connecting <- struct{}{} }
				opts.connected = headConnected.Store
			case extra:
				opts.allocating = func(*allocSlot) { extraSteps <- extraStep{addr, time.Now()} }
				opts.connecting = func() { extraSteps <- extraStep{addr, time.Now()} }
			}
			client, raw, relay, rtt, perm, err := dialAndAllocate(raceCtx, s, user, pass, addr, cfg, opts)
			if err != nil {
				errCh <- relayAttemptError{addr: addr, err: err, at: time.Now()}
				return
			}
			claimed := false
			once.Do(func() {
				claimed = true
				cancelRace()
				winCh <- winner{client: client, raw: raw, relay: relay, addr: addr, rtt: rtt, perm: perm, user: user}
			})
			if !claimed {
				// Another failover candidate got there first: log this
				// server's RTT, then release the surplus allocation
				// (relayConn.Close → Refresh(lifetime=0) deallocates server-side).
				turnLog("[STREAM %d] Failover candidate %s lost rtt=%v (group %d)", s.id, addr, rtt, cfg.GroupID)
				relay.Close()
				client.Close()
				raw.Close()
			}
		}(addr)
	}

	launch(addrs[0], false)
	launchedCount := 1
	fannedOut := len(addrs) == 1 // past the head: the extras raced
	behindRaced := len(behind) == 0
	extrasFailed := 0

	var behindTimer *time.Timer
	var behindDue <-chan time.Time
	var behindCap time.Time
	lastStep := map[string]time.Time{} // the extras raced, by their last step on the network
	extraFailed := map[string]bool{}
	defer func() {
		if behindTimer != nil {
			behindTimer.Stop()
		}
	}()
	// behindAt is when the link's own are raced unless an extra wins first:
	// each extra still in the race has relayReserveStep from its last step, or
	// until behindCap while it has taken none — queued — and the reserve waits
	// for the last of them. Zero once every extra has failed.
	behindAt := func() (at time.Time, queued bool) {
		for _, a := range extras {
			if extraFailed[a] {
				continue
			}
			due := behindCap
			if step, ok := lastStep[a]; ok {
				due = minTime(behindCap, step.Add(relayReserveStep))
			} else {
				queued = true
			}
			if due.After(at) {
				at = due
			}
		}
		return at, queued
	}
	waitBehind := func() {
		if behindTimer != nil {
			behindTimer.Stop()
		}
		at, _ := behindAt()
		behindTimer = time.NewTimer(time.Until(at))
		behindDue = behindTimer.C
	}
	noteStep := func(step extraStep) {
		if step.at.After(lastStep[step.addr]) {
			lastStep[step.addr] = step.at
		}
	}
	raceBehind := func(cause reserveCause) {
		behindRaced = true
		if behindTimer != nil {
			behindTimer.Stop()
		}
		behindDue = nil
		for _, a := range behind {
			launch(a, false)
			launchedCount++
		}
		reserveRaced(s.id, cause)
	}
	// fanOut races what comes after the head: the extras, with the link's own
	// held back behind them — or, with no other extra to race, the link's own
	// at once. It returns the words for the caller's line.
	fanOut := func() string {
		fannedOut = true
		if len(extras) == 0 {
			if len(behind) > 0 {
				raceBehind(reserveAtOnce)
			}
			return fmt.Sprint(behind)
		}
		for _, a := range extras {
			launch(a, true)
			launchedCount++
		}
		if behindRaced {
			return fmt.Sprint(extras)
		}
		behindCap = time.Now().Add(relayReserveCap)
		waitBehind()
		return fmt.Sprintf("%v, the link's own %v behind them", extras, behind)
	}

	var headSlot *allocSlot
	var headStart <-chan time.Time
	var headStartTimer *time.Timer
	defer func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
		}
	}()
	// One clock, restarted per step: the TCP connect (if there is one), then the
	// Allocate. A relay that took its time over the connect has still answered,
	// and its Allocate gets a full head start of its own.
	startHeadStart := func() {
		if headStartTimer != nil {
			headStartTimer.Stop()
		}
		headStartTimer = time.NewTimer(relayHeadStart)
		headStart = headStartTimer.C
	}

	var failed []relayAttemptError
	for {
		select {
		case w := <-winCh:
			return s.runSession(ctx, w, cfg)
		case <-connecting:
			if !fannedOut {
				startHeadStart()
			}
		case headSlot = <-allocating:
			if !fannedOut {
				startHeadStart()
			}
		case <-headStart:
			headStart = nil
			if fannedOut {
				continue
			}
			// Silent, not refused: race the rest now, and let the next worker in
			// this relay's queue start its own clock. The Allocate itself runs
			// on — see relayHeadStart. A TCP connect that is still hanging holds
			// no slot yet; it runs on as well, and is closed if it loses.
			headSlot.release()
			racing := fanOut()
			turnLog("[STREAM %d] %s — racing %s (group %d)",
				s.id, headStartExpired(addrs[0], headSlot != nil, headConnected.Load()), racing, cfg.GroupID)
		case step := <-extraSteps:
			noteStep(step)
			if !behindRaced {
				waitBehind()
			}
		case <-behindDue:
			behindDue = nil
			if behindRaced {
				continue
			}
			// A step already sent counts, though the timer was ready first in
			// this select (Codex, 2026-11-06).
			for drained := false; !drained; {
				select {
				case step := <-extraSteps:
					noteStep(step)
				default:
					drained = true
				}
			}
			at, queued := behindAt()
			if time.Now().Before(at) {
				waitBehind()
				continue
			}
			var why string
			cause := reserveAfterSteps
			switch {
			case queued:
				why, cause = fmt.Sprintf("an extra of %v is still queued %v after they were raced", extras, relayReserveCap), reserveAfterCap
			case !at.Before(behindCap):
				why, cause = fmt.Sprintf("no extra of %v has won %v after they were raced", extras, relayReserveCap), reserveAfterCap
			default:
				why = fmt.Sprintf("no extra of %v has won %v after its last step on the network", extras, relayReserveStep)
			}
			raceBehind(cause)
			turnLog("[STREAM %d] %s — racing the link's own %v (group %d)", s.id, why, behind, cfg.GroupID)
		case attempt := <-errCh:
			failed = append(failed, attempt)
			err := attempt.err
			if !fannedOut {
				// The assigned server failed: try the failover candidates. Say
				// why before moving on — a failover that succeeds swallows this
				// error otherwise (only "all servers failed" ever surfaces it),
				// and an elected server refusing Allocate on every reconnect was
				// invisible in the log except as a second Dial line one RTT later.
				racing := fanOut()
				turnLog("[STREAM %d] %s failed (%v) — fanning out to %s (group %d)",
					s.id, addrs[0], err, racing, cfg.GroupID)
				continue
			}
			if !behindRaced && slices.Contains(extras, attempt.addr) {
				extraFailed[attempt.addr] = true
				if extrasFailed++; extrasFailed == len(extras) {
					raceBehind(reserveAfterFailures)
					turnLog("[STREAM %d] every extra of %v has failed — racing the link's own %v (group %d)",
						s.id, extras, behind, cfg.GroupID)
					continue
				}
				// Its steps no longer hold the reserve back; the queued ones
				// still have their time (Codex, 2026-11-06).
				waitBehind()
			}
			if len(failed) == launchedCount {
				raced := newRaceError(failed)
				if spoke := raced.spokesman(); raced.overrulesLast() {
					turnLog("[STREAM %d] all %d servers failed; acting on what %s answered (%v), not on the last to fail, %s (%v) (group %d)",
						s.id, len(failed), spoke.addr, spoke.err, failed[len(failed)-1].addr, failed[len(failed)-1].err, cfg.GroupID)
				}
				return raced
			}
		case <-ctx.Done():
			cancelRace()
			// A racer may still win after we leave; reap it so the allocation
			// and sockets don't leak.
			go reapRace(&wg, winCh)
			return ctx.Err()
		}
	}
}

// relayAttemptError is one relay's failure within an attempt.
type relayAttemptError struct {
	addr string
	err  error
	at   time.Time // when the relay's answer, or the end of its silence, came in
}

// raceError is an attempt every relay of which failed.
//
// It used to be the last failure to arrive, wrapped — and what arrives last is
// usually what says least. A relay answering 486 does so in one round trip; a
// dark one next to it takes pion's ~7.8s to time out, and its timeout then stood
// for the whole attempt: no credential rotation, no quota backoff, the worker
// back on the same full credential after a plain reconnect delay, for as long
// as the second relay stayed dark. So the attempt speaks through the first
// answer to come in that calls for new credentials (classifyCredError), if
// there is one, and through the last failure as before otherwise. Between two
// such answers the order still decides — a 401 ahead of a 486 is a 401 — but
// both rotate the credential, which is what matters. Only that error is in the chain and in the text — the others'
// text carries addresses and ports that must not reach the substring fallback
// of classifyCredError (see isTransportError) — but each relay's own answer is
// kept for whoever needs to know which one said what (quotaAnsweredBy).
type raceError struct {
	attempts []relayAttemptError // in the order they failed
	speaks   int
}

func newRaceError(attempts []relayAttemptError) *raceError {
	e := &raceError{attempts: attempts, speaks: len(attempts) - 1}
	for i, a := range attempts {
		if classifyCredError(a.err) {
			e.speaks = i
			break
		}
	}
	return e
}

func (e *raceError) spokesman() relayAttemptError { return e.attempts[e.speaks] }

// overrulesLast reports whether the answer that speaks changes what the attempt
// would have been read as: it is not the last failure, and the last failure
// does not call for new credentials itself. Two relays both answering 486 —
// every reconnect onto orphaned quota, ten workers at a time (device, 21.09) —
// read the same either way and are not worth a line each.
func (e *raceError) overrulesLast() bool {
	last := len(e.attempts) - 1
	return e.speaks != last && !classifyCredError(e.attempts[last].err)
}

func (e *raceError) Error() string {
	return fmt.Sprintf("TURN allocate: all %d servers failed: %v", len(e.attempts), e.spokesman().err)
}

func (e *raceError) Unwrap() error { return e.spokesman().err }

// quotaAnswer is one relay's 486 and when it came in; a zero time means the
// error did not say.
type quotaAnswer struct {
	addr string
	at   time.Time
}

// quotaAnsweredBy narrows addrs to the relays that answered err's attempt with
// 486. An error that does not say which relay said what leaves addrs as it is.
func quotaAnsweredBy(err error, addrs []string) []quotaAnswer {
	var out []quotaAnswer
	var raced *raceError
	if !errors.As(err, &raced) {
		for _, addr := range addrs {
			out = append(out, quotaAnswer{addr: addr})
		}
		return out
	}
	for _, a := range raced.attempts {
		if isQuotaError(a.err) && slices.Contains(addrs, a.addr) {
			out = append(out, quotaAnswer{addr: a.addr, at: a.at})
		}
	}
	return out
}

// quotaBesideSilence reports whether err is an attempt in which a 486 speaks
// while another relay's Allocate ended without a TURN answer — a transport
// failure or a timeout, whatever it had answered before that. It names the two.
//
// That attempt asks for new credentials, and new credentials mean a trip to VK,
// which may cost the user a captcha. The relay that did not answer might well
// have on the very same credential: its quota is its own (486 is per credential
// per relay), and the usual reason for the 486 next to it is our own orphans on
// the first relay right after a network drop — exactly when a dial to the second
// is most likely to be lost to the same flaky path. It gets one more try before
// this worker gives the credential up (quotaGraceApplies). A relay that stays
// dark costs that one attempt; it used to cost every attempt until the orphans
// expired, ten minutes.
func quotaBesideSilence(err error) (quota, silent string, ok bool) {
	var raced *raceError
	if !errors.As(err, &raced) || !isQuotaError(raced) {
		return "", "", false
	}
	for _, a := range raced.attempts {
		if _, answered := turnErrorCode(a.err); !answered {
			return raced.spokesman().addr, a.addr, true
		}
	}
	return "", "", false
}

// quotaGraceApplies decides the one more try: once per credential per worker
// (used is the credential that has had it), and not on a credential a sibling
// has already replaced — there the 486 takes its usual fast path to the new
// one, which is in the cache or being fetched already.
func quotaGraceApplies(err error, user, used string, replaced bool) (quota, silent string, ok bool) {
	if user == used || replaced {
		return "", "", false
	}
	return quotaBesideSilence(err)
}

// relayHeadStart is how long the attempt's first relay has to answer Allocate
// before the rest are dialed alongside it; the first to allocate takes the
// session and the others are released.
//
// Until now the others were dialed only after the first had failed, and a relay
// that has gone silent does not fail: pion retransmits for ~7.8s before giving
// up. With three Allocates in flight at a time, nine workers took three such
// rounds — about 25s to move a session to a relay that was answering in 200ms
// (field logs of 2026-09-18: 56 and 23 Allocate timeouts). v1.6.0 raced after
// 400ms; that is below a healthy Allocate on a slow network (two round trips:
// 180-200ms on LTE, 290-410ms on the test Wi-Fi), so it dialed the second relay
// on every ordinary connect and scattered streams across relays. 1.2s leaves a
// healthy relay room for a retransmission or two and still costs a dark one a
// second instead of eight.
//
// The clock starts when this worker's Allocate is actually sent, not while it
// queues for a slot: after a network return every worker dials at once, and a
// healthy relay must not lose the race to its own queue. When the head start
// runs out the hanging Allocate gives up its slot — the next worker in the
// queue can start its own clock — but is not aborted: cutting an Allocate short
// is how ghost allocations were made (a reply still on its way allocates on the
// relay with nobody left to release it). If the relay does answer late, the
// loser path below releases that allocation properly.
const relayHeadStart = 1200 * time.Millisecond

// relayReserveCap is the longest the link's own relays wait behind the extras
// raced after a failed head (runWithCreds) while no extra has taken a step on
// the network — queued for an Allocate slot, or over TCP behind the connects
// already paced to its relay (relay_connect_pacing.go, half a second and more
// apart). The wait runs from the extras' steps so that their queues do not
// hand the race to the link's own, whose queues are empty — nothing else dials
// them; but a queue can be long, and four head starts is three or four
// connects paced to one relay before the reserve is raced anyway.
//
// A var for the tests, which set it out of the way of a slow host or short.
var relayReserveCap = 4 * relayHeadStart

// relayReserveStep is how long the link's own wait after an extra's last step
// on the network: the head start the head had. A var for the tests, as above.
var relayReserveStep = relayHeadStart

// extraStep is a step an extra's dial took on the network, and when.
type extraStep struct {
	addr string
	at   time.Time
}

// reserveCause is why the link's own relays were raced behind the extras.
type reserveCause int

const (
	reserveAtOnce        reserveCause = iota // no other extra to race
	reserveAfterFailures                     // every extra raced failed
	reserveAfterSteps                        // none won relayHeadStart after its last step
	reserveAfterCap                          // relayReserveCap ran out, an extra queued or not
)

// reserveRaced is called as the link's own are raced behind the extras. A seam
// for the tests, which have to know why without timing it.
var reserveRaced = func(stream int, cause reserveCause) {}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// headStartExpired says what the first relay had not done when its head start
// ran out.
//
// Over TCP the clock that starts with the connect keeps running while the dial
// queues for one of the relay's Allocate slots, and is restarted only when the
// Allocate goes out. That is deliberate, though the line used to call it a
// connection the relay "has not accepted": the slots are per relay, and what
// holds them for long is Allocates hanging on that very relay — a first relay's
// gives its slot up when its own head start runs out, a raced one keeps it for
// pion's whole ~7.8s. Busy slots do not prove the relay dark, but a dial still
// without one after relayHeadStart has nothing better to do than try the others
// too; stopping the clock at the end of the connect would leave it queueing
// there with no limit but the context. Over UDP the dial sends nothing before
// its slot, and the clock starts with the Allocate.
//
// connected is read without a snapshot of the select it sits next to: a slot
// granted in the same instant the timer fires can still be reported as a wait.
// It words a log line and decides nothing.
func headStartExpired(relay string, allocating, connected bool) string {
	switch {
	case allocating:
		return fmt.Sprintf("%s has not answered Allocate for %v", relay, relayHeadStart)
	case connected:
		return fmt.Sprintf("%s took the TCP connection, but this dial is still queued for an Allocate slot on it %v after the connect began", relay, relayHeadStart)
	default:
		return fmt.Sprintf("%s has not accepted the TCP connection for %v", relay, relayHeadStart)
	}
}

// dialOpts is what only runWithCreds needs from a dial; the zero value is a
// plain dial.
type dialOpts struct {
	// session is the attempt's own context. A failed Allocate counts against
	// the server while it is alive — even after the race was won elsewhere and
	// ctx cancelled, because Allocate is not cancellable: what it reports is
	// the relay's answer, or its silence. nil means ctx.
	session context.Context
	// allocating is called once the dial holds its Allocate slot, just before
	// the request goes out.
	allocating func(*allocSlot)
	// connecting is called just before a TCP connect to the relay starts. Over
	// UDP there is no such moment: the "dial" sends nothing.
	connecting func()
	// connected is called with true once that connect has succeeded.
	connected func(bool)
}

// dialAndAllocate dials one TURN server and performs the Allocate handshake,
// measuring the Dial→Allocate latency — the network part only, not the time
// spent queued for an Allocate slot, which said nothing about the server and once
// booked a 6s "rtt" against a relay that answered in 230ms (the election ranks
// servers by this number). On any error it closes whatever it opened and
// returns. On success the caller owns client/raw/relay. Uses ctx for
// the dial and the slot wait so a cancelled race aborts promptly.
//
// Each attempt gets its own permWatch, wired into the pion logger factory
// before NewClient so it sees the allocation's whole lifecycle. Losing failover
// candidates simply drop theirs — a permWatch owns no goroutine, so an unwatched
// one costs nothing.
func dialAndAllocate(ctx context.Context, s *stream, user, pass, addr string, cfg WorkerGroupConfig, opts dialOpts) (*turn.Client, net.Conn, net.PacketConn, time.Duration, *permWatch, error) {
	// Decided per dial, not per proxy start — see relayTransportChoice.
	overTCP := relayOverTCP(cfg)
	// Ahead of everything that is timed or logged below: the wait is our own
	// queue, not the relay's silence, so neither the head start nor the rtt may
	// count it (see relay_connect_pacing.go).
	if overTCP && !awaitRelayConnectSlot(ctx, addr) {
		return nil, nil, nil, 0, nil, ctx.Err()
	}
	// The credential's tag says which generation this dial runs on — the one
	// fact the per-stream cache-hit line used to carry.
	if overTCP {
		turnLog("[STREAM %d] Dial TURN %s over TCP (group %d, creds %s)", s.id, addr, cfg.GroupID, credsTag(user))
	} else {
		turnLog("[STREAM %d] Dial TURN %s (group %d, creds %s)", s.id, addr, cfg.GroupID, credsTag(user))
	}
	dialStart := time.Now()
	perm := newPermWatch(s.id)
	// Where the count of relays heard stood when this candidate began to wait on
	// its relay (relay_silence.go): at the connect over TCP, at the Allocate
	// over UDP.
	var heard uint64

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}

	var turnConn net.PacketConn
	var raw net.Conn
	if !overTCP {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN UDP dial: %w", err)
		}
		raw = c
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		if opts.connecting != nil {
			opts.connecting()
		}
		heard = relayHeardMark(true)
		c, err := connectRelayTCP(ctx, dialer, addr)
		if err != nil {
			// Over TCP the connect is the relay's first chance to be silent or to
			// refuse, so it counts against the server on the same terms as a
			// failed Allocate below. A connect that our own race cancelled does
			// not: unlike an Allocate it really is cancelled, and says nothing.
			session := opts.session
			if session == nil {
				session = ctx
			}
			// Nor a local network failure, an isolated TCP flow failure while
			// another stream is receiving from this same relay, or a silence no
			// relay broke (relay_silence.go).
			if session.Err() == nil && ctx.Err() == nil && !relayNotToBlame(err, dialStart) &&
				!tcpAttemptFailureIsIsolated(addr, s, err) && !silenceNotToBlame(err, true, heard, addr) {
				noteServerFailure(addr)
			}
			return nil, nil, nil, 0, nil, fmt.Errorf("TURN TCP dial: %w", err)
		}
		raw = c
		turnConn = turn.NewSTUNConn(c)
		if opts.connected != nil {
			opts.connected(true)
		}
	}
	// Everything the relay's socket delivers is the relay heard (relay_silence.go).
	responses := &allocateResponseConn{PacketConn: relayHeardConn{turnConn, overTCP}, remote: raw.RemoteAddr().String()}

	// This socket is only used for TURN, never STUN Binding discovery. With
	// STUNServerAddr set, pion ends its receive loop on the first datagram from
	// that address that is neither STUN nor ChannelData (client.go HandleInbound:
	// errNonSTUNMessage → "Exiting loop"), and on a connected socket every
	// datagram comes from that address. From then on nothing is read: Allocate
	// replies are lost, and later refreshes and channel binds fail as if the relay
	// had gone dark. With only TURNServerAddr such packets are ignored.
	client, err := newTURNClient(&turn.ClientConfig{
		TURNServerAddr: addr,
		Username:       user,
		Password:       pass,
		Conn:           responses,
		// pion refreshes the peer permission every 120s by default. That is
		// twice as often as it needs to be: the permission's lifetime is a
		// fixed 300s (RFC 8656 section 9), so 240s renews it with a full 60s of
		// margin while halving the radio wake-ups this costs — on mobile each
		// refresh drags the radio into RRC-connected for the tail timer.
		//
		// Since 2026-11-10 these transactions go out in the stream's keepalive
		// burst (refresh_grid.go): pion's timer for them is stopped, and its
		// 240s is the ceiling the grid sends them under — at the ninth tick,
		// 225s — and the backstop's interval when no tick came.
		//
		// Not disabled outright (free-turn-proxy sets 24h) because after the
		// first WriteTo the data path never re-sends CreatePermission —
		// createPermission short-circuits on permStatePermitted
		// (internal/client/udp_conn.go:169) — leaving ChannelBind refresh as
		// the only thing that reinstalls the permission. pion fires that at
		// 300-330s (bindingRefreshInterval 5m, checked every 30s — every 25s
		// tick on the grid, so 300-325s — condition is
		// a strict >, and refreshedAt is stamped after the transaction), i.e.
		// *after* the 300s permission has already lapsed. That would open a
		// ~30s window every 5 minutes in which the relay may drop inbound —
		// too short for the 90s dead-stream detector to catch, so it would
		// surface as unexplained downstream loss rather than a failed stream.
		// bindingRefreshInterval is unexported in ClientConfig, so the window
		// cannot be closed from here.
		//
		// permWatch still sees this class of failure, just at 2x225s instead of
		// 2x120s (~8 min). The faster detectors are unaffected: ChannelBind
		// latches in ~60s and allocation refresh on a single failure.
		PermissionRefreshInterval: 240 * time.Second,
		LoggerFactory:             pionLogFactory{streamID: s.id, watch: perm},
	})
	if err != nil {
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN client: %w", err)
	}

	if err := client.Listen(); err != nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN listen: %w", err)
	}

	dialed := time.Since(dialStart)

	slot := acquireAllocSlot(ctx, addr)
	if slot == nil {
		client.Close()
		raw.Close()
		return nil, nil, nil, 0, nil, ctx.Err()
	}
	if opts.allocating != nil {
		opts.allocating(slot)
	}
	if !overTCP {
		// Over UDP nothing has gone to the relay before this request; over TCP
		// the window opened with the connect, which, accepted, was the relay
		// heard.
		heard = relayHeardMark(false)
	}
	allocStart := time.Now()
	// Counted while it runs, and on success till it is booked live below —
	// never in neither count (relay_return.go).
	allocated := noteAllocating(user, addr)
	relay, err := client.Allocate()
	err = responses.allocationError(err)
	slot.release()
	if err != nil {
		allocated()
		client.Close()
		raw.Close()
		// Only a genuine refusal or silence counts against the server, and only
		// while the attempt itself is alive: a dial during a teardown says
		// nothing about the host. Losing the race does not excuse it — nothing
		// here cancels an Allocate, so a relay that was still silent when
		// another one won has earned the strike (see dialOpts.session).
		//
		// Nor does 486. The quota is per credential on this relay, and what fills
		// it is our own allocations — usually ghosts of sockets that died with
		// the path. The relay answered; the fix is the credential rotation that
		// 486 already triggers (refreshGroupCreds, quotaCooldown), not a
		// five-minute stand-down. Field log 18.09: 91.231.135.87 proved an SRTP
		// session at 09:58:31, a run of 486s on the old credential stood it down
		// at 09:58:40, and the fresh credential eight seconds later had only the
		// relay that never carried a byte left to go to.
		session := opts.session
		if session == nil {
			session = ctx
		}
		//
		// Nor an Allocate the phone's own network failed: a write the local stack
		// refused, or silence while the network was leaving (relayNotToBlame).
		// Over TCP a live sibling also excuses transport failure or silence;
		// explicit TURN refusals keep their existing handling. Nor a silence no
		// relay broke while it lasted (relay_silence.go).
		if session.Err() == nil && !isQuotaError(err) && !isAllocateMismatch(err) && !relayNotToBlame(err, dialStart) &&
			(!overTCP || !tcpAttemptFailureIsIsolated(addr, s, err)) && !silenceNotToBlame(err, overTCP, heard, addr) {
			noteServerFailure(addr)
		}
		return nil, nil, nil, 0, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	// Counted live until closed, so that losing it without a release marks this
	// relay as still holding our quota (orphaned_allocations.go).
	//
	// Beneath it, the allocation's periodic transactions pass from pion's
	// timers to the keepalive grid (refresh_grid.go).
	relay = trackAllocation(refreshOnGrid(relay, s.id), user, addr)
	allocated()
	if overTCP {
		// Outermost, so the deadline is on the socket before the release is
		// written; trackedRelay beneath it books a release that timed out.
		relay = boundRelayClose(relay, raw)
	}

	return client, raw, relay, dialed + time.Since(allocStart), perm, nil
}

// runSession runs the relay session on the connected server and owns its
// lifecycle: it closes the relay, client and underlying conn on exit.
func (s *stream) runSession(ctx context.Context, w winner, cfg WorkerGroupConfig) error {
	defer w.raw.Close()
	defer w.client.Close()
	defer w.relay.Close()

	// Whatever reached the queues while the stream was reconnecting, before any
	// transport starts its writer — runNoDTLS starts it ahead of the relay proof.
	if n := s.drainOutbound(); n > 0 {
		turnLog("[STREAM %d] dropped %d packet(s) queued while the stream was reconnecting", s.id, n)
	}

	// Over TCP the socket is watched for as long as the session runs
	// (relay_tcp_watch.go). Deferred last, so it is let go before anything above
	// closes it.
	if tc := relayTCPConn(w.raw); tc != nil {
		relaySockets.register(s, w.addr, tc)
		defer func() { relaySockets.unregister(tc, time.Now()) }()
	}

	turnLog("[STREAM %d] TURN %s rtt=%v (group %d), relayed address %s", s.id, w.addr, w.rtt, cfg.GroupID, w.relay.LocalAddr())

	// Blackhole watchdog. When permWatch declares the allocation dead, close the
	// relay: that is the one handle all three transports block on, so whichever
	// loop owns this stream unwinds immediately instead of writing into a dead
	// allocation until the 90s no-RX detector eventually notices — or never
	// notices, because a shaped-but-alive path keeps the liveness clock fresh.
	// Closing here also sends Refresh(lifetime=0), releasing the server-side
	// allocation instead of leaving it to eat the credential's quota.
	//
	// The same goes for a TCP flow the kernel has given up (relayTCPUserTimeout).
	// Its one ETIMEDOUT may have gone to pion's read loop, which drops it, and the
	// session would then linger until its next write broke — or, on an idle
	// tunnel, until the dead-stream detector. Over UDP the channel is nil.
	//
	// And for pion's read loop ending on any other error — over TCP, a reset or a
	// close from the far side (permWatch.readerStopped). Nothing can arrive on
	// this session any more, whatever its writes report.
	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()
	go func() {
		select {
		case <-w.perm.deadCh():
			turnLog("[STREAM %d] Recycling allocation after blackhole", s.id)
			w.relay.Close()
		case <-relayFlowGaveUp(w.raw):
			turnLog("[STREAM %d] TCP flow to %s given up by the kernel: no progress for %v — reconnecting",
				s.id, w.addr, relayTCPUserTimeout)
			w.relay.Close()
		case <-w.perm.readerGoneCh():
			turnLog("[STREAM %d] nothing reads from %s any more (%v) — reconnecting",
				s.id, w.addr, w.perm.readerStoppedBy())
			w.relay.Close()
		case <-sessCtx.Done():
		}
	}()

	// The transports report their own handshake success against this address
	// (noteServerHandshakeOK), which is what lets a sibling's success vouch for
	// the uplink when another server fails its handshake in the same window.
	s.serverAddr = w.addr
	s.allocateRTT = w.rtt
	// Whether this session's flow has a fate of its own, and who else is on the
	// relay to vouch for it if its handshake fails (relay_heard_by_others.go).
	s.overTCP.Store(relayFlow(w.raw) != nil)
	defer trackLiveSession(w.addr, s)()

	// For the log line below: which side of the relay a failed data-plane
	// handshake died on (see relayWriteProbe). And for the relay proof of the
	// noDTLS transport, whose window over UDP grows with the time the permission
	// took (relayProofLimit).
	relay := newRelayWriteProbe(w.relay)

	// The allocation check for this session (alloc_check.go): the peer the
	// permission is asked for is the one every transport sends to.
	s.allocCheck.Store(newAllocCheck(s.id, w.client, cfg.PeerAddr, w.perm))
	defer s.allocCheck.Store(nil)

	// And its periodic transactions, for the keepalive loop to send in its
	// burst (refresh_grid.go).
	s.refreshGrid.Store(relayRefreshGrid(w.relay))
	defer s.refreshGrid.Store(nil)

	started := time.Now()
	var err error
	switch cfg.PeerType {
	case "wireguard":
		err = s.runNoDTLS(ctx, relay, cfg.PeerAddr)
	case "srtp":
		err = s.runSRTP(ctx, relay, cfg.PeerAddr)
	default:
		err = s.runDTLS(ctx, relay, cfg.PeerAddr, true)
	}

	// Health accounting for the static assignment (see turn_server_health.go).
	//
	// A TCP flow that timed out is not held against the relay. On the network
	// that needs TCP, flows die one at a time while their neighbours to the very
	// same address carry on (field log 19.09: both relays hit alike, a flow hung
	// next to one answering in 200ms), so the death says nothing about the host —
	// and three of them, young, would stand a working relay down for five
	// minutes. A relay that really is gone earns its strikes on the redial, where
	// the connect or the Allocate fails.
	//
	// The same goes for a flow that ended under pion's reader — reset or closed
	// from the far side. In the field those came singly too (19.09: thirteen,
	// spread over both relays, usually half a minute after the flow had gone
	// deaf, with the neighbours carrying on).
	flowTimedOut := relayFlowTimedOut(w.raw)
	readerErr := w.perm.readerStoppedBy()
	flowEnded := flowTimedOut || (readerErr != nil && relayFlow(w.raw) != nil)
	// How long the relay had been silent when the session ended: what an
	// out-of-reach end is graded by (sessionOutcome, sessionSilence).
	ended := time.Now()
	silent := sessionSilence(s.activity.Load(), started, ended)
	hole := sessionBlackhole(w.perm) // once, for the grade and the seat
	verdict := sessionOutcome(ctx.Err() != nil, hole, ended.Sub(started), silent, err)
	if flowEnded && verdict == verdictFailure {
		verdict = verdictNone
	}
	// And whatever ended with the phone's own network: every session on it dies
	// at that moment, on every relay alike, and a handshake that was under way
	// times out for the same reason (local_network_failure.go).
	if (verdict == verdictFailure || verdict == verdictHandshakeFailure) && relayNotToBlame(err, started) {
		turnLog("[STREAM %d] %s is not held to account for this session: the phone's own network failed under it", s.id, w.addr)
		verdict = verdictNone
	}
	// A handshake failed while another stream on this relay hears it is the
	// flow's failure, over either transport (relay_heard_by_others.go). Weighed
	// after the excuse above: a handshake cut short by the phone's own network
	// is no failure of the flow either, and counted here it sent a working
	// relay to the end of this stream's list after two such sessions (Codex
	// review of the iOS port, 22.10).
	if verdict == verdictHandshakeFailure && relayHeardByOthers(w.addr, s, time.Now()) {
		avoid := ""
		if n := s.noteFlowFailure(w.addr); n == flowFailsBeforeAvoid {
			avoid = fmt.Sprintf("; %d in a row on it for this stream, which dials it last until a session of its own gets through", n)
		}
		turnLog("[STREAM %d] %s handshake: %s — a flow's failure, not the relay's: other streams are hearing it%s",
			s.id, w.addr, relay.describe(time.Now()), avoid)
		verdict = verdictNone
	}
	switch verdict {
	case verdictSuccess:
		noteServerSuccess(w.addr)
	case verdictHandshakeFailure:
		turnLog("[STREAM %d] %s handshake: %s", s.id, w.addr, relay.describe(time.Now()))
		noteServerHandshakeFailure(w.addr, started)
	case verdictFailure:
		noteServerFailure(w.addr)
	}
	// A session the relay no longer knew may have left its allocation seated
	// there (orphaned_allocations.go), read off the same reading of the
	// watchdog as the grade above. Whichever comes first — this, or the close
	// whose release fails (on a 400 the watchdog has usually closed the relay
	// already) — the allocation is counted once (countGhostLocked) and the
	// other only extends its mark.
	if outOfReachSeated(hole, relayFlow(w.raw) != nil, err) {
		noteOutOfReach(w.user, w.addr, trackedAllocation(w.relay), time.Now())
	}
	// A session that went deaf while a stream on another relay kept hearing its
	// own counts toward resting this relay (relay_deaf.go). Not one the
	// blackhole watchdog ended: a silent relay is graded above as the failure it
	// is, and a relay that no longer knew the socket did not go deaf on it.
	if hole == noBlackhole {
		noteDeafSession(s, w.addr, cfg.PeerAddr.String(), ctx.Err() != nil, err, started, time.Now())
	}

	// A blackhole teardown surfaces as "use of closed network connection", which
	// carries no diagnosis and — more importantly — no auth/quota wording for
	// classifyCredError to act on. Restate it with pion's own message so a
	// blackhole that was really a stale credential still rotates the credential.
	// A nil err means the loops exited cleanly, which WorkerGroup would read as
	// "server closed the stream": override it too, this was a failure.
	//
	// The cause is folded in with %s, not %w. classifyCredError is code-driven and
	// bails out early on any error whose chain contains a *net.OpError (see
	// isTransportError), and the relay we just closed ourselves puts exactly that
	// in the chain. Wrapping would therefore route every blackhole down the
	// "transport, not credential" branch and never rotate — which is the whole
	// reason this restatement exists. Flattening to text keeps pion's wording
	// ("error 401: Unauthorized") reachable by the substring fallback; nothing
	// downstream matches on this error's chain.
	if w.perm.fired() {
		if err == nil {
			return fmt.Errorf("TURN blackhole: %s", w.perm.why())
		}
		return fmt.Errorf("TURN blackhole: %s (%s)", w.perm.why(), err)
	}
	// Likewise for a flow the kernel gave up: what the transport returns is the
	// closed relay, or nil if its loops simply wound down — and nil would be read
	// as "the server closed the stream". No credential wording can hide in this
	// one, so the cause is kept in the chain.
	if flowTimedOut {
		if err == nil {
			return fmt.Errorf("%w: no progress for %v", errRelayFlowTimedOut, relayTCPUserTimeout)
		}
		return fmt.Errorf("%w: no progress for %v: %w", errRelayFlowTimedOut, relayTCPUserTimeout, err)
	}
	// And for a reader that stopped: the transport's own error is again only the
	// relay we closed, or nil. The reader's error is a transport error and stays
	// in the chain as one — its text carries addresses and ports, which must not
	// reach the substring fallback of classifyCredError (see isTransportError).
	if readerErr != nil {
		return fmt.Errorf("the relay connection is no longer read: %w", readerErr)
	}
	return err
}

// reapRace drains any late-arriving winner (after the caller has given up on
// ctx cancellation) and closes its resources so they don't leak. winCh holds at
// most one winner (guarded by sync.Once), so a single non-blocking drain after
// all dialers have exited is sufficient.
func reapRace(wg *sync.WaitGroup, winCh chan winner) {
	wg.Wait()
	select {
	case w := <-winCh:
		w.relay.Close()
		w.client.Close()
		w.raw.Close()
	default:
	}
}
