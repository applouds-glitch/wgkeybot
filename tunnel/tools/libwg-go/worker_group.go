/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/stun/v3"
)

const (
	defaultCycleSecs = 36000 // cap for the credential cache TTL (see credentials.go)
	workerStagger    = 500 * time.Millisecond
)

// vkSemaphore limits concurrent VK API credential fetches across all groups.
// A limit of 2 lets pairs of groups fetch in parallel while avoiding
// hammering VK with unbounded concurrent authentication requests.
var vkSemaphore = make(chan struct{}, 2)

// allocSlots bounds concurrent TURN Allocate() handshakes per relay. Without it,
// streams spaced by stagger still pile up because Allocate retransmits for
// ~7.8s (RTO=200ms, 7 attempts) — the first alloc hasn't failed before the 6th
// stream starts, so the server's per-IP path sees a burst and silently drops a
// share of them. Cap 3 keeps the first stream unblocked while smoothing the
// fan-out behind it.
//
// Per relay, not global: the burst being paced is one relay's, and a relay that
// has gone silent holds its slots for the whole 7.8s. With one shared pool three
// Allocates hanging on a dark relay blocked every dial to the relay that was
// answering (see relayHeadStart).
const allocSlotsPerRelay = 3

var allocSlots = struct {
	sync.Mutex
	byRelay map[string]chan struct{}
}{byRelay: map[string]chan struct{}{}}

func allocSlotsFor(addr string) chan struct{} {
	allocSlots.Lock()
	defer allocSlots.Unlock()
	sem := allocSlots.byRelay[addr]
	if sem == nil {
		sem = make(chan struct{}, allocSlotsPerRelay)
		allocSlots.byRelay[addr] = sem
	}
	return sem
}

// allocSlot is one held Allocate slot. It is released by whichever comes
// first — the Allocate returning, or the head start on its relay running out
// (see runWithCreds) — and only once.
type allocSlot struct {
	sem  chan struct{}
	once sync.Once
}

// acquireAllocSlot waits for a free Allocate slot on addr; nil if ctx ends first.
func acquireAllocSlot(ctx context.Context, addr string) *allocSlot {
	sem := allocSlotsFor(addr)
	select {
	case sem <- struct{}{}:
		return &allocSlot{sem: sem}
	case <-ctx.Done():
		return nil
	}
}

func (s *allocSlot) release() {
	if s != nil {
		s.once.Do(func() { <-s.sem })
	}
}

// WorkerGroupConfig — parameters for one stream group (one VK link).
type WorkerGroupConfig struct {
	GroupID  int
	Link     string
	PeerAddr *net.UDPAddr
	UseUDP   bool
	PeerType string
	TurnIP   string
	TurnPort int

	// Set for the length of one attempt (pinTransport): the transport it was
	// registered with, so that its server order and every dial of its race read
	// the same one, whatever the setting does meanwhile.
	transportPinned bool
	pinnedTCP       bool
}

// pinTransport returns cfg for one attempt, tied to the transport it was
// registered with (see beginAttempt).
func (cfg WorkerGroupConfig) pinTransport(overTCP bool) WorkerGroupConfig {
	cfg.transportPinned, cfg.pinnedTCP = true, overTCP
	return cfg
}

// WorkerGroup runs the streams for one VK link using an error-driven, per-worker
// model — no group-level rotation timer, no batch kill/restart.
//
// Credentials are fetched lazily through the shared cache (fetchCreds →
// getCredsCached, single-flight per slot) and kept warm by the cache's own TTL.
// pion/turn refreshes each live TURN allocation internally (Refresh at
// lifetime/2, see internal/client/allocation.go), so a healthy stream never
// needs new credentials — our STUN keepalive is only a NAT keepalive. A worker
// re-fetches (throttled, via refreshGroupCreds) ONLY when its own session fails
// with an auth/quota error, then reconnects itself; healthy sibling streams are
// never torn down.
//
// WorkerGroup blocks until every worker has exited (ctx cancellation) so the
// caller's done-channel / graceful TURN release (deferred relayConn.Close →
// Refresh(lifetime=0) in runWithCreds) semantics are preserved.
func WorkerGroup(ctx context.Context, cfg WorkerGroupConfig, streams []*stream) {
	var wg sync.WaitGroup

	// cumStagger accumulates each stream's start delay so consecutive streams are
	// spaced at least workerStagger (500ms) apart — the jitter is added on top,
	// never subtracted, so the gap never dips below the floor. Stream 0 starts
	// immediately (cumStagger == 0) to keep tunnel-up fast.
	var cumStagger time.Duration
	for _, s := range streams {
		stagger := cumStagger
		cumStagger += workerStagger + time.Duration(rand.Intn(200))*time.Millisecond

		wg.Add(1)
		go func(s *stream, stagger time.Duration) {
			defer wg.Done()
			runWorker(ctx, cfg, s, stagger)
		}(s, stagger)
	}
	wg.Wait()
}

// runWorker drives a single persistent stream: fetch creds → connect → on exit,
// re-fetch creds (only for auth/quota errors) and reconnect. It returns when ctx
// is cancelled, or when a credential failure is one that retrying cannot fix —
// a dead call, or a captcha that lost the solve ladder maxCaptchaFailStreak
// times in a row. Giving up is reported through reportWorkerGaveUp, which
// escalates to a user-visible terminal failure once no worker is left.
//
// UDP streams prefer the elected TURN server (see assignServers). TCP streams
// spread their preferred relays by stream ID (see assignTCPServers). Remaining
// candidates are tried if the preferred relay fails or exceeds its head start.
// failStreak only
// counts consecutive connect failures to drive the retry backoff. A session
// that stayed up for a while (or was closed cleanly by the server) resets the
// streak for a fast retry.
func runWorker(ctx context.Context, cfg WorkerGroupConfig, s *stream, stagger time.Duration) {
	if stagger > 0 {
		select {
		case <-time.After(stagger):
		case <-ctx.Done():
			return
		}
	}

	var st workerBackoff
	credFailStreak := 0 // consecutive credential fetches that failed for any reason
	for {
		// Parked while there is no physical network at all (network_availability.go).
		if !waitForNetwork(ctx) {
			return
		}

		// Fetch credentials via the shared cache. A cache hit is cheap (no VK
		// call); on a miss the per-slot lock single-flights the fetch so the
		// group's workers don't stampede VK.
		select {
		case vkSemaphore <- struct{}{}:
		case <-ctx.Done():
			return
		}
		user, pass, addrs, err := fetchCreds(ctx, cfg.Link, cfg.GroupID)
		<-vkSemaphore
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !isNetworkAvailable() {
				// Offline: not evidence about the credential, and the gate above
				// already parks the retry. Don't let it age the streaks.
				continue
			}

			// A dead call or one that needs a logged-in account cannot be fixed by
			// any number of retries — the startup path already treats both as
			// terminal (see the -2/-4 returns in wgTurnProxyStart). Mid-session they
			// used to fall into the same endless 30s loop as a lost packet.
			if isTerminalCredError(err) {
				reportWorkerGaveUp(s.id, err.Error())
				return
			}

			credFailStreak++
			var wait time.Duration
			switch {
			case errors.Is(err, errCaptchaUnsolved), errors.Is(err, errCaptchaLockout):
				// Either this worker just lost the solve ladder, or another one did
				// and the global lockout is still armed. Both mean the same thing:
				// the captcha gate is not opening. Give up once the session has spent
				// its budget of ladders — including the dialogs they put in front of
				// the user — rather than reopening it for as long as the tunnel is up.
				if captchaFailureStreak() >= maxCaptchaFailStreak {
					reportWorkerGaveUp(s.id, "captcha unsolved")
					return
				}
				// The lockout window (exponential, see bumpCaptchaLockout) is the real
				// pacing here: nothing can succeed before it expires, so sleep it out
				// instead of retrying on a cadence it would only reject again.
				wait = captchaLockoutRemaining() + time.Duration(rand.Intn(5000))*time.Millisecond
				if wait < 5*time.Second {
					wait = 5 * time.Second
				}
			default:
				// Everything else (VK rate limit, HTTP failure, a transient 5xx) is
				// assumed recoverable, so the worker keeps retrying — but on a
				// backoff, not a fixed 30s forever.
				wait = credRetryDelay(credFailStreak)
			}

			turnErrorLog("[WORKER %d] Credential error (streak %d, captcha %d/%d): %v — retry in %v",
				s.id, credFailStreak, captchaFailureStreak(), maxCaptchaFailStreak, err, wait.Round(time.Second))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			continue
		}
		credFailStreak = 0

		// The network can disappear while credentials are being fetched.
		if !isNetworkAvailable() {
			continue
		}

		// Apply optional manual TurnIP/TurnPort override to the fetched list.
		addrs = applyTurnOverride(addrs, cfg)

		if s.attemptOnce(ctx, cfg, user, pass, addrs, &st) {
			return
		}
	}
}

// workerWaits is called as a worker goes into the wait before its next attempt.
// A seam for the tests, which have to know the worker is in that wait and not
// still on its way there.
var workerWaits = func(streamID int, delay time.Duration, wakeable bool) {}

// workerBackoff is what one attempt leaves for the next.
type workerBackoff struct {
	failStreak int
	// The credential that has had its one more try after a 486 beside a relay
	// that never answered (see quotaBesideSilence).
	quotaGraceUsed string
}

// attemptOnce runs one attempt of the worker's loop — the session, and the wait
// before the next one — and reports whether the worker is to stop.
//
// The attempt stays registered (beginAttempt) until the wait is over, not
// just while the session runs: a move to another network or to another relay
// transport recycles it either way, and a worker sitting out a reconnect delay
// is woken by that the same as one in a session — the delay belonged to a path
// that is no longer the one in use.
func (s *stream) attemptOnce(ctx context.Context, cfg WorkerGroupConfig, user, pass string, addrs []string, st *workerBackoff) (stop bool) {
	// TCP spreads preferred relays; UDP keeps the election. Health and
	// orphaned allocations override either preference. Keep the full list
	// for the later retry decision, including relays that recover meanwhile.
	//
	// Registered first: the order below and the dials after it have to follow
	// the transport the attempt is tagged with.
	attempt := beginAttempt(ctx, cfg)
	defer attempt.end()
	attemptCfg := cfg.pinTransport(attempt.overTCP)

	ordered := streamAttemptOrder(user, addrs, s.id, attemptCfg, time.Now())
	attemptHead := ordered[0]

	// The session and its race get a context of their own, ended with them: a
	// racer still hanging in an Allocate counts against its relay only while
	// this is alive (dialOpts.session), and the attempt now outlives the session
	// by the length of the wait below.
	start := time.Now()
	runCtx, endRun := context.WithCancel(attempt.ctx)
	runErr := s.runWithCreds(runCtx, user, pass, ordered, attemptCfg)
	endRun()
	sessionDur := time.Since(start)

	if ctx.Err() != nil {
		return true
	}
	if attempt.moved() {
		// Recycled by a move to another network or relay transport (see
		// network_switch.go): not a failure of anything, so reconnect over the
		// new one at once.
		st.failStreak = 0
		return false
	}
	if !isNetworkAvailable() {
		// Skip per-worker retry delays while offline; the gate above resumes
		// the moment a physical network is back.
		return false
	}

	if runErr == nil {
		// runWithCreds returned nil while the tunnel is still up: the TURN
		// server closed this stream. Reconnect just this worker (racing the
		// servers afresh) after a brief delay, with the backoff reset (avoids
		// a hot loop if the server keeps closing immediately).
		turnLog("[WORKER %d] Stream closed by server → reconnecting", s.id)
		st.failStreak = 0
		select {
		case <-time.After(time.Duration(500+rand.Intn(500)) * time.Millisecond):
		case <-ctx.Done():
			return true
		}
		return false
	}

	// A 486 right after our own release on one of these relays is VK not
	// having processed that release yet, not a full credential: try the same
	// one again shortly, without rotating it or cooling down, and without
	// counting a failure (see releaseSettleWindow).
	if relay, age, ok := settlingQuotaError(runErr, user, ordered, time.Now()); ok {
		wait := releaseSettleRetry()
		turnLog("[WORKER %d] 486 with our release on %s only %v old — VK has not freed it yet, same creds again in %v",
			s.id, relay, age.Round(100*time.Millisecond), wait.Round(100*time.Millisecond))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return true
		}
		return false
	}

	// Auth/quota error → throttled, single-flight credential re-fetch so the
	// next iteration picks up a fresh credential. Healthy siblings untouched.
	// Every other error is transient from this worker's point of view: it
	// reconnects (with backoff) rather than giving up, so a stream always
	// recovers on its own — WireGuard and the sibling streams keep running
	// while just this stream is recreated.
	//
	// One exception, once per credential: a 486 from one relay while another's
	// Allocate ended without a TURN answer is tried again as it is before VK
	// is asked for anything (quotaGraceApplies).
	graced := false
	if quota, silent, ok := quotaGraceApplies(runErr, user, st.quotaGraceUsed, credsReplaced(cfg.GroupID, user)); ok {
		st.quotaGraceUsed = user
		graced = true
		turnLog("[WORKER %d] 486 from %s while %s gave no answer — one more try on the same creds before they are given up",
			s.id, quota, silent)
	}
	if !graced && classifyCredError(runErr) {
		refreshGroupCreds(cfg.GroupID, user)
	}

	// A session that stayed up for a while was healthy; treat its drop as a
	// fresh failure (reset the backoff) rather than as part of a failure
	// streak.
	if sessionDur > 60*time.Second {
		st.failStreak = 0
	} else {
		st.failStreak++
	}

	// A failure on a server the next attempt will not even dial is not a
	// repeat of the same failure: the election (or a stand-down) has just
	// moved this stream to a different host, and that host deserves a first
	// attempt, not the backoff the dead one earned. Without this a stream
	// that failed twice on a dead relay waited 7-17s before trying the
	// working one — most of TunnelManager's 25s connect budget, spent
	// sleeping next to a server that was already known to work.
	retryCandidates := ordered // preserve the UDP election's retry policy
	if relayOverTCP(cfg) {
		retryCandidates = addrs
	}
	if streamAttemptOrder(user, retryCandidates, s.id, cfg, time.Now())[0] != attemptHead {
		st.failStreak = 0
	}

	retryDelay := reconnectDelay(st.failStreak)
	note := ""
	// Whether a move to another network or relay transport ends the wait below:
	// an ordinary reconnect delay was earned on a path that is then no longer
	// the one in use.
	wakeable := true
	// 486 (TURN allocation quota) after a mass teardown — say a host freeze
	// past the relay idle timeout, or a second network drop within ten
	// minutes, where the server-side allocations survive as ghosts still
	// holding the credential's quota — needs a new credential.
	//
	// If this credential has already been replaced — this worker's
	// refreshGroupCreds above force-expired the slot, or a sibling's did, or
	// the new one is already in — the 486 says nothing about the next
	// attempt, which runs on another identity. Retry at once: the first
	// worker back fetches the new credential (the slot lock single-flights
	// it), the rest take it from the cache. The rotation is lazy — nothing
	// fetches until a worker comes back for it — so the long cooldown here
	// only postponed the fetch: on the device on 2026-09-18 the new
	// credential was requested 5.2s after the rotation, the last stream came
	// back 15s after the network did.
	//
	// A 486 on the credential that is still current (the rotation was
	// throttled: it is the one fetched moments ago) gets the long jittered
	// cooldown, so a quota that stays full is not hammered in lockstep.
	if graced {
		// At once, whatever the streak: this is the try the credential is owed.
		retryDelay = reconnectDelay(0)
		note = " (one more try on these creds)"
	} else if isQuotaError(runErr) {
		if credsReplaced(cfg.GroupID, user) {
			st.failStreak = 0
			retryDelay = reconnectDelay(st.failStreak)
			note = " (on replaced creds)"
		} else {
			retryDelay = quotaCooldown()
			// Not cut short by a change of transport: the quota is the
			// credential's on the relay, however the relay is reached.
			wakeable = false
		}
	}
	turnErrorLog("[WORKER %d] Error (streak %d): %v → retry in %v%s", s.id, st.failStreak, runErr, retryDelay, note)
	var recycled <-chan struct{}
	if wakeable {
		recycled = attempt.ctx.Done()
	}
	workerWaits(s.id, retryDelay, wakeable)
	select {
	case <-time.After(retryDelay):
	case <-recycled:
		if ctx.Err() != nil {
			return true
		}
		turnLog("[WORKER %d] the network or the relay transport changed — reconnecting now instead of in %v", s.id, retryDelay)
	case <-ctx.Done():
		return true
	}
	if attempt.moved() {
		st.failStreak = 0
	}
	return false
}

const (
	// maxCaptchaFailStreak is how many captcha solve ladders — each of which can
	// end in a full-screen dialog — the session runs back to back before the
	// workers accept that the gate is not opening and stop. Counted session-wide
	// (see captchaFailureStreak); each failure also widens the global lockout, so
	// the five attempts stretch over ~15 minutes instead of hammering the user.
	maxCaptchaFailStreak = 5
	// credRetryBase is the first backoff after a failed credential fetch, and
	// credRetryMax caps the exponential growth.
	credRetryBase = 30 * time.Second
	credRetryMax  = 5 * time.Minute
)

// credRetryDelay returns the jittered backoff before retrying a credential fetch
// that failed for a recoverable reason: 30s, 1m, 2m, 4m, then 5m. A flat 30s
// forever kept a permanently broken group hitting VK 120 times an hour.
func credRetryDelay(streak int) time.Duration {
	if streak < 1 {
		streak = 1
	}
	d := credRetryBase << uint(min(streak-1, 4))
	if d > credRetryMax {
		d = credRetryMax
	}
	return d + time.Duration(rand.Intn(5000))*time.Millisecond
}

// isTerminalCredError reports whether a credential failure is one that no retry
// can fix: the VK call has ended or the join link is invalid (CALL_UNAVAILABLE),
// or the call refuses anonymous joins (CALL_REQUIRES_AUTH).
func isTerminalCredError(err error) bool {
	return isCallUnavailable(err) || errors.Is(err, errCallRequiresAuth)
}

// reconnectDelay returns the backoff before a worker's next connect attempt.
// Transient TURN allocate failures (a lost UDP packet, a brief server-side
// race) usually clear on a fresh attempt — and the next attempt re-races all
// servers anyway — so the first couple of retries are fast (~0.5-1s) before
// falling back to jittered exponential backoff for a genuinely dead path.
func reconnectDelay(failStreak int) time.Duration {
	if failStreak <= 1 {
		return time.Duration(500+rand.Intn(500)) * time.Millisecond
	}
	exp := uint(failStreak - 1)
	if exp > 4 {
		exp = 4
	}
	base := time.Duration(1<<exp) * time.Second // 2,4,8,16,16s
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	return base + time.Duration(5+rand.Intn(11))*time.Second
}

// isQuotaError reports whether err is specifically a TURN allocation-quota
// rejection (486). Narrower than classifyCredError: only the quota case warrants
// the long quotaCooldown, because the cred IS valid — its allocation slots are
// just full (usually with our own zombie allocations after a mass teardown).
func isQuotaError(err error) bool {
	if code, ok := turnErrorCode(err); ok {
		return code == stun.CodeAllocQuotaReached
	}
	if isTransportError(err) {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "quota")
}

// turnErrorCode extracts the numeric STUN/TURN error code when err carries a
// server error response (pion builds a *stun.TurnError in sendAllocateRequest,
// client.go:441). ok=false for every other error — dial/write failures,
// watchdog, context cancellation.
func turnErrorCode(err error) (stun.ErrorCode, bool) {
	var turnErr *stun.TurnError
	if errors.As(err, &turnErr) {
		return turnErr.ErrorCodeAttr.Code, true
	}
	return 0, false
}

// isTransportError reports whether err is a socket/network-level failure (dial
// refused, EHOSTUNREACH, EPIPE, timeout). Such errors say nothing about the
// credential — and critically, their text carries IPs and ephemeral ports, so
// they must never reach the substring fallbacks below. Field case: an Allocate
// from local port 50819 produced "write udp 10.69.196.227:50819->…: broken
// pipe", whose "508" matched the Insufficient-Capacity pattern and force-expired
// a healthy credential mid-outage.
func isTransportError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var syscallErr syscall.Errno
	return errors.As(err, &syscallErr)
}

// quotaCooldown is the jittered backoff after a 486 on a credential that is still
// current — its rotation was throttled, so the next attempt would run on the same
// full quota. 5-13s spreads the N simultaneously-saturated workers so they don't
// retry in lockstep and re-hit 486. (A 486 on a credential already replaced
// retries at once; see runWorker.)
func quotaCooldown() time.Duration {
	return 5*time.Second + time.Duration(rand.Intn(8001))*time.Millisecond
}

// classifyCredError reports whether err from a TURN session indicates the
// credential should be re-fetched: TURN allocation quota (486) or stale/invalid
// credentials (401/stale nonce/etc.). Other errors (dial failures, watchdog,
// transient drops) are handled by a plain reconnect that keeps the credential.
//
// Classification is code-driven where possible: pion surfaces a server error
// response as *stun.TurnError, so the numeric code is authoritative. Bare
// substring matching on the message is the fallback for errors that never carry
// a code (our own wrappers, non-pion paths) — and it runs only after transport
// errors are excluded, because their addresses/ports collide with the numeric
// patterns (see isTransportError). The surviving numeric patterns are anchored
// on "error " for the same reason.
func classifyCredError(err error) bool {
	if code, ok := turnErrorCode(err); ok {
		switch code {
		case stun.CodeUnauthorized, // 401
			stun.CodeStaleNonce,           // 438
			stun.CodeAllocMismatch,        // 437
			stun.CodeWrongCredentials,     // 441
			stun.CodeAllocQuotaReached,    // 486
			stun.CodeInsufficientCapacity: // 508
			return true
		}
		return false
	}
	if isTransportError(err) {
		return false
	}
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "quota") ||
		strings.Contains(e, "error 486") ||
		strings.Contains(e, "allocation quota reached") ||
		strings.Contains(e, "error 401") ||
		strings.Contains(e, "unauthorized") ||
		strings.Contains(e, "stale nonce") ||
		strings.Contains(e, "allocation mismatch") ||
		strings.Contains(e, "attribute not found") ||
		strings.Contains(e, "error 508") ||
		strings.Contains(e, "error 29")
}

// applyTurnOverride applies the optional manual TurnIP/TurnPort pin to the
// fetched TURN server list. A TurnIP pin replaces the whole list with the single
// pinned server; a bare TurnPort rewrites the port on every server. Returns a
// fresh slice when rewriting — addrs may alias the cached ServerAddrs slice
// (returned by reference on a cache hit), so it must not be mutated in place.
func applyTurnOverride(addrs []string, cfg WorkerGroupConfig) []string {
	if cfg.TurnIP != "" {
		_, origPort, _ := net.SplitHostPort(addrs[0])
		port := origPort
		if cfg.TurnPort != 0 {
			port = fmt.Sprintf("%d", cfg.TurnPort)
		}
		return []string{net.JoinHostPort(cfg.TurnIP, port)}
	}
	if cfg.TurnPort != 0 {
		rewritten := make([]string, len(addrs))
		for i, a := range addrs {
			origHost, _, _ := net.SplitHostPort(a)
			rewritten[i] = net.JoinHostPort(origHost, fmt.Sprintf("%d", cfg.TurnPort))
		}
		return rewritten
	}
	return addrs
}
