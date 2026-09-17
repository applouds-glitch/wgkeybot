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

// allocSemaphore bounds concurrent TURN Allocate() handshakes. Without it,
// streams spaced by stagger still pile up because Allocate retransmits for
// ~7.8s (RTO=200ms, 7 attempts) — the first alloc hasn't failed before the 6th
// stream starts, so the server's per-IP path sees a burst and silently drops a
// share of them. Cap 3 keeps the first stream unblocked while smoothing the
// fan-out behind it.
var allocSemaphore = make(chan struct{}, 3)

// WorkerGroupConfig — parameters for one stream group (one VK link).
type WorkerGroupConfig struct {
	GroupID  int
	Link     string
	PeerAddr *net.UDPAddr
	UseUDP   bool
	PeerType string
	TurnIP   string
	TurnPort int
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

	// The spare identity for this group's slot (credential_spare.go). Not in wg:
	// it holds no allocation, so the drain in wgTurnProxyStop has nothing to wait
	// for, and it leaves on ctx like everything else.
	go runSpareFiller(ctx, cfg, defaultSpareSchedule, func() bool {
		for _, s := range streams {
			if s.ready.Load() {
				return true
			}
		}
		return false
	})

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
// Streams are spread over the relays VK returned: each starts its attempt from
// relay (id + addrShift) mod n (see serversForAttempt). The other relays are
// failover only: runWithCreds dials them just for this attempt, and only after
// the first one errors. A short failed session moves addrShift on by one, so the
// next attempt starts from the next relay; a session that lasted pins the stream
// to the relay that carried it. That per-stream shift is all that is remembered
// about relays. failStreak only counts consecutive connect failures to drive the
// retry backoff. A session that stayed up for a while (or was closed cleanly by
// the server) resets the streak for a fast retry.
func runWorker(ctx context.Context, cfg WorkerGroupConfig, s *stream, stagger time.Duration) {
	if stagger > 0 {
		select {
		case <-time.After(stagger):
		case <-ctx.Done():
			return
		}
	}

	failStreak := 0
	credFailStreak := 0 // consecutive credential fetches that failed for any reason
	for {
		permit, ok := waitForNetworkPermit(ctx, true)
		if !ok {
			return
		}
		if permit.unvalidatedProbe {
			turnLog("[WORKER %d] Controlled probe on unvalidated network", s.id)
		}

		// Fetch credentials via the shared cache. A cache hit is cheap (no VK
		// call); on a miss the per-slot lock single-flights the fetch so the
		// group's workers don't stampede VK.
		select {
		case vkSemaphore <- struct{}{}:
		case <-ctx.Done():
			releaseNetworkPermit(permit)
			return
		}
		user, pass, addrs, err := fetchCreds(ctx, cfg.Link, cfg.GroupID)
		<-vkSemaphore
		if err != nil {
			releaseNetworkPermit(permit)
			if ctx.Err() != nil {
				return
			}
			if !permit.unvalidatedProbe && !isNetworkAvailable() {
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

			var paused interface {
				error
				RetryAt() time.Time
			}
			if errors.As(err, &paused) {
				turnLog("[WORKER %d] %v", s.id, paused)
				select {
				case <-time.After(max(time.Millisecond, time.Until(paused.RetryAt()))):
				case <-ctx.Done():
					return
				}
				continue
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

		// Effective availability can disappear while credentials are being fetched.
		// Re-check before Allocate unless this worker owns the single controlled
		// probe permit. Healthy sessions never pass through this gate.
		if !permit.unvalidatedProbe && !isNetworkAvailable() {
			releaseNetworkPermit(permit)
			continue
		}

		// Apply optional manual TurnIP/TurnPort override to the fetched list.
		addrs = applyTurnOverride(addrs, cfg)

		// This stream's relay order for the attempt. Empty means every relay has
		// already refused this identity with 486: there is nothing to dial, the
		// credential is what has to change.
		vkAddrs := addrs
		addrs = serversForAttempt(vkAddrs, s.id+s.addrShift, user, pass, time.Now())

		start := time.Now()
		var runErr error
		if len(addrs) == 0 {
			runErr = errCredentialSaturated
		} else {
			runErr = s.runWithCreds(ctx, user, pass, addrs, cfg)
		}
		sessionDur := time.Since(start)
		releaseNetworkPermit(permit)

		if ctx.Err() != nil {
			return
		}
		if !isNetworkAvailable() {
			// Skip per-worker retry delays while offline. The gate above resumes on
			// Android validation, fresh TURN proof, or one rate-limited probe permit.
			continue
		}

		if runErr == nil {
			// runWithCreds returned nil while the tunnel is still up: the TURN
			// server closed this stream. Reconnect just this worker after a brief
			// delay, with the backoff reset (avoids a hot loop if the server keeps
			// closing immediately).
			turnLog("[WORKER %d] Stream closed by server → reconnecting", s.id)
			failStreak = 0
			select {
			case <-time.After(time.Duration(500+rand.Intn(500)) * time.Millisecond):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Auth error, or 486 from every relay → throttled, single-flight credential
		// rotation so the next iteration picks up a fresh identity. Healthy
		// siblings untouched. Every other error is transient from this worker's
		// point of view: it reconnects (with backoff) rather than giving up, so a
		// stream always recovers on its own — WireGuard and the sibling streams
		// keep running while just this stream is recreated.
		if isQuotaError(runErr) {
			noteFreshCredentialRefusal(user, pass, vkAddrs, time.Now())
		}
		rotated := false
		if shouldRotateCredentials(runErr, user, pass, vkAddrs, time.Now()) {
			rotated = refreshGroupCreds(cfg.GroupID, user, pass)
		}

		// A session that stayed up for a while was healthy: treat its drop as a
		// fresh failure (reset the backoff) and keep the stream on the relay that
		// carried it. A short one counts towards the streak and moves the stream's
		// next attempt on to the next relay — the whole of the failover policy.
		lasted := sessionDur > 60*time.Second
		if lasted {
			failStreak = 0
		} else {
			failStreak++
		}
		s.noteRelayOutcome(vkAddrs, lasted)

		retryDelay := reconnectDelay(failStreak)
		// 486 (TURN allocation quota) is a special case: a fast retry just hits
		// 486 again before the single-flight rotation can land a fresh credential
		// with a fresh quota. Replace the 0.5-1s retry with a long jittered
		// cooldown: (a) give the refetch time to arrive, (b) spread the N workers
		// that failed at the same instant so they don't hammer the server in
		// lockstep. A rotation that promoted the spare identity — this worker's or
		// a sibling's a moment earlier — has nothing to wait for: the credential is
		// already in the cache, and allocSemaphore paces the reconnects.
		if isQuotaError(runErr) && !rotated && !groupCredentialReplaced(cfg.GroupID, user, pass) {
			retryDelay = quotaCooldown()
		}
		turnErrorLog("[WORKER %d] Error (streak %d): %v → retry in %v", s.id, failStreak, runErr, retryDelay)
		select {
		case <-time.After(retryDelay):
		case <-ctx.Done():
			return
		}
	}
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
// race) usually clear on a fresh attempt — and the next attempt starts from the
// next relay anyway — so the first couple of retries are fast (~0.5-1s) before
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
	var cooled *credentialRelayQuotaError
	if errors.Is(err, errCredentialSaturated) || errors.As(err, &cooled) {
		return true
	}
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

// quotaCooldown is the jittered backoff after a 486. 5-13s gives the single-flight
// refreshGroupCreds time to land a fresh credential (new quota) and spreads the
// N simultaneously-saturated workers so they don't retry in lockstep and re-hit 486.
func quotaCooldown() time.Duration {
	return 5*time.Second + time.Duration(rand.Intn(8001))*time.Millisecond
}

// classifyCredError reports whether err from a TURN session indicates the
// credential should be re-fetched: TURN allocation quota (486) or stale/invalid
// credentials (401/stale nonce/etc.). Other errors (dial failures, watchdog,
// transient drops) are handled by a plain reconnect that keeps the credential.
// Allocation mismatch (437) concerns the transport/allocation, not the identity.
// Missing attributes alone likewise do not establish a credential refusal.
//
// Classification is code-driven where possible: pion surfaces a server error
// response as *stun.TurnError, so the numeric code is authoritative. Bare
// substring matching on the message is the fallback for errors that never carry
// a code (our own wrappers, non-pion paths) — and it runs only after transport
// errors are excluded, because their addresses/ports collide with the numeric
// patterns (see isTransportError). The surviving numeric patterns are anchored
// on "error " for the same reason.
func classifyCredError(err error) bool {
	var reconnect *credentialReconnectError
	if errors.As(err, &reconnect) {
		return true
	}
	if code, ok := turnErrorCode(err); ok {
		switch code {
		case stun.CodeUnauthorized, // 401
			stun.CodeStaleNonce,           // 438
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
		strings.Contains(e, "error 508") ||
		strings.Contains(e, "error 29")
}

// shouldRotateCredentials decides whether a failed attempt has spent the
// identity it ran on.
//
// An authentication refusal from any relay has: the credential is stale
// everywhere. A 486 has not, on its own. VK counts allocations per (identity,
// relay), so the identity is spent only once every relay VK returned has refused
// it; until then the stream still has somewhere to go with the credential it
// holds, and serversForAttempt sends it there. The 2026-09-17 log is the case
// this rule exists for: one relay in quota cooldown, the other timing out under
// a dark uplink, and the pair read as "quota" — a credential with seven hours
// left was thrown away for a trip to VK that the same dark uplink then failed
// twice.
func shouldRotateCredentials(err error, user, pass string, addrs []string, now time.Time) bool {
	if hasAuthRefusal(err) {
		return true
	}
	if isQuotaError(err) {
		return credentialSaturatedEverywhere(user, pass, addrs, now)
	}
	return classifyCredError(err)
}

// hasAuthRefusal reports whether any relay in err's tree answered with a code
// that condemns the credential itself. It walks joined errors as well as
// wrapped ones, because errors.As stops at the first *stun.TurnError it meets
// and an attempt across two relays can carry a 486 next to a 401.
func hasAuthRefusal(err error) bool {
	if err == nil {
		return false
	}
	if turnErr, ok := err.(*stun.TurnError); ok {
		switch turnErr.ErrorCodeAttr.Code {
		case stun.CodeUnauthorized, stun.CodeStaleNonce, stun.CodeWrongCredentials, stun.CodeInsufficientCapacity:
			return true
		}
		return false
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return hasAuthRefusal(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if hasAuthRefusal(e) {
				return true
			}
		}
	}
	return false
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
