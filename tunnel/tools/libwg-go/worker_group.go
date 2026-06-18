/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultCycleSecs = 36000 // cap for the credential cache TTL (see credentials.go)
	workerStagger    = 500 * time.Millisecond

	// preferredHeadStart is the grace window the preferred server (addrs[0])
	// gets to win the Allocate race alone before runWithCreds fans out to the
	// other servers. Long enough that a healthy preferred usually wins by itself
	// on typical mobile RTT (keeping steady-state at ~1 Allocate/stream), short
	// enough that a dead preferred fails over quickly. Set to 400ms after field
	// logs showed mobile-hotspot RTT spiking to ~315ms, which made a healthy
	// preferred occasionally exceed a 300ms window and fan out unnecessarily.
	preferredHeadStart = 400 * time.Millisecond
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
	GroupID   int
	Link      string
	PeerAddr  *net.UDPAddr
	UseUDP    bool
	PeerType  string
	TurnIP    string
	TurnPort  int
	PauseFlag *int32 // non-nil → check Doze-mode pause
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
// re-fetch creds (only for auth/quota errors) and reconnect. It returns only
// when ctx is cancelled.
//
// The TURN server is no longer chosen by index: runWithCreds races all servers
// (preferred first, see orderPreferred) and the fastest to Allocate wins.
// failStreak now only counts consecutive connect failures to drive the retry
// backoff. A session that stayed up for a while (or was closed cleanly by the
// server) resets the streak for a fast retry.
func runWorker(ctx context.Context, cfg WorkerGroupConfig, s *stream, stagger time.Duration) {
	if stagger > 0 {
		select {
		case <-time.After(stagger):
		case <-ctx.Done():
			return
		}
	}

	failStreak := 0
	for {
		if ctx.Err() != nil {
			return
		}

		// Doze-mode pause: suspend reconnects while the device is dozing.
		if cfg.PauseFlag != nil && atomic.LoadInt32(cfg.PauseFlag) != 0 {
			turnLog("[WORKER %d] Paused (Doze)", s.id)
			for atomic.LoadInt32(cfg.PauseFlag) != 0 {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(1 * time.Second)
			}
			turnLog("[WORKER %d] Resumed", s.id)
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
			turnLog("[WORKER %d] Credential error: %v — retry in 30s", s.id, err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Apply optional manual TurnIP/TurnPort override to the fetched list.
		addrs = applyTurnOverride(addrs, cfg)

		// Put the last race winner (if any) first so it gets the head-start in
		// the Allocate race; runWithCreds still races the rest if it has died.
		addrs = orderPreferred(addrs, cfg.GroupID)

		// The first connection in a group (no winner elected yet) probes all
		// servers at once to pick the fastest; everyone else follows that
		// election and only head-start-races (preferred first, fan out on
		// failure) — so A-vs-B is tested once per group, not on every stream.
		raceAll := !hasPreferred(cfg.GroupID)

		start := time.Now()
		runErr := s.runWithCreds(ctx, user, pass, addrs, cfg, raceAll)
		sessionDur := time.Since(start)

		if ctx.Err() != nil {
			return
		}

		if runErr == nil {
			// runWithCreds returned nil while the tunnel is still up: the TURN
			// server closed this stream. Reconnect just this worker (racing the
			// servers afresh) after a brief delay, with the backoff reset (avoids
			// a hot loop if the server keeps closing immediately).
			turnLog("[WORKER %d] Stream closed by server → reconnecting", s.id)
			failStreak = 0
			select {
			case <-time.After(time.Duration(500+rand.Intn(500)) * time.Millisecond):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Auth/quota error → throttled, single-flight credential re-fetch so the
		// next iteration picks up a fresh credential. Healthy siblings untouched.
		// Every other error is transient from this worker's point of view: it
		// reconnects (with backoff) rather than giving up, so a stream always
		// recovers on its own — WireGuard and the sibling streams keep running
		// while just this stream is recreated.
		if classifyCredError(runErr) {
			refreshGroupCreds(cfg.GroupID)
		}

		// A session that stayed up for a while was healthy; treat its drop as a
		// fresh failure (reset the backoff) rather than as part of a failure
		// streak.
		if sessionDur > 60*time.Second {
			failStreak = 0
		} else {
			failStreak++
		}

		retryDelay := reconnectDelay(failStreak)
		turnLog("[WORKER %d] Error (streak %d): %v → retry in %v", s.id, failStreak, runErr, retryDelay)
		select {
		case <-time.After(retryDelay):
		case <-ctx.Done():
			return
		}
	}
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

// classifyCredError reports whether err from a TURN session indicates the
// credential should be re-fetched: TURN allocation quota (486) or stale/invalid
// credentials (401/stale nonce/etc.). Other errors (dial failures, watchdog,
// transient drops) are handled by a plain reconnect that keeps the credential.
func classifyCredError(err error) bool {
	e := strings.ToLower(err.Error())
	return strings.Contains(e, "quota") ||
		strings.Contains(e, "486") ||
		strings.Contains(e, "allocation quota reached") ||
		strings.Contains(e, "401") ||
		strings.Contains(e, "unauthorized") ||
		strings.Contains(e, "stale nonce") ||
		strings.Contains(e, "allocation mismatch") ||
		strings.Contains(e, "attribute not found") ||
		strings.Contains(e, "508") ||
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
