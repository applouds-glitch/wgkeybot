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
	defaultCycleSecs    = 36000
	workerStagger       = 500 * time.Millisecond
	staleCredsThreshold = 8
	quotaThreshold      = 5
	maxRetriesPerCycle  = 5
	minRotationInterval = 120 * time.Second
)

// vkSemaphore limits concurrent VK API credential fetches across all groups.
// A limit of 2 lets pairs of groups fetch in parallel while avoiding
// hammering VK with unbounded concurrent authentication requests.
var vkSemaphore = make(chan struct{}, 2)

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

// WorkerGroup manages seamless credential rotation for one VK link.
//
// Lifecycle per cycle:
//  1. Fetch fresh credentials (serialised via groupFetchMu).
//  2. Kill old batch (credentials ready — minimal gap).
//  3. Start new batch with jittered per-stream stagger (500ms base + 0-200ms jitter).
//  4. Wait for TTL expiry or early-rotation trigger, then repeat.
func WorkerGroup(ctx context.Context, cfg WorkerGroupConfig, streams []*stream) {

	var prevCancel context.CancelFunc
	var prevDoneChs []chan struct{}
	var prevRefreshCh chan struct{}

	var lastUser, lastPass, lastAddr string
	var lastRotationTime time.Time

	killBatch := func() {
		if prevCancel != nil {
			prevCancel()
			for _, ch := range prevDoneChs {
				select {
				case <-ch:
				case <-time.After(3 * time.Second):
				}
			}
			prevCancel = nil
			prevDoneChs = nil
		}
	}
	defer killBatch()

	// prevBatchAlive reports whether at least one worker from the previous batch
	// is still running (its done channel not yet closed). The unchanged-creds
	// optimisation must not be taken when the whole batch has already died — e.g.
	// DPI blocked every stream and all workers hit their retry cap. Skipping the
	// restart then would leave the group idle for the full TTL (up to 10 h) with
	// no live streams instead of retrying at the throttled cooldown rate.
	prevBatchAlive := func() bool {
		for _, ch := range prevDoneChs {
			select {
			case <-ch:
			default:
				return true
			}
		}
		return false
	}

	cycleNumber := 0

	for {
		if ctx.Err() != nil {
			return
		}

		// Doze-mode pause
		if cfg.PauseFlag != nil && atomic.LoadInt32(cfg.PauseFlag) != 0 {
			killBatch()
			turnLog("[GROUP %d] Paused (Doze)", cfg.GroupID)
			for atomic.LoadInt32(cfg.PauseFlag) != 0 {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(1 * time.Second)
			}
			turnLog("[GROUP %d] Resumed", cfg.GroupID)
		}

		// ── Step 1: Fetch credentials ─────────────────────────────────────────
		turnLog("[GROUP %d] Cycle %d: fetching credentials...", cfg.GroupID, cycleNumber)

		select {
		case vkSemaphore <- struct{}{}:
		case <-ctx.Done():
			return
		}
		user, pass, addr, lifetime, err := fetchCredsWithLifetime(ctx, cfg.Link, cfg.GroupID)
		<-vkSemaphore

		if err != nil {
			if ctx.Err() != nil {
				return
			}
			turnLog("[GROUP %d] Credential error: %v — retry in 30s", cfg.GroupID, err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		// Only use VK's lifetime when it is meaningfully above the 2-minute safety
		// margin (2×cacheSafetyMargin = 120s). When lifetime ≤ 120 (includes the
		// common VK lifetime=0 case), fall back to defaultCycleSecs and let the
		// stale-creds early-rotation mechanism trigger the next cycle naturally.
		sleepSecs := defaultCycleSecs
		if lifetime > 120 {
			sleepSecs = lifetime - 120
		}
		cycleDur := time.Duration(sleepSecs) * time.Second

		// Override TURN address if configured
		if cfg.TurnIP != "" {
			_, origPort, _ := net.SplitHostPort(addr)
			if cfg.TurnPort != 0 {
				addr = net.JoinHostPort(cfg.TurnIP, fmt.Sprintf("%d", cfg.TurnPort))
			} else {
				addr = net.JoinHostPort(cfg.TurnIP, origPort)
			}
		} else if cfg.TurnPort != 0 {
			origHost, _, _ := net.SplitHostPort(addr)
			addr = net.JoinHostPort(origHost, fmt.Sprintf("%d", cfg.TurnPort))
		}

		turnLog("[GROUP %d] Credentials OK, TURN=%s, TTL=%ds", cfg.GroupID, addr, sleepSecs)

		// ── Unchanged-creds optimisation ──────────────────────────────────────
		// If creds are identical to the previous cycle and at least one stream
		// from that batch is still alive, skip kill+restart and just wait. If the
		// whole batch has died (prevBatchAlive == false) fall through to a real
		// restart so the group recovers instead of idling for the full TTL.
		if prevCancel != nil && prevBatchAlive() && user == lastUser && pass == lastPass && addr == lastAddr {
			waitSecs := lifetime - int((2 * cacheSafetyMargin).Seconds())
			if waitSecs < 60 {
				// lifetime too close to the safety margin — same fallback as the
				// main sleep path; stale-creds detection will trigger early rotation.
				waitSecs = defaultCycleSecs
			}
			turnLog("[GROUP %d] Credentials unchanged — skipping rotation, waiting %ds",
				cfg.GroupID, waitSecs)
			select {
			case <-time.After(time.Duration(waitSecs) * time.Second):
				turnLog("[GROUP %d] TTL window expired → planned rotation", cfg.GroupID)
			case <-prevRefreshCh:
				turnLog("[GROUP %d] Early rotation signal — restarting despite unchanged creds", cfg.GroupID)
			case <-ctx.Done():
				return
			}
			cycleNumber++
			continue
		}
		lastUser, lastPass, lastAddr = user, pass, addr

		// ── Step 2: Kill old batch ─────────────────────────────────────────────
		killBatch()

		// ── Step 3: Start new batch with jittered per-stream stagger ─────────
		batchCtx, batchCancel := context.WithCancel(ctx)
		refreshCh := make(chan struct{}, 1)
		doneChs := make([]chan struct{}, len(streams))

		var quotaWorkers sync.Map
		var staleWorkers sync.Map

		for i, s := range streams {
			doneCh := make(chan struct{})
			doneChs[i] = doneCh
			stagger := time.Duration(i)*workerStagger + time.Duration(rand.Intn(200))*time.Millisecond

			go func(s *stream, stagger time.Duration, doneCh chan struct{}) {
				defer close(doneCh)

				if stagger > 0 {
					select {
					case <-time.After(stagger):
					case <-batchCtx.Done():
						return
					}
				}

				attempt := 0
				for {
					if batchCtx.Err() != nil {
						return
					}

					err := s.runWithCreds(batchCtx, user, pass, addr, cfg)

					if err == nil {
						if batchCtx.Err() == nil {
							// runWithCreds returned nil but context is still active:
							// the TURN server closed the stream. Rotate immediately.
							select {
							case refreshCh <- struct{}{}:
								turnLog("[WORKER %d] Stream closed by server → rotation", s.id)
							default:
							}
						}
						return
					}

					if batchCtx.Err() != nil {
						return
					}

					errLow := strings.ToLower(err.Error())

					// TURN allocation quota (486): rotate only once quotaThreshold
					// workers report it — a couple of 486s just means the
					// per-credential quota is tight, so stay stable on the streams
					// that did allocate instead of churning. When we do rotate,
					// invalidate the cached credential first so the next cycle
					// fetches a fresh one — a stale cache hit would otherwise hand
					// back the same exhausted credential and quota would recur.
					if strings.Contains(errLow, "quota") ||
						strings.Contains(errLow, "486") ||
						strings.Contains(errLow, "allocation quota reached") {
						quotaWorkers.Store(s.id, true)
						cnt := 0
						quotaWorkers.Range(func(k, v any) bool { cnt++; return true })
						if cnt >= quotaThreshold {
							invalidateGroupCreds(cfg.GroupID)
							select {
							case refreshCh <- struct{}{}:
								turnLog("[GROUP %d] TURN quota on %d workers → invalidate creds + rotation", cfg.GroupID, cnt)
							default:
							}
						}
						return
					}

					// Stale credentials: half the group stale → early rotation.
					// (staleCredsThreshold is a global fallback; we use the
					// smaller of the two so small groups still trigger.)
					if strings.Contains(errLow, "401") ||
						strings.Contains(errLow, "unauthorized") ||
						strings.Contains(errLow, "stale nonce") ||
						strings.Contains(errLow, "allocation mismatch") ||
						strings.Contains(errLow, "attribute not found") ||
						strings.Contains(errLow, "508") ||
						strings.Contains(errLow, "error 29") {
						staleWorkers.Store(s.id, true)
						cnt := 0
						staleWorkers.Range(func(k, v any) bool { cnt++; return true })
						threshold := staleCredsThreshold
						if half := len(streams)/2 + 1; half < threshold {
							threshold = half
						}
						if cnt >= threshold {
							select {
							case refreshCh <- struct{}{}:
								turnLog("[GROUP %d] Stale creds on %d/%d workers → rotation", cfg.GroupID, cnt, len(streams))
							default:
							}
						}
					}

					attempt++
					if attempt > maxRetriesPerCycle {
						turnLog("[WORKER %d] Max retries (%d) exceeded — giving up", s.id, maxRetriesPerCycle)
						return
					}
					exp := uint(attempt - 1)
					if exp > 4 {
						exp = 4
					}
					base := time.Duration(1<<exp) * time.Second // 1,2,4,8,16s
					if base > 30*time.Second {
						base = 30 * time.Second
					}
					retryDelay := base + time.Duration(5+rand.Intn(11))*time.Second
					turnLog("[WORKER %d] Error #%d: %v → retry in %v", s.id, attempt, err, retryDelay)
					select {
					case <-time.After(retryDelay):
					case <-batchCtx.Done():
						return
					}
				}
			}(s, stagger, doneCh)
		}

		prevCancel = batchCancel
		prevDoneChs = doneChs
		prevRefreshCh = refreshCh

		// allWorkersDone watches for the case where every worker in the batch
		// exits (after max retries, persistent errors, etc.). Without this,
		// the group could sit idle until TTL expiry (default 10 h) with no
		// active streams. We signal refreshCh so the group rotates and gets
		// fresh credentials — if the network problem has cleared, streams
		// will recover; if not, the rotation cooldown throttles the rate.
		go func() {
			for _, ch := range doneChs {
				select {
				case <-ch:
				case <-batchCtx.Done():
					return
				}
			}
			select {
			case refreshCh <- struct{}{}:
			default:
			}
		}()

		// ── Step 4: Wait for TTL or early-rotation signal ─────────────────────
		select {
		case <-time.After(cycleDur):
			turnLog("[GROUP %d] TTL expired (%v) → planned rotation", cfg.GroupID, cycleDur)
		case <-refreshCh:
			elapsed := time.Since(lastRotationTime)
			if elapsed < minRotationInterval {
				remaining := minRotationInterval - elapsed
				turnLog("[GROUP %d] Early rotation deferred — cooldown %v remaining", cfg.GroupID, remaining)
				select {
				case <-time.After(remaining):
				case <-ctx.Done():
					return
				}
			}
			turnLog("[GROUP %d] Early rotation", cfg.GroupID)
		case <-ctx.Done():
			return
		}
		lastRotationTime = time.Now()
		cycleNumber++
	}
}
