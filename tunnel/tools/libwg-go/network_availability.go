/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"time"
)

// transportPathProofTTL keeps reconnects enabled long enough for a stream to
// reach the 90s dead threshold and still have a full reconnect window. Healthy
// streams renew the proof on every validated RX, so working networks that
// Android never marks VALIDATED remain usable indefinitely. On a real outage
// the proof expires and the gate stops further credential/Allocate churn.
const transportPathProofTTL = 3 * time.Minute

// unvalidatedProbeInterval prevents a circular wait after a real outage on a
// network that never gains Android validation. One worker may probe; success
// renews transport proof and releases all siblings, failure leaves them parked.
const unvalidatedProbeInterval = time.Minute

// networkAvailability gates only new TURN connection work. Android validation
// and observed TURN reachability are deliberately separate signals: either one
// may open the gate. Existing relay sessions never wait here.
//
// Both are overridden by a third: whether there is a physical network at all
// (see setPhysicalPath). It is stored as "absent" so that its zero value — like
// androidValidated's default — leaves the gate alone on hosts that never report
// it.
//
// androidValidated defaults to true for hosts that do not publish Android
// connectivity state (iOS, Windows and tests).
var networkAvailability = struct {
	sync.Mutex
	physicalPathAbsent   bool
	androidValidated     bool
	transportProvenUntil time.Time
	transportGeneration  uint64
	nextUnvalidatedProbe time.Time
	unvalidatedProbeBusy bool
	unvalidatedProbeID   uint64
	becameAvailable      chan struct{}
}{
	androidValidated: true,
	becameAvailable:  make(chan struct{}),
}

func networkAvailableLocked(now time.Time) bool {
	if networkAvailability.physicalPathAbsent {
		return false
	}
	return networkAvailability.androidValidated || now.Before(networkAvailability.transportProvenUntil)
}

func signalNetworkWaitersLocked() {
	close(networkAvailability.becameAvailable)
	networkAvailability.becameAvailable = make(chan struct{})
}

// setNetworkAvailable updates Android's NET_CAPABILITY_VALIDATED signal. A
// false value does not erase fresh proof obtained from the TURN transport.
func setNetworkAvailable(validated bool) {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	now := time.Now()
	wasAvailable := networkAvailableLocked(now)
	networkAvailability.androidValidated = validated
	if validated {
		networkAvailability.nextUnvalidatedProbe = time.Time{}
		networkAvailability.unvalidatedProbeBusy = false
		networkAvailability.unvalidatedProbeID++
	}
	if !wasAvailable && networkAvailableLocked(now) {
		signalNetworkWaitersLocked()
	}
}

// setPhysicalPath records whether Android has any physical network at all — the
// one fact neither of the other signals can express. It reports whether anything
// changed.
//
// Without it, losing every network left the gate open for as long as the last
// transport proof lived (up to transportPathProofTTL): workers kept dialing a
// route that did not exist, a fresh ENETUNREACH every half second per stream, and
// every failure aged a backoff streak over a network that was not even there. An
// absent path therefore closes the gate outright — over Android validation, over
// proof, and over the unvalidated probe, since with no route a probe cannot learn
// anything either.
//
// Losing the path also discards transport proof: it was earned on the network
// that just vanished and says nothing about the next one — otherwise a handover
// through "no network" let the old proof wave every parked worker onto the new
// network at once. The generation is deliberately left alone. If the same
// network comes straight back, the live streams of this very session renew the
// proof with their next accepted packet; bumping the generation would orphan
// that proof, and on a network Android never validates, proof is the only thing
// that reopens the gate for the rest of the workers.
//
// A returning path wakes every parked worker unconditionally, even while the
// gate stays closed: during the absence they waited with no probe timer at all,
// so without this nobody would claim the probe on a network Android does not
// validate, and the session would stay parked for good. The probe schedule is
// reset for the same reason — a path that has just appeared is exactly when one
// probe is worth spending.
//
// Reports that change nothing are no-ops. The Android side pushes on every path
// change, re-addressing of a network that never went away included, and that
// must not keep resetting the probe rate limit.
func setPhysicalPath(present bool) bool {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	if networkAvailability.physicalPathAbsent == !present {
		return false
	}
	networkAvailability.physicalPathAbsent = !present
	if !present {
		networkAvailability.transportProvenUntil = time.Time{}
		return true
	}
	networkAvailability.nextUnvalidatedProbe = time.Time{}
	networkAvailability.unvalidatedProbeBusy = false
	networkAvailability.unvalidatedProbeID++
	signalNetworkWaitersLocked()
	return true
}

// markNetworkPathProven records real TURN reachability for the current proxy
// generation. Callers must only invoke it after an authenticated transport
// handshake or a packet accepted by the strict RX path.
func markNetworkPathProven(generation uint64) {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	if generation != networkAvailability.transportGeneration {
		return
	}
	now := time.Now()
	wasAvailable := networkAvailableLocked(now)
	networkAvailability.transportProvenUntil = now.Add(transportPathProofTTL)
	networkAvailability.nextUnvalidatedProbe = time.Time{}
	networkAvailability.unvalidatedProbeBusy = false
	if !wasAvailable {
		signalNetworkWaitersLocked()
	}
}

// beginNetworkPathGeneration invalidates proof and markers from every older
// proxy generation, then returns the token new streams must present.
func beginNetworkPathGeneration() uint64 {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	networkAvailability.transportGeneration++
	networkAvailability.transportProvenUntil = time.Time{}
	networkAvailability.nextUnvalidatedProbe = time.Time{}
	networkAvailability.unvalidatedProbeBusy = false
	networkAvailability.unvalidatedProbeID++
	return networkAvailability.transportGeneration
}

// resetNetworkPathProof prevents proof from an old proxy generation or
// physical network from authorising work on a new path.
func resetNetworkPathProof() {
	beginNetworkPathGeneration()
}

func isNetworkAvailable() bool {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()
	return networkAvailableLocked(time.Now())
}

func networkAvailabilitySnapshot() (pathPresent, androidValidated, transportProven, effective bool, proofRemaining time.Duration) {
	networkAvailability.Lock()
	defer networkAvailability.Unlock()

	pathPresent = !networkAvailability.physicalPathAbsent
	androidValidated = networkAvailability.androidValidated
	proofRemaining = networkAvailability.transportProvenUntil.Sub(time.Now())
	if proofRemaining < 0 {
		proofRemaining = 0
	}
	transportProven = proofRemaining > 0
	effective = pathPresent && (androidValidated || transportProven)
	return
}

type networkPermit struct {
	unvalidatedProbe bool
	probeID          uint64
}

func waitForNetworkPermit(ctx context.Context, allowUnvalidatedProbe bool) (networkPermit, bool) {
	for {
		networkAvailability.Lock()
		now := time.Now()
		if networkAvailableLocked(now) {
			networkAvailability.Unlock()
			return networkPermit{}, true
		}

		// With no physical path there is no probe either: it could only fail, and
		// the waiter sits on becameAvailable with no timer until setPhysicalPath
		// wakes it.
		var probeAt time.Time
		if allowUnvalidatedProbe && !networkAvailability.physicalPathAbsent {
			if !networkAvailability.unvalidatedProbeBusy {
				probeAt = networkAvailability.nextUnvalidatedProbe
			}
			if !networkAvailability.unvalidatedProbeBusy && (probeAt.IsZero() || !now.Before(probeAt)) {
				networkAvailability.nextUnvalidatedProbe = now.Add(unvalidatedProbeInterval)
				networkAvailability.unvalidatedProbeBusy = true
				networkAvailability.unvalidatedProbeID++
				probeID := networkAvailability.unvalidatedProbeID
				networkAvailability.Unlock()
				return networkPermit{unvalidatedProbe: true, probeID: probeID}, true
			}
		}
		becameAvailable := networkAvailability.becameAvailable
		networkAvailability.Unlock()

		if probeAt.IsZero() {
			select {
			case <-becameAvailable:
			case <-ctx.Done():
				return networkPermit{}, false
			}
			continue
		}

		timer := time.NewTimer(time.Until(probeAt))
		select {
		case <-becameAvailable:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return networkPermit{}, false
		}
	}
}

func releaseNetworkPermit(permit networkPermit) {
	if !permit.unvalidatedProbe {
		return
	}
	networkAvailability.Lock()
	if !networkAvailability.unvalidatedProbeBusy || permit.probeID != networkAvailability.unvalidatedProbeID {
		networkAvailability.Unlock()
		return
	}
	networkAvailability.unvalidatedProbeBusy = false
	// Wake parked workers so exactly one can either claim an overdue probe or
	// install a timer for the remaining rate-limit interval.
	signalNetworkWaitersLocked()
	networkAvailability.Unlock()
}

func waitForNetworkAvailable(ctx context.Context) bool {
	_, ok := waitForNetworkPermit(ctx, false)
	return ok
}
