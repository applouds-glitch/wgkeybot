/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"testing"
	"time"
)

const healthTestAddr = "95.163.34.160:19302"

// One lost uplink blackholes every stream at once. That is one verdict on the
// server, not twelve, and it must not on its own clear a threshold that is
// supposed to describe a host failing repeatedly over time — otherwise a blip
// stands down every server VK returned.
func TestNoteServerFailureCoalescesOneIncident(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	now := time.Now()
	for i := 0; i < 12; i++ {
		noteServerFailureAt(healthTestAddr, now.Add(time.Duration(i)*time.Millisecond))
	}

	if serverPenalized(healthTestAddr, now.Add(time.Second)) {
		t.Fatal("one incident reported by twelve streams stood the server down")
	}
}

// Trouble that outlives the coalescing window still earns a stand-down, and the
// penalty still expires on its own.
func TestNoteServerFailurePenalizesPersistentTrouble(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	start := time.Now()
	step := serverFailCoalesce + time.Second
	var last time.Time
	for strike := 0; strike < serverFailThreshold; strike++ {
		last = start.Add(time.Duration(strike) * step)
		// Each strike arrives with the usual crowd of siblings right behind it.
		noteServerFailureAt(healthTestAddr, last)
		noteServerFailureAt(healthTestAddr, last.Add(5*time.Millisecond))
	}

	if !serverPenalized(healthTestAddr, last.Add(time.Second)) {
		t.Fatalf("%d strikes over %v did not stand the server down", serverFailThreshold, step*time.Duration(serverFailThreshold-1))
	}
	if serverPenalized(healthTestAddr, last.Add(serverPenaltyWindow+time.Second)) {
		t.Fatal("penalty outlived its window")
	}
}

// "In a row" has to mean in a row: strikes an evening apart are separate
// incidents, and stale ones must not add up to a stand-down.
func TestNoteServerFailureForgetsStaleStreak(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	start := time.Now()
	noteServerFailureAt(healthTestAddr, start)
	noteServerFailureAt(healthTestAddr, start.Add(serverFailCoalesce+time.Second))

	late := start.Add(2 * time.Hour)
	noteServerFailureAt(healthTestAddr, late)

	if serverPenalized(healthTestAddr, late.Add(time.Second)) {
		t.Fatal("a blip hours after two old strikes stood the server down")
	}
}

const healthTestPeerAddr = "90.156.236.92:19302"

// One relay whose data plane is dead, several that work: the failing host must
// stand down on its first verdict instead of waiting out three strikes. What
// makes that safe is the overlap — a sibling completed a handshake on another
// server while this attempt was failing, so the uplink is provably fine and the
// fault is this host's alone.
func TestHandshakeFailureStandsServerDownWhileASiblingProvesAnotherServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	attemptStart := time.Now()
	noteServerHandshakeOKAt(healthTestPeerAddr, attemptStart.Add(time.Second))
	noteServerHandshakeFailureAt(healthTestAddr, attemptStart, attemptStart.Add(10*time.Second))

	if !serverPenalized(healthTestAddr, attemptStart.Add(11*time.Second)) {
		t.Fatal("a proven sibling did not authorise an immediate stand-down")
	}
	if serverPenalized(healthTestPeerAddr, attemptStart.Add(11*time.Second)) {
		t.Fatal("the healthy server was stood down too")
	}
}

// A lost uplink fails every handshake on every server at once. Nothing proves
// the path in that window, so a single failure must decide nothing and the
// ordinary streak has to run its course — otherwise one blip stands down the
// whole list VK returned.
func TestHandshakeFailureWithoutProofFallsBackToTheStreak(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	attemptStart := time.Now()
	noteServerHandshakeFailureAt(healthTestAddr, attemptStart, attemptStart.Add(10*time.Second))

	if serverPenalized(healthTestAddr, attemptStart.Add(11*time.Second)) {
		t.Fatal("an unproven failure stood the server down on one strike")
	}
}

// Proof from the failing server itself argues the opposite: another stream is
// talking to that very host, so its data plane works and one stream's failure
// is not the host's fault.
func TestHandshakeFailureIgnoresProofFromTheSameServer(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	attemptStart := time.Now()
	noteServerHandshakeOKAt(healthTestAddr, attemptStart.Add(time.Second))
	noteServerHandshakeFailureAt(healthTestAddr, attemptStart, attemptStart.Add(10*time.Second))

	if serverPenalized(healthTestAddr, attemptStart.Add(11*time.Second)) {
		t.Fatal("a server proved healthy by its own sibling was stood down")
	}
}

// Only proof that overlaps the failed attempt says anything about the uplink.
// A success from before the attempt began is exactly what a dying uplink leaves
// behind, and must not be read as "the network is fine, blame the host".
func TestHandshakeFailureIgnoresProofOlderThanTheAttempt(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()

	attemptStart := time.Now()
	noteServerHandshakeOKAt(healthTestPeerAddr, attemptStart.Add(-time.Second))
	noteServerHandshakeFailureAt(healthTestAddr, attemptStart, attemptStart.Add(10*time.Second))

	if serverPenalized(healthTestAddr, attemptStart.Add(11*time.Second)) {
		t.Fatal("proof from before the attempt authorised a stand-down")
	}
}
