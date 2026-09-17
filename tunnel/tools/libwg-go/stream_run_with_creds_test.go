/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// A relay that allocates and then swallows the data plane is the failure this
// whole path exists to catch, and it has to be told apart from the ordinary
// "session ended badly" so it can be acted on immediately.
func TestSessionOutcomeSeparatesHandshakeFailureFromAnyOtherError(t *testing.T) {
	hs := fmt.Errorf("SRTP handshake failed: %w", errDataPlaneHandshake)
	if got := sessionOutcome(false, false, time.Second, hs); got != verdictHandshakeFailure {
		t.Fatalf("data-plane handshake failure read as %v", got)
	}
	if got := sessionOutcome(false, false, time.Second, errors.New("relay TX: broken pipe")); got != verdictFailure {
		t.Fatalf("an ordinary short failure read as %v", got)
	}
}

// The verdicts that already existed must not shift: a teardown is our doing and
// says nothing, a blackhole is the clearest failure there is, and a session that
// ran long enough proves the host works.
func TestSessionOutcomeKeepsTheExistingVerdicts(t *testing.T) {
	if got := sessionOutcome(true, true, time.Second, errDataPlaneHandshake); got != verdictNone {
		t.Fatalf("a teardown was charged to the server: %v", got)
	}
	if got := sessionOutcome(false, true, time.Second, nil); got != verdictFailure {
		t.Fatalf("a blackholed allocation read as %v", got)
	}
	if got := sessionOutcome(false, false, healthySessionDuration, nil); got != verdictSuccess {
		t.Fatalf("a healthy session read as %v", got)
	}
	if got := sessionOutcome(false, false, time.Second, nil); got != verdictNone {
		t.Fatalf("a clean short session read as %v", got)
	}
}
