/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// The dead-stream detector fires after deadStreamTimeout of silence — longer
// than healthySessionDuration, so every session it ended used to read as a
// healthy one, however little it had carried. What counts is the time the relay
// was heard.
func TestSessionOutcomeTakesTheSilenceOffADeadStream(t *testing.T) {
	if deadStreamTimeout < healthySessionDuration {
		t.Skip("the detector now fires before a session counts as healthy")
	}
	deaf := &deadStreamError{silent: deadStreamTimeout}

	// Handshake, then nothing: the detector fires at deadStreamTimeout and a bit.
	// Not a success — and not a failure either: one deaf stream does not say
	// whose fault it was (see sessionOutcome).
	if got := sessionOutcome(false, false, deadStreamTimeout+5*time.Second, deaf); got != verdictNone {
		t.Fatalf("a relay that went silent right after the handshake read as %v", got)
	}
	// Wrapped on its way up, it is still what it is.
	if got := sessionOutcome(false, false, deadStreamTimeout+5*time.Second, fmt.Errorf("session: %w", deaf)); got != verdictNone {
		t.Fatalf("a wrapped dead-stream read as %v", got)
	}
	// Heard for a healthy while first: the relay did work.
	if got := sessionOutcome(false, false, healthySessionDuration+deadStreamTimeout, deaf); got != verdictSuccess {
		t.Fatalf("a relay heard for %v before it went silent read as %v", healthySessionDuration, got)
	}
	if got := sessionOutcome(false, false, healthySessionDuration+deadStreamTimeout-time.Second, deaf); got != verdictNone {
		t.Fatalf("a relay heard for just under %v read as %v", healthySessionDuration, got)
	}
	// Any other error leaves the length as it was.
	if got := sessionOutcome(false, false, deadStreamTimeout+5*time.Second, errors.New("relay TX: broken pipe")); got != verdictSuccess {
		t.Fatalf("a long session with another error read as %v", got)
	}
	// A blackhole is still the clearest failure there is, deaf or not.
	if got := sessionOutcome(false, true, deadStreamTimeout+5*time.Second, deaf); got != verdictFailure {
		t.Fatalf("a blackholed allocation that also went deaf read as %v", got)
	}
}

// The detector's own error has to be the typed one, with the text the log and
// the classifiers have always seen.
func TestDeadStreamDetectorReportsTheTypedError(t *testing.T) {
	now := time.Now()
	activity := newStreamActivity(now.Add(-deadStreamTimeout-time.Second), 0)
	got := make(chan error, 1)
	s := &stream{id: 7}
	s.runKeepalive(context.Background(), activity, func(err error) { got <- err }, func(int) error { return nil })

	var dead *deadStreamError
	select {
	case err := <-got:
		if !errors.As(err, &dead) || dead.silent < deadStreamTimeout {
			t.Fatalf("the detector reported %v", err)
		}
		if !strings.HasPrefix(err.Error(), "dead-stream: no RX for ") {
			t.Fatalf("the error reads %q", err)
		}
		if classifyCredError(err) || isTransportError(err) {
			t.Fatalf("%q was classified as a credential or transport error", err)
		}
	default:
		t.Fatal("the detector returned without reporting")
	}
}

// A freeze restarts the detector's clock so that a thawed host does not tear
// every stream down at once. It does not restart the silence: a relay heard
// last before the freeze has been silent since then, and the session is graded
// on that.
func TestFreezeResetDoesNotShortenTheSilence(t *testing.T) {
	now := time.Now()
	activity := newStreamActivity(now.Add(-5*time.Minute), 0)
	activity.resetLiveness(now.Add(-deadStreamTimeout - time.Second))

	got := make(chan error, 1)
	(&stream{id: 8}).runKeepalive(context.Background(), activity, func(err error) { got <- err }, func(int) error { return nil })
	var dead *deadStreamError
	select {
	case err := <-got:
		if !errors.As(err, &dead) {
			t.Fatalf("the detector reported %v", err)
		}
	default:
		t.Fatal("the detector returned without reporting")
	}
	if dead.silent < 5*time.Minute {
		t.Fatalf("silent for %v: counted from the freeze reset, not from the last packet", dead.silent)
	}
	if got := sessionOutcome(false, false, 5*time.Minute, dead); got != verdictNone {
		t.Fatalf("a session that heard nothing in five minutes read as %v", got)
	}
}

func shortDeadStream(t *testing.T, d time.Duration) {
	t.Helper()
	prev := deadStreamTimeout
	deadStreamTimeout = d
	t.Cleanup(func() { deadStreamTimeout = prev })
}

// Through a real session: a young stream that goes deaf leaves the relay's
// record exactly as it found it. Booked as a success it wiped the strike; booked
// as a failure, three of them stand a relay down under its working streams.
func TestDeadStreamLeavesTheRelaysRecordAlone(t *testing.T) {
	shortDeadStream(t, 2*time.Second)
	relay := startTestRelay(t, listenFakeRelay(t), 0)
	h := runWorkersAgainst(t, 127, 1, []string{relay.addr})
	waitFor(t, "a stream", 5*time.Second, func() bool { return h.ready() == 1 })
	// The harness resets the record as it starts. Old enough that a strike
	// for this session would not be coalesced into it.
	noteServerFailureAt(relay.addr, time.Now().Add(-3*serverFailCoalesce))

	waitFor(t, "the dead-stream detector", 6*time.Second, func() bool { return h.ready() == 0 })
	serverHealthState.Lock()
	defer serverHealthState.Unlock()
	if got := healthEntryLocked(relay.addr).failures; got != 1 {
		t.Fatalf("the relay's one strike became %d after a session that went deaf", got)
	}
}
