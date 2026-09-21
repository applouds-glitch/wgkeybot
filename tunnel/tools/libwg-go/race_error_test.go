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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func attemptErr(addr string, err error) relayAttemptError {
	return relayAttemptError{addr: addr, err: fmt.Errorf("TURN allocate: %w", err)}
}

// The answer that calls for new credentials speaks for the attempt, whenever in
// the race it arrived; with none, the last failure does, as it always has.
func TestRaceErrorSpeaksThroughTheCredentialAnswer(t *testing.T) {
	const a, b = "relay-a:19302", "relay-b:19302"
	timeout := writeErr(50486, syscall.ETIMEDOUT)

	// The field order: 486 in one round trip, the dark relay's timeout 7.8s on.
	raced := newRaceError([]relayAttemptError{attemptErr(a, turnErr(stun.CodeAllocQuotaReached)), attemptErr(b, timeout)})
	if !isQuotaError(raced) || !classifyCredError(raced) {
		t.Fatalf("a 486 followed by a timeout read as %q: no rotation, no quota backoff", raced)
	}
	if isTransportError(raced) {
		t.Fatal("the other relay's timeout is in the chain: classifyCredError would bail out on it")
	}
	if strings.Contains(raced.Error(), "50486") {
		t.Fatalf("the other relay's addresses are in the text the substring fallback reads: %q", raced)
	}
	if got := raced.spokesman().addr; got != a {
		t.Fatalf("%s speaks for the attempt, want %s", got, a)
	}

	if !raced.overrulesLast() {
		t.Fatal("a 486 speaking over a timeout is not reported")
	}

	// The other way round was always fine, and still is.
	raced = newRaceError([]relayAttemptError{attemptErr(a, timeout), attemptErr(b, turnErr(stun.CodeAllocQuotaReached))})
	if !isQuotaError(raced) || raced.spokesman().addr != b {
		t.Fatalf("a timeout followed by a 486 read as %q", raced)
	}

	// Two credential answers: the first to arrive.
	raced = newRaceError([]relayAttemptError{attemptErr(a, turnErr(stun.CodeUnauthorized)), attemptErr(b, turnErr(stun.CodeAllocQuotaReached))})
	if code, _ := turnErrorCode(raced); code != stun.CodeUnauthorized {
		t.Fatalf("spoke with %v, want the first credential answer", code)
	}
	// …which changes nothing about how the attempt is read: no line for it. On
	// the device both relays held our orphans, and ten workers said so at once.
	if raced.overrulesLast() {
		t.Fatal("one credential answer ahead of another was reported as overruling it")
	}

	// None: the last failure, in the chain as the transport error it is.
	refused := writeErr(40100, syscall.ECONNREFUSED)
	raced = newRaceError([]relayAttemptError{attemptErr(a, timeout), attemptErr(b, refused)})
	if classifyCredError(raced) || !isTransportError(raced) || !errors.Is(raced, syscall.ECONNREFUSED) {
		t.Fatalf("two transport failures read as %q", raced)
	}
	// A code that is not about the credential does not outrank it either.
	raced = newRaceError([]relayAttemptError{attemptErr(a, turnErr(stun.CodeForbidden)), attemptErr(b, refused)})
	if raced.spokesman().addr != b {
		t.Fatal("a 403 spoke for the attempt over the last failure")
	}

	// One relay, one answer; and the text runWorker has always logged.
	raced = newRaceError([]relayAttemptError{attemptErr(a, refused)})
	if !strings.HasPrefix(raced.Error(), "TURN allocate: all 1 servers failed: TURN allocate: ") {
		t.Fatalf("the error reads %q", raced)
	}
}

// Our release on one relay explains a 486 from that relay, not from another:
// the attempt now says which relay answered what.
func TestSettlingQuotaIsAskedOfTheRelayThatAnswered486(t *testing.T) {
	resetAllocationBook(t)
	now := time.Now()
	noteBoundNetwork(orphanNetA, now)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close() // released cleanly, just now

	timeout := writeErr(50000, syscall.ETIMEDOUT)
	both := []string{orphanRelay1, orphanRelay2}

	// Relay 1 said 486; the release was on relay 2, which only timed out.
	raced := newRaceError([]relayAttemptError{attemptErr(orphanRelay1, turnErr(stun.CodeAllocQuotaReached)), attemptErr(orphanRelay2, timeout)})
	if relay, _, ok := settlingQuotaError(raced, "alice", both, now.Add(600*time.Millisecond)); ok {
		t.Fatalf("relay 1's 486 was explained by our release on %s", relay)
	}
	// Relay 2 said it: that is the release settling.
	raced = newRaceError([]relayAttemptError{attemptErr(orphanRelay2, turnErr(stun.CodeAllocQuotaReached)), attemptErr(orphanRelay1, timeout)})
	if relay, _, ok := settlingQuotaError(raced, "alice", both, now.Add(600*time.Millisecond)); !ok || relay != orphanRelay2 {
		t.Fatalf("relay 2's 486 right after our release there: relay=%q ok=%v", relay, ok)
	}
	// An error that does not say who answered keeps the old reading.
	if _, _, ok := settlingQuotaError(quota486(), "alice", both, now.Add(600*time.Millisecond)); !ok {
		t.Fatal("a plain 486 lost the settle window")
	}
}

// The race itself: the first relay is dark, the second answers 486 as soon as it
// is raced — and the dark one's timeout arrives seven seconds after it. The
// attempt has to come back as the 486 it was.
func TestRaceReportsThe486NotTheTimeoutThatFollowedIt(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	resetServerHealth()
	t.Cleanup(resetServerHealth)

	silent := listenFakeRelay(t) // takes datagrams, never answers
	refuser, _ := startInitialRefusalServer(t, 100, stun.CodeAllocQuotaReached)
	addrs := []string{silent.LocalAddr().String(), refuser.LocalAddr().String()}

	s, _ := newNoDTLSTestStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := s.runWithCreds(ctx, t.Name(), "pass", addrs, WorkerGroupConfig{GroupID: 131, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: fakeRelay(t, nil)})

	var raced *raceError
	if !errors.As(err, &raced) || len(raced.attempts) != 2 {
		t.Fatalf("the attempt ended with %v", err)
	}
	if last := raced.attempts[1]; last.addr != addrs[0] {
		t.Fatalf("%s failed last: the test did not stage the order it is about", last.addr)
	}
	if !isQuotaError(err) || !classifyCredError(err) {
		t.Fatalf("the attempt read as %q, want the 486", err)
	}
	if got := quotaAnsweredBy(err, addrs); len(got) != 1 || got[0].addr != addrs[1] || got[0].at.IsZero() {
		t.Fatalf("486 attributed to %v, want %s and the time it came in", got, addrs[1])
	}
	if quota, silent, ok := quotaBesideSilence(err); !ok || quota != addrs[1] || silent != addrs[0] {
		t.Fatalf("quotaBesideSilence: quota=%q silent=%q ok=%v", quota, silent, ok)
	}
}

// The settle window is judged when the relay said 486, not when the attempt
// ended: the silence of the relay next to it holds the attempt open for eight
// seconds more, and a 486 three seconds after our release would otherwise be
// read as a full credential — a trip to VK for a quota freed long since.
func TestSettlingQuotaIsJudgedWhenThe486CameIn(t *testing.T) {
	resetAllocationBook(t)
	t0 := time.Now()
	noteBoundNetwork(orphanNetA, t0)
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()
	both := []string{orphanRelay1, orphanRelay2}
	timeout := writeErr(50000, syscall.ETIMEDOUT)
	raceEndedAt := t0.Add(releaseSettleWindow + time.Second)

	attempt := func(quotaAt time.Time) error {
		quota := attemptErr(orphanRelay2, turnErr(stun.CodeAllocQuotaReached))
		quota.at = quotaAt
		silent := attemptErr(orphanRelay1, timeout)
		silent.at = raceEndedAt
		return newRaceError([]relayAttemptError{quota, silent})
	}
	// Every worker of the group comes back with such an attempt of its own, the
	// last of them long after: a fallback can queue behind a silent relay.
	for worker := 0; worker < 3; worker++ {
		endedAt := raceEndedAt.Add(time.Duration(worker) * 2 * releaseSettleWindow)
		if _, age, ok := settlingQuotaError(attempt(t0.Add(3*time.Second)), "alice", both, endedAt); !ok || age > 4*time.Second {
			t.Fatalf("worker %d: a 486 three seconds after our release, in an attempt that ended after the window: ok=%v age=%v", worker, ok, age)
		}
	}
	// Answered before the release went out: explained by it all the more.
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()
	if _, age, ok := settlingQuotaError(attempt(t0.Add(-time.Second)), "alice", both, time.Now()); !ok || age != 0 {
		t.Fatalf("a 486 from just before our release: ok=%v age=%v", ok, age)
	}
	// Answered after the window: a full credential, whenever the attempt ended.
	trackAllocation(&countingConn{}, "alice", orphanRelay2).Close()
	late := time.Now().Add(releaseSettleWindow + time.Second)
	if _, _, ok := settlingQuotaError(attempt(late), "alice", both, late); ok {
		t.Fatal("a 486 that came in after the window kept the credential")
	}
}

// Which attempts get the one more try: a 486 that speaks, next to a relay that
// did not answer at all.
func TestQuotaBesideSilence(t *testing.T) {
	const a, b = "relay-a:19302", "relay-b:19302"
	quota := turnErr(stun.CodeAllocQuotaReached)
	timeout := writeErr(50000, syscall.ETIMEDOUT)
	for _, tc := range []struct {
		name     string
		attempts []relayAttemptError
		want     bool
	}{
		{"486 then silence", []relayAttemptError{attemptErr(a, quota), attemptErr(b, timeout)}, true},
		{"silence then 486", []relayAttemptError{attemptErr(b, timeout), attemptErr(a, quota)}, true},
		{"486 from both", []relayAttemptError{attemptErr(a, quota), attemptErr(b, quota)}, false},
		{"486 and a refusal", []relayAttemptError{attemptErr(a, quota), attemptErr(b, turnErr(stun.CodeForbidden))}, false},
		{"stale credentials and silence", []relayAttemptError{attemptErr(a, turnErr(stun.CodeUnauthorized)), attemptErr(b, timeout)}, false},
		{"silence only", []relayAttemptError{attemptErr(a, timeout), attemptErr(b, timeout)}, false},
		{"486 alone", []relayAttemptError{attemptErr(a, quota)}, false},
	} {
		quotaRelay, silent, ok := quotaBesideSilence(newRaceError(tc.attempts))
		if ok != tc.want || (ok && (quotaRelay != a || silent != b)) {
			t.Errorf("%s: quota=%q silent=%q ok=%v, want %v", tc.name, quotaRelay, silent, ok, tc.want)
		}
	}
	if _, _, ok := quotaBesideSilence(quota486()); ok {
		t.Error("an error that does not say who answered what got the extra try")
	}
}

// Once per credential, and not on a credential a sibling has already replaced.
func TestQuotaGraceIsOncePerCredentialAndYieldsToReplacedCreds(t *testing.T) {
	const a, b = "relay-a:19302", "relay-b:19302"
	raced := newRaceError([]relayAttemptError{
		attemptErr(a, turnErr(stun.CodeAllocQuotaReached)),
		attemptErr(b, writeErr(50000, syscall.ETIMEDOUT)),
	})
	if _, _, ok := quotaGraceApplies(raced, "alice", "", false); !ok {
		t.Fatal("the first 486 beside silence on a credential got no extra try")
	}
	if _, _, ok := quotaGraceApplies(raced, "alice", "alice", false); ok {
		t.Fatal("a credential got its extra try twice")
	}
	if _, _, ok := quotaGraceApplies(raced, "bob", "alice", false); !ok {
		t.Fatal("a new credential was denied the try the old one used")
	}
	if _, _, ok := quotaGraceApplies(raced, "alice", "", true); ok {
		t.Fatal("a credential already replaced was tried once more instead of being left for the new one")
	}
}

// Through the worker: a 486 beside a relay that never answered is tried once
// more on the same credential, and only then is VK asked for a new one.
func TestWorkerTriesOnceMoreBeforeGivingUpCredsOverA486BesideSilence(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	resetServerHealth()
	const group = 97
	dropCredSlot(t, group)

	silent := listenFakeRelay(t)
	refuser, _ := startInitialRefusalServer(t, 100, stun.CodeAllocQuotaReached)
	addrs := []string{silent.LocalAddr().String(), refuser.LocalAddr().String()}

	var fetches atomic.Int32
	fn := func(context.Context, string) (string, string, []string, int, error) {
		fetches.Add(1)
		return t.Name(), "pass", addrs, 0, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runWorkerAgainst(t, ctx, group, addrs[0], fn)
	defer func() {
		cancel()
		<-done
	}()

	// Each attempt is held open ~8s by the silent relay's Allocate.
	waitFor(t, "the second attempt to reach the refusing relay", 14*time.Second, func() bool { return refuser.count() >= 2 })
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d credential fetches by the second attempt: the first 486 beside silence gave the credential up", n)
	}
	waitFor(t, "new credentials after the second such attempt", 14*time.Second, func() bool { return fetches.Load() >= 2 })
}
