/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestWorkerAvoidanceKeepsSecondRetryBackoff(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	resetRelayConnectPacing()
	t.Cleanup(resetRelayConnectPacing)
	firstSocket, second := twoRelaySockets(t)
	first := startTestRelay(t, firstSocket, 0)
	addrs := []string{first.addr, second.LocalAddr().String()}
	peer := choosyPeer(t, func(int, time.Time) bool { return false })
	previousFetch, previousWaits := globalGetCreds, workerWaits
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", addrs, nil
	}
	t.Cleanup(func() { globalGetCreds, workerWaits = previousFetch, previousWaits })

	s, _ := newNoDTLSTestStream(t)
	s.id = 0
	s.flowFails.Store(&flowFailRun{relay: first.addr, n: flowFailsBeforeAvoid})
	// This witness has no worker, so its liveness can never prove a new path
	// and wake the tested worker's backoff. It only vouches for the first relay.
	witness, _ := newNoDTLSTestStream(t)
	witness.ready.Store(true)
	activity := newStreamActivity(time.Now(), 0)
	activity.noteRx(time.Now())
	witness.activity.Store(activity)
	t.Cleanup(trackLiveSession(first.addr, witness))
	ctx, cancel := context.WithCancel(context.Background())
	witnessDone := make(chan struct{})
	go func() {
		defer close(witnessDone)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				activity.noteRx(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	type retry struct {
		delay   time.Duration
		avoided string
		demoted bool
	}
	waits := make(chan retry, 4)
	workerWaits = func(w workerWait) {
		if w.stream == s.id {
			waits <- retry{w.delay, s.avoidedRelay(), serverDemoted(first.addr)}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorker(ctx, WorkerGroupConfig{GroupID: 0, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: peer}, s, 0)
	}()
	t.Cleanup(func() {
		cancel()
		<-witnessDone
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("worker did not stop during cleanup")
		}
	})
	for attempt := 1; attempt <= 2; attempt++ {
		select {
		case got := <-waits:
			if got.avoided != first.addr || got.demoted {
				t.Fatalf("retry %d: avoided=%q, demoted=%v; witness must keep %s usable and avoided", attempt, got.avoided, got.demoted, first.addr)
			}
			if attempt == 2 && got.delay < 2*time.Second {
				t.Fatalf("second retry delay = %v, want >= 2s with the same avoided relay", got.delay)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("worker never reached retry %d", attempt)
		}
	}
	if first.seen.count() < 2 {
		t.Fatal("worker did not fail two real sessions on the first relay")
	}
}

// vouchFor keeps a ready witness with a fresh clock on each relay, so that a
// handshake this stream fails there is the flow's failure (relayHeardByOthers).
// The witnesses have no worker: their liveness can never prove a new path and
// wake the tested worker's backoff. The returned func waits for their clock to
// stop, after ctx ends.
func vouchFor(t *testing.T, ctx context.Context, relays ...string) func() {
	t.Helper()
	var clocks []*streamActivity
	for _, relay := range relays {
		witness, _ := newNoDTLSTestStream(t)
		witness.ready.Store(true)
		activity := newStreamActivity(time.Now(), 0)
		activity.noteRx(time.Now())
		witness.activity.Store(activity)
		t.Cleanup(trackLiveSession(relay, witness))
		clocks = append(clocks, activity)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				for _, clock := range clocks {
					clock.noteRx(now)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { <-done }
}

// A stream failing its handshakes under the alibi on both of its relays. Its
// head alternates: two failures on the first relay and it dials the second,
// one failure there and the first is its head again (flowFailRun counts one
// relay), where two more failures avoid it again. A head change alone reset
// the streak every time, and the stream redialed in under a second for as
// long as that lasted; a relay this streak has already failed on gets no fresh
// streak.
func TestWorkerAvoidanceOnBothRelaysKeepsBackoff(t *testing.T) {
	resetAllocationBook(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	resetServerHealth()
	t.Cleanup(resetServerHealth)
	resetRelayConnectPacing()
	t.Cleanup(resetRelayConnectPacing)
	firstSocket, secondSocket := twoRelaySockets(t)
	first := startTestRelay(t, firstSocket, 0)
	second := startTestRelay(t, secondSocket, 0)
	addrs := []string{first.addr, second.addr}
	peer := choosyPeer(t, func(int, time.Time) bool { return false })
	previousFetch, previousWaits := globalGetCreds, workerWaits
	globalGetCreds = func(context.Context, string, int) (string, string, []string, error) {
		return t.Name(), "pass", addrs, nil
	}
	t.Cleanup(func() { globalGetCreds, workerWaits = previousFetch, previousWaits })

	s, _ := newNoDTLSTestStream(t)
	s.id = 0
	ctx, cancel := context.WithCancel(context.Background())
	witnessesDone := vouchFor(t, ctx, first.addr, second.addr)
	type retry struct {
		relay   string // the relay of the session that just failed (serverAddr)
		delay   time.Duration
		avoided string
		demoted bool
	}
	waits := make(chan retry, 8)
	workerWaits = func(w workerWait) {
		if w.stream == s.id {
			waits <- retry{s.serverAddr, w.delay, s.avoidedRelay(), serverDemoted(first.addr) || serverDemoted(second.addr)}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWorker(ctx, WorkerGroupConfig{GroupID: 0, Link: "test", UseUDP: true, PeerType: "wireguard", PeerAddr: peer}, s, 0)
	}()
	t.Cleanup(func() {
		cancel()
		witnessesDone()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("worker did not stop during cleanup")
		}
	})
	// The waits after attempts 1 and 2 (first relay; the second avoids it), 3
	// (second relay) and 4 (first relay again).
	var got []retry
	for attempt := 1; attempt <= 4; attempt++ {
		select {
		case r := <-waits:
			if r.demoted {
				t.Fatalf("retry %d: a relay was demoted; the witnesses must keep both usable", attempt)
			}
			got = append(got, r)
		case <-time.After(30 * time.Second):
			t.Fatalf("worker never reached retry %d", attempt)
		}
	}
	var relays []string
	for _, r := range got {
		relays = append(relays, r.relay)
	}
	if want := []string{first.addr, first.addr, second.addr, first.addr}; !slices.Equal(relays, want) {
		t.Fatalf("attempts ran on %v, want %v", relays, want)
	}
	if got[1].avoided != first.addr || got[2].avoided != "" {
		t.Fatalf("avoided after attempts 2 and 3: %q, %q; want the first relay, then none (the failure on the second ends its run)",
			got[1].avoided, got[2].avoided)
	}
	// The second relay is new to the streak: the stream goes to it at once.
	if got[1].delay >= time.Second {
		t.Fatalf("delay after attempt 2 = %v, want under 1s: the head moved to a relay this streak had not failed on", got[1].delay)
	}
	if got[3].delay < 2*time.Second {
		t.Fatalf("delay after attempt 4 = %v, want >= 2s: the fourth failure is the streak's second on the first relay, not a fresh one",
			got[3].delay)
	}
	if first.seen.count() < 2 || second.seen.count() < 1 {
		t.Fatalf("relays dialed %d and %d time(s); want real sessions failed on both", first.seen.count(), second.seen.count())
	}
}
