/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// pinRelayConnectGap fixes the spacing for one test: no jitter, and short enough
// to wait for.
func pinRelayConnectGap(t *testing.T, d time.Duration) {
	t.Helper()
	prev := relayConnectGap
	relayConnectGap = func() time.Duration { return d }
	resetRelayConnectPacing()
	t.Cleanup(func() {
		relayConnectGap = prev
		resetRelayConnectPacing()
	})
}

// leaveTimes releases n callers for addr at the same instant and returns when
// each was let go, in order.
func leaveTimes(ctx context.Context, addr string, n int) []time.Duration {
	start := time.Now()
	var mu sync.Mutex
	var left []time.Duration
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if awaitRelayConnectSlot(ctx, addr) {
				mu.Lock()
				left = append(left, time.Since(start))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(left, func(i, j int) bool { return left[i] < left[j] })
	return left
}

func assertSpaced(t *testing.T, left []time.Duration, n int, gap time.Duration) {
	t.Helper()
	if len(left) != n {
		t.Fatalf("%d of %d callers were let go", len(left), n)
	}
	if left[0] > gap/2 {
		t.Fatalf("the first connect waited %v: it must leave at once", left[0])
	}
	const slack = 20 * time.Millisecond
	for i := 1; i < n; i++ {
		if d := left[i] - left[i-1]; d < gap-slack {
			t.Fatalf("connects %d and %d left %v apart, want %v: %v", i-1, i, d, gap, left)
		}
	}
}

func TestBurstOfTCPConnectsToOneRelayIsSpaced(t *testing.T) {
	const gap = 150 * time.Millisecond
	pinRelayConnectGap(t, gap)

	assertSpaced(t, leaveTimes(context.Background(), "relay-a:19302", 4), 4, gap)

	// The queue has drained; a lone reconnect later is not held, and neither is
	// the first connect to another relay while this one's queue is long — the
	// dial that races a silent relay goes through that door.
	time.Sleep(gap + 50*time.Millisecond)
	began := time.Now()
	if !awaitRelayConnectSlot(context.Background(), "relay-a:19302") || time.Since(began) > gap/2 {
		t.Fatalf("a lone reconnect was held for %v", time.Since(began))
	}
	// A quiet spell earns no credit: the burst after it is spaced like the first,
	// not let through on the slots that went unused meanwhile.
	time.Sleep(4 * gap)
	assertSpaced(t, leaveTimes(context.Background(), "relay-a:19302", 3), 3, gap)
	time.Sleep(gap + 50*time.Millisecond)
	go leaveTimes(context.Background(), "relay-a:19302", 4)
	time.Sleep(20 * time.Millisecond)
	began = time.Now()
	if !awaitRelayConnectSlot(context.Background(), "relay-b:19302") || time.Since(began) > gap/2 {
		t.Fatalf("a connect to another relay queued behind this one's for %v", time.Since(began))
	}
}

// Callers that gave up leave promptly, and a reset — a proxy start, a move to
// another network — clears what they had reserved: the redials that follow do
// not queue behind connects that will never be made.
func TestAbandonedConnectSlotsDoNotDelayTheRedials(t *testing.T) {
	const gap = 400 * time.Millisecond
	pinRelayConnectGap(t, gap)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []time.Duration, 1)
	go func() { done <- leaveTimes(ctx, "relay-a:19302", 6) }()
	time.Sleep(50 * time.Millisecond)
	began := time.Now()
	cancel()
	if left := <-done; len(left) != 1 || time.Since(began) > gap/2 {
		t.Fatalf("after the cancel: %d let go, the rest took %v to leave", len(left), time.Since(began))
	}

	resetRelayConnectPacing()
	began = time.Now()
	if !awaitRelayConnectSlot(context.Background(), "relay-a:19302") || time.Since(began) > gap/2 {
		t.Fatalf("the first redial after the reset was held for %v", time.Since(began))
	}
}

// End to end: workers released together — what the network coming back does —
// reach the relay one at a time, all of them do, and over UDP nothing is held.
func TestWorkersReleasedTogetherConnectOverTCPOneAtATime(t *testing.T) {
	const gap = 250 * time.Millisecond
	pinRelayConnectGap(t, gap)
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)

	var mu sync.Mutex
	var connects []time.Duration
	start := time.Now()
	prev := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
		mu.Lock()
		connects = append(connects, time.Since(start))
		mu.Unlock()
		return prev(ctx, d, addr)
	}
	t.Cleanup(func() { dialRelayTCP = prev })

	h := runWorkersAgainst(t, 123, 4, []string{relay.addr})
	waitFor(t, "all four streams", 6*time.Second, func() bool { return h.ready() == 4 })

	mu.Lock()
	got := append([]time.Duration(nil), connects...)
	mu.Unlock()
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	assertSpaced(t, got, 4, gap)
}

func TestUDPDialsAreNotPaced(t *testing.T) {
	pinRelayConnectGap(t, 5*time.Second)
	first, _ := twoRelaySockets(t)
	relay := startTestRelay(t, first, 0)

	h := runWorkersAgainst(t, 124, 3, []string{relay.addr})
	waitFor(t, "three streams over UDP", 4*time.Second, func() bool { return h.ready() == 3 })
}

// The wait is our own queue. A relay that answers at once must not be raced
// because a worker stood in that queue for longer than the head start.
func TestWaitForAConnectSlotIsNotTheRelaysSilence(t *testing.T) {
	first, second := twoTCPRelayListeners(t)
	a := startTCPTestRelay(t, first)
	b := startTCPTestRelay(t, second)
	overTCP(t)
	pinRelayConnectGap(t, relayHeadStart+400*time.Millisecond)

	h := runWorkersAgainst(t, 125, 2, []string{a.addr, b.addr})
	waitFor(t, "both streams on the first relay", 6*time.Second, func() bool { return h.ready() == 2 })

	if n := b.ln.accepted.Load(); n != 0 {
		t.Fatalf("the second relay was dialed %d time(s): the wait for a slot was counted as the first one's silence", n)
	}
}
