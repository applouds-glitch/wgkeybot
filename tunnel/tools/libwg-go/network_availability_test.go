package main

import (
	"context"
	"testing"
	"time"
)

func resetNetworkAvailabilityForTest() {
	setPhysicalPath(true)
}

func waitsForNetwork(t *testing.T, ctx context.Context) <-chan bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- waitForNetwork(ctx) }()
	return done
}

// No physical network parks new connection work; the network coming back
// releases it.
func TestNetworkGateWaitsForAPhysicalNetwork(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setPhysicalPath(false)
	if isNetworkAvailable() {
		t.Fatal("no physical network, yet the gate reads available")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := waitsForNetwork(t, ctx)
	select {
	case <-done:
		t.Fatal("gate opened with no physical network")
	case <-time.After(50 * time.Millisecond):
	}

	setPhysicalPath(true)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("gate reported cancellation on a returning network")
		}
	case <-time.After(time.Second):
		t.Fatal("a returning network did not release the parked worker")
	}
}

func TestNetworkGateHonorsCancellation(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setPhysicalPath(false)

	ctx, cancel := context.WithCancel(context.Background())
	done := waitsForNetwork(t, ctx)
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a cancelled wait reported a network")
		}
	case <-time.After(time.Second):
		t.Fatal("a parked worker did not notice cancellation")
	}
}

// The field case of 2026-09-18: a cellular network Android never validates,
// and a relay that went dark long ago. Nothing but the physical path may hold a
// worker back — there is no validation signal and no proof to expire, so a
// reconnect never waits for a once-a-minute probe.
func TestNetworkGateIsOpenWheneverThereIsANetwork(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 20; i++ {
		if !waitForNetwork(ctx) {
			t.Fatalf("attempt %d waited on a present network", i)
		}
	}
}

// Every parked worker is released at once, not one at a time.
func TestReturningNetworkReleasesEveryParkedWorker(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setPhysicalPath(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const workers = 9
	done := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		go func() { done <- waitForNetwork(ctx) }()
	}
	time.Sleep(50 * time.Millisecond)
	setPhysicalPath(true)
	for i := 0; i < workers; i++ {
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("a worker saw cancellation instead of the network")
			}
		case <-time.After(time.Second):
			t.Fatalf("only %d of %d parked workers were released", i, workers)
		}
	}
}

// Kotlin pushes on every path change, re-addressing of the same network
// included: a report that changes nothing must say so, so that nothing is
// logged or re-signalled for it.
func TestRepeatedPathReportChangesNothing(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	if setPhysicalPath(true) {
		t.Fatal("path present → present reported a change")
	}
	if !setPhysicalPath(false) {
		t.Fatal("path present → absent reported no change")
	}
	if setPhysicalPath(false) {
		t.Fatal("path absent → absent reported a change")
	}
	if !setPhysicalPath(true) {
		t.Fatal("path absent → present reported no change")
	}
}
