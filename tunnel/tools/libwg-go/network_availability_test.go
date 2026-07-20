package main

import (
	"context"
	"testing"
	"time"
)

func resetNetworkAvailabilityForTest() {
	setNetworkAvailable(true)
	resetNetworkPathProof()
}

func TestNetworkAvailabilityGateWaitsAndResumes(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setNetworkAvailable(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- waitForNetworkAvailable(ctx) }()

	select {
	case <-done:
		t.Fatal("gate returned while network was unavailable")
	case <-time.After(50 * time.Millisecond):
	}

	setNetworkAvailable(true)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("gate returned false after network became available")
		}
	case <-time.After(time.Second):
		t.Fatal("gate did not resume after network became available")
	}
}

func TestNetworkAvailabilityGateHonorsCancellation(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setNetworkAvailable(false)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- waitForNetworkAvailable(ctx) }()
	cancel()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("gate returned true after context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("gate did not unblock on context cancellation")
	}
}

func TestTransportProofKeepsUnvalidatedNetworkAvailable(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(true)
	markNetworkPathProven(generation)
	setNetworkAvailable(false)
	if !isNetworkAvailable() {
		t.Fatal("Android validation loss erased fresh transport proof")
	}
}

func TestTransportProofExpires(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(false)
	markNetworkPathProven(generation)

	networkAvailability.Lock()
	networkAvailability.transportProvenUntil = time.Now().Add(-time.Second)
	networkAvailability.Unlock()
	if isNetworkAvailable() {
		t.Fatal("expired transport proof kept gate open")
	}
}

func TestOldGenerationCannotRestorePathProof(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	oldGeneration := beginNetworkPathGeneration()
	beginNetworkPathGeneration()
	setNetworkAvailable(false)
	markNetworkPathProven(oldGeneration)
	if isNetworkAvailable() {
		t.Fatal("stale stream generation restored path proof")
	}
}

func TestTransportProofResumesWaitingWorkers(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- waitForNetworkAvailable(ctx) }()

	select {
	case <-done:
		t.Fatal("gate returned before transport proof")
	case <-time.After(50 * time.Millisecond):
	}

	markNetworkPathProven(generation)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("gate returned false after transport proof")
		}
	case <-time.After(time.Second):
		t.Fatal("transport proof did not resume waiting worker")
	}
}

func TestUnvalidatedProbePermitIsSingleAndRateLimited(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	beginNetworkPathGeneration()
	setNetworkAvailable(false)
	permit, ok := waitForNetworkPermit(context.Background(), true)
	if !ok || !permit.unvalidatedProbe {
		t.Fatal("first worker did not receive controlled probe permit")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, secondOK := waitForNetworkPermit(ctx, true); secondOK {
		t.Fatal("second worker received a concurrent probe permit")
	}

	releaseNetworkPermit(permit)
	networkAvailability.Lock()
	networkAvailability.nextUnvalidatedProbe = time.Now().Add(-time.Second)
	networkAvailability.Unlock()
	secondPermit, secondOK := waitForNetworkPermit(context.Background(), true)
	if !secondOK || !secondPermit.unvalidatedProbe {
		t.Fatal("probe permit did not reopen after release and interval")
	}
	releaseNetworkPermit(secondPermit)
}

func TestOldProbePermitCannotReleaseNewProbe(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(false)
	oldPermit, ok := waitForNetworkPermit(context.Background(), true)
	if !ok {
		t.Fatal("old probe permit not acquired")
	}

	// A successful old probe opens the gate. Later the proof expires and a new
	// outage cycle issues a different permit while the old session is unwinding.
	markNetworkPathProven(generation)
	networkAvailability.Lock()
	networkAvailability.transportProvenUntil = time.Now().Add(-time.Second)
	networkAvailability.nextUnvalidatedProbe = time.Now().Add(-time.Second)
	networkAvailability.Unlock()
	newPermit, newOK := waitForNetworkPermit(context.Background(), true)
	if !newOK {
		t.Fatal("new probe permit not acquired")
	}

	releaseNetworkPermit(oldPermit)
	networkAvailability.Lock()
	busy := networkAvailability.unvalidatedProbeBusy
	activeID := networkAvailability.unvalidatedProbeID
	networkAvailability.Unlock()
	if !busy || activeID != newPermit.probeID {
		t.Fatal("old permit released the active probe")
	}
	releaseNetworkPermit(newPermit)
}
