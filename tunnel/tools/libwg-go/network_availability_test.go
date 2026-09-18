package main

import (
	"context"
	"testing"
	"time"
)

func resetNetworkAvailabilityForTest() {
	setPhysicalPath(true)
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

func TestAbsentPhysicalPathClosesGateOverValidationAndProof(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(true)
	markNetworkPathProven(generation)

	setPhysicalPath(false)
	if isNetworkAvailable() {
		t.Fatal("gate stayed open with no physical network")
	}
	if path, _, _, effective, _ := networkAvailabilitySnapshot(); path || effective {
		t.Fatalf("snapshot disagrees with the gate: path=%t effective=%t", path, effective)
	}
}

func TestAbsentPhysicalPathWithholdsProbe(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setNetworkAvailable(false)
	setPhysicalPath(false)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if permit, ok := waitForNetworkPermit(ctx, true); ok {
		t.Fatalf("granted a permit with no physical network: %+v", permit)
	}
}

func TestLosingPhysicalPathDiscardsProof(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(false)
	markNetworkPathProven(generation)

	setPhysicalPath(false)
	setPhysicalPath(true)
	if isNetworkAvailable() {
		t.Fatal("proof earned on the vanished network reopened the gate on the next one")
	}
}

func TestSameNetworkReturningCanRenewProofInSameGeneration(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()

	generation := beginNetworkPathGeneration()
	setNetworkAvailable(false)
	markNetworkPathProven(generation)

	setPhysicalPath(false)
	setPhysicalPath(true)
	// A live stream of the same session accepts its next packet.
	markNetworkPathProven(generation)
	if !isNetworkAvailable() {
		t.Fatal("a path blip orphaned proof from the running session")
	}
}

func TestReturningPhysicalPathWakesParkedWorkerForProbe(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setNetworkAvailable(false)
	setPhysicalPath(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan networkPermit, 1)
	go func() {
		if permit, ok := waitForNetworkPermit(ctx, true); ok {
			got <- permit
		}
	}()

	select {
	case permit := <-got:
		t.Fatalf("worker left the gate with no physical network: %+v", permit)
	case <-time.After(50 * time.Millisecond):
	}

	// Android has not validated the returning network: the gate itself stays
	// closed, so only a wake plus the probe can get anyone out.
	setPhysicalPath(true)
	select {
	case permit := <-got:
		if !permit.unvalidatedProbe {
			t.Fatal("returning path opened the gate instead of granting the probe")
		}
		releaseNetworkPermit(permit)
	case <-time.After(time.Second):
		t.Fatal("parked worker was not woken when the physical network returned")
	}
}

func TestReturningPhysicalPathResumesOnValidatedNetwork(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setPhysicalPath(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan networkPermit, 1)
	go func() {
		if permit, ok := waitForNetworkPermit(ctx, true); ok {
			got <- permit
		}
	}()

	select {
	case permit := <-got:
		t.Fatalf("validation alone let a worker through with no physical network: %+v", permit)
	case <-time.After(50 * time.Millisecond):
	}

	setPhysicalPath(true)
	select {
	case permit := <-got:
		if permit.unvalidatedProbe {
			t.Fatal("validated network was handed a probe instead of an open gate")
		}
	case <-time.After(time.Second):
		t.Fatal("parked worker was not woken when the physical network returned")
	}
}

func TestRepeatedPhysicalPathReportKeepsProbeRateLimit(t *testing.T) {
	resetNetworkAvailabilityForTest()
	defer resetNetworkAvailabilityForTest()
	setNetworkAvailable(false)

	probe, ok := waitForNetworkPermit(context.Background(), true)
	if !ok || !probe.unvalidatedProbe {
		t.Fatalf("expected the first worker to take the probe, got %+v ok=%t", probe, ok)
	}
	releaseNetworkPermit(probe)

	// A re-addressed but otherwise unchanged network reports "present" again.
	if setPhysicalPath(true) {
		t.Fatal("an unchanged path was reported as a change")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if permit, ok := waitForNetworkPermit(ctx, true); ok {
		t.Fatalf("a repeated present report reset the probe rate limit: %+v", permit)
	}
}
