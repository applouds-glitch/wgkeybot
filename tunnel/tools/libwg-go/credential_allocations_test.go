/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func credentialSlotCounts(user, pass string) (active, refs int) {
	credentialAllocations.Lock()
	defer credentialAllocations.Unlock()
	if slots := credentialAllocations.byCred[credentialAllocationKey{user, pass}]; slots != nil {
		return len(slots.tokens), slots.refs
	}
	return 0, 0
}

func waitCredentialSlots(t *testing.T, user, pass string, wantActive, wantRefs int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		active, refs := credentialSlotCounts(user, pass)
		if active == wantActive && refs == wantRefs {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("credential slots: active=%d refs=%d, want active=%d refs=%d", active, refs, wantActive, wantRefs)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCredentialAllocationLimitAcrossSessions(t *testing.T) {
	user, pass := t.Name(), "pass"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	releases := make([]func(), 10)
	for i := range releases {
		var err error
		releases[i], err = acquireCredentialAllocation(ctx, user, pass)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(releases[i])
	}

	// A reconnect can cancel the old session before its allocations have
	// closed. Its leases must remain in force until their owners release them.
	cancel()
	waitCredentialSlots(t, user, pass, 10, 10)
	nextCtx, nextCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer nextCancel()
	acquired := make(chan func(), 1)
	errs := make(chan error, 1)
	go func() {
		release, err := acquireCredentialAllocation(nextCtx, user, pass)
		if err != nil {
			errs <- err
			return
		}
		acquired <- release
	}()
	waitCredentialSlots(t, user, pass, 10, 11)
	select {
	case release := <-acquired:
		release()
		t.Fatal("eleventh allocation bypassed the quota")
	default:
	}

	// An independent credential can connect even while this one is full.
	other, err := acquireCredentialAllocation(nextCtx, user+"-other", pass)
	if err != nil {
		t.Fatal(err)
	}
	other()
	waitCredentialSlots(t, user+"-other", pass, 0, 0)

	releases[0]()
	select {
	case release := <-acquired:
		t.Cleanup(release)
		waitCredentialSlots(t, user, pass, 10, 10)
		release()
	case err := <-errs:
		t.Fatalf("waiting reconnect failed: %v", err)
	case <-nextCtx.Done():
		t.Fatal("releasing an old allocation did not unblock the reconnect")
	}
	for _, release := range releases {
		release() // A duplicate close must not free another owner's slot.
	}
	waitCredentialSlots(t, user, pass, 0, 0)
}

func TestCredentialAllocationWaitIsCancellable(t *testing.T) {
	user, pass := t.Name(), "pass"
	for i := 0; i < 10; i++ {
		release, err := acquireCredentialAllocation(context.Background(), user, pass)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, err := acquireCredentialAllocation(ctx, user, pass)
		if release != nil {
			release()
		}
		done <- err
	}()
	waitCredentialSlots(t, user, pass, 10, 11)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter did not stop")
	}
	waitCredentialSlots(t, user, pass, 10, 10)
	if release, err := acquireCredentialAllocation(ctx, user+"-cancelled", pass); !errors.Is(err, context.Canceled) {
		if release != nil {
			release()
		}
		t.Fatalf("already cancelled request returned %v", err)
	}
	waitCredentialSlots(t, user+"-cancelled", pass, 0, 0)
}
