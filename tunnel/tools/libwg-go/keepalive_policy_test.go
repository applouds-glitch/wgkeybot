/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"testing"
	"time"
)

func TestStreamActivitiesShareKeepaliveGrid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now)
	b := newStreamActivity(now.Add(7 * time.Second))

	checkAt := now.Add(10 * time.Second)
	deadlineA, reasonA := a.nextDeadline(checkAt, time.Time{})
	deadlineB, reasonB := b.nextDeadline(checkAt, time.Time{})
	if !deadlineA.Equal(deadlineB) {
		t.Fatalf("streams use different keepalive grids: a=%v b=%v", deadlineA, deadlineB)
	}
	if reasonA != keepaliveGridWake || reasonB != keepaliveGridWake {
		t.Fatalf("unexpected wake reasons: a=%v b=%v", reasonA, reasonB)
	}
}

func TestRealTrafficDoesNotShiftSharedKeepaliveGrid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now)
	checkAt := now.Add(10 * time.Second)
	want, _ := a.nextDeadline(checkAt, time.Time{})
	a.noteRx(checkAt.Add(4 * time.Second))
	if got, reason := a.nextDeadline(checkAt, time.Time{}); !got.Equal(want) || reason != keepaliveGridWake {
		t.Fatalf("traffic shifted keepalive grid: got=%v want=%v", got, want)
	}
}

func TestProbeCadenceCannotPostponeDeadStreamDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now)
	checkAt := now.Add(deadStreamTimeout - time.Second)
	retryAt := now.Add(4 * keepaliveInterval)

	deadline, reason := a.nextDeadline(checkAt, retryAt)
	want := now.Add(deadStreamTimeout)
	if !deadline.Equal(want) {
		t.Fatalf("deadline=%v, want exact dead-stream check at %v", deadline, want)
	}
	if reason != keepaliveDeadCheckWake {
		t.Fatalf("reason=%v, want dead-stream check", reason)
	}
}

func TestFailedSendRetriesBeforeGrid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now)
	checkAt := now.Add(10 * time.Second)
	retryAt := checkAt.Add(keepaliveSendRetry)

	deadline, reason := a.nextDeadline(checkAt, retryAt)
	if !deadline.Equal(retryAt) || reason != keepaliveRetryWake {
		t.Fatalf("deadline=%v reason=%v, want retry at %v", deadline, reason, retryAt)
	}
}

func TestFreezeResetClearsStaleLivenessInsteadOfClosing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now)

	// A host freeze leaves rxAge far past the dead-stream threshold even though
	// the path itself may be fine; resetLiveness must make the stream survivable
	// again rather than leaving it to the dead-stream detector.
	thaw := now.Add(deadStreamTimeout + 5*time.Minute)
	if a.rxAge(thaw) < deadStreamTimeout {
		t.Fatalf("setup: rxAge=%v, want >= %v", a.rxAge(thaw), deadStreamTimeout)
	}
	a.resetLiveness(thaw)
	if age := a.rxAge(thaw); age != 0 {
		t.Fatalf("rxAge=%v after freeze reset, want 0", age)
	}
}

func TestSleepWithinGridIsNotTreatedAsFreeze(t *testing.T) {
	// nextDeadline never returns a point beyond the shared grid, so the longest
	// legitimate sleep is one interval. The freeze test in runKeepalive keys off
	// keepaliveInterval+freezeSlack and must not fire on that.
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now)
	deadline, _ := a.nextDeadline(now, time.Time{})
	if slept := deadline.Sub(now); slept > keepaliveInterval+freezeSlack {
		t.Fatalf("a normal grid sleep of %v would be misread as a freeze", slept)
	}
}

func TestSharedGridStaysWithinNatSafetyMargin(t *testing.T) {
	now := time.Unix(1_700_000_000, 1)
	deadline := nextKeepaliveGrid(now)
	if !deadline.After(now) || deadline.Sub(now) > keepaliveInterval {
		t.Fatalf("unsafe shared grid: now=%v deadline=%v", now, deadline)
	}
}
