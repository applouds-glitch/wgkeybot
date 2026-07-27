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
	// Same slot (ids 3 and 11 collapse to the same phase at a fan-out of 8) —
	// identical grid.
	a := newStreamActivity(now, keepalivePhase(3, 8))
	b := newStreamActivity(now.Add(7*time.Second), keepalivePhase(11, 8))

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

// Sibling streams must not transmit at the same instant (a single lost burst
// would starve every liveness clock together), yet must stay inside one radio
// wake window. Holds at every fan-out, not just the common 8.
func TestSiblingStreamsAreStaggeredWithinOneWakeWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	checkAt := now.Add(10 * time.Second)

	for _, total := range []int{1, 2, 4, 8, 12, 40} {
		seen := make(map[time.Time]int, total)
		var earliest, latest time.Time
		for id := 0; id < total; id++ {
			a := newStreamActivity(now, keepalivePhase(id, total))
			deadline, _ := a.nextDeadline(checkAt, time.Time{})
			if prev, dup := seen[deadline]; dup {
				t.Fatalf("total=%d: streams %d and %d fire at the same instant %v", total, prev, id, deadline)
			}
			seen[deadline] = id
			if earliest.IsZero() || deadline.Before(earliest) {
				earliest = deadline
			}
			if deadline.After(latest) {
				latest = deadline
			}
		}
		if spread := latest.Sub(earliest); spread >= keepaliveSpread {
			t.Fatalf("total=%d: spread=%v, want < %v so the burst stays in one radio window", total, spread, keepaliveSpread)
		}
	}
}

// The stagger must not lengthen any stream's own NAT-hold gap: phase is constant,
// so consecutive keepalives of one stream stay exactly keepaliveInterval apart.
func TestPhaseDoesNotStretchPerStreamInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, total := range []int{1, 2, 8, 12} {
		for id := 0; id < total; id++ {
			phase := keepalivePhase(id, total)
			first := nextKeepaliveGrid(now, phase)
			second := nextKeepaliveGrid(first, phase)
			if gap := second.Sub(first); gap != keepaliveInterval {
				t.Fatalf("total=%d stream %d: gap=%v, want %v", total, id, gap, keepaliveInterval)
			}
		}
	}
}

// A degenerate or not-yet-known stream count must not produce a negative or
// out-of-window phase — those would silently shorten a stream's NAT-hold gap.
func TestKeepalivePhaseHandlesDegenerateCounts(t *testing.T) {
	for _, tc := range []struct{ id, total int }{
		{0, 0}, {0, 1}, {3, 0}, {3, 1}, {-1, 8}, {5, -2}, {9, 8},
	} {
		phase := keepalivePhase(tc.id, tc.total)
		if phase < 0 || phase >= keepaliveSpread {
			t.Fatalf("keepalivePhase(%d, %d)=%v, want within [0, %v)", tc.id, tc.total, phase, keepaliveSpread)
		}
	}
}

func TestRealTrafficDoesNotShiftSharedKeepaliveGrid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now, keepalivePhase(2, 8))
	checkAt := now.Add(10 * time.Second)
	want, _ := a.nextDeadline(checkAt, time.Time{})
	a.noteRx(checkAt.Add(4 * time.Second))
	if got, reason := a.nextDeadline(checkAt, time.Time{}); !got.Equal(want) || reason != keepaliveGridWake {
		t.Fatalf("traffic shifted keepalive grid: got=%v want=%v", got, want)
	}
}

func TestProbeCadenceCannotPostponeDeadStreamDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now, keepalivePhase(0, 8))
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
	a := newStreamActivity(now, keepalivePhase(0, 8))
	checkAt := now.Add(10 * time.Second)
	retryAt := checkAt.Add(keepaliveSendRetry)

	deadline, reason := a.nextDeadline(checkAt, retryAt)
	if !deadline.Equal(retryAt) || reason != keepaliveRetryWake {
		t.Fatalf("deadline=%v reason=%v, want retry at %v", deadline, reason, retryAt)
	}
}

func TestFreezeResetClearsStaleLivenessInsteadOfClosing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now, keepalivePhase(0, 8))

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
	a := newStreamActivity(now, keepalivePhase(7, 8))
	deadline, _ := a.nextDeadline(now, time.Time{})
	if slept := deadline.Sub(now); slept > keepaliveInterval+freezeSlack {
		t.Fatalf("a normal grid sleep of %v would be misread as a freeze", slept)
	}
}

func TestSharedGridStaysWithinNatSafetyMargin(t *testing.T) {
	now := time.Unix(1_700_000_000, 1)
	for _, total := range []int{1, 8, 12} {
		for id := 0; id < total; id++ {
			deadline := nextKeepaliveGrid(now, keepalivePhase(id, total))
			if !deadline.After(now) || deadline.Sub(now) > keepaliveInterval {
				t.Fatalf("unsafe shared grid: total=%d stream=%d now=%v deadline=%v", total, id, now, deadline)
			}
		}
	}
}
