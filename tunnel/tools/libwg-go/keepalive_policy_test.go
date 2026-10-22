/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"sync"
	"sync/atomic"
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
	deadlineA, reasonA := a.nextDeadline(checkAt, time.Time{}, time.Time{})
	deadlineB, reasonB := b.nextDeadline(checkAt, time.Time{}, time.Time{})
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
			deadline, _ := a.nextDeadline(checkAt, time.Time{}, time.Time{})
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
	want, _ := a.nextDeadline(checkAt, time.Time{}, time.Time{})
	a.noteRx(checkAt.Add(4 * time.Second))
	if got, reason := a.nextDeadline(checkAt, time.Time{}, time.Time{}); !got.Equal(want) || reason != keepaliveGridWake {
		t.Fatalf("traffic shifted keepalive grid: got=%v want=%v", got, want)
	}
}

func TestProbeCadenceCannotPostponeDeadStreamDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now, keepalivePhase(0, 8))
	checkAt := now.Add(deadStreamTimeout - time.Second)
	retryAt := now.Add(4 * keepaliveInterval)

	deadline, reason := a.nextDeadline(checkAt, retryAt, time.Time{})
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

	deadline, reason := a.nextDeadline(checkAt, retryAt, time.Time{})
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
	deadline, _ := a.nextDeadline(now, time.Time{}, time.Time{})
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

func TestWireGuardKeepaliveRunsOncePerSharedGrid(t *testing.T) {
	var calls atomic.Int64
	sender := installWireGuardKeepaliveSender(func() { calls.Add(1) })
	defer clearWireGuardKeepaliveSender(sender)

	grid := time.Unix(1_700_000_000, 0).Truncate(keepaliveInterval)
	var wg sync.WaitGroup
	for id := 0; id < 40; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sendWireGuardKeepaliveOnSharedGrid(grid.Add(keepalivePhase(id, 40)))
		}(id)
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("same-grid WireGuard keepalive calls=%d, want 1", got)
	}

	if !sendWireGuardKeepaliveOnSharedGrid(grid.Add(keepaliveInterval)) {
		t.Fatal("next shared grid did not send a WireGuard keepalive")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("two-grid WireGuard keepalive calls=%d, want 2", got)
	}
}

func TestWireGuardKeepaliveSenderLifecycleDoesNotConsumeGrid(t *testing.T) {
	grid := time.Unix(1_700_000_000, 0).Truncate(keepaliveInterval)
	if sendWireGuardKeepaliveOnSharedGrid(grid) {
		t.Fatal("keepalive sent without an installed WireGuard device")
	}

	var calls atomic.Int64
	first := installWireGuardKeepaliveSender(func() { calls.Add(1) })
	if !sendWireGuardKeepaliveOnSharedGrid(grid) {
		t.Fatal("new sender did not send in the current grid")
	}
	clearWireGuardKeepaliveSender(first)
	if sendWireGuardKeepaliveOnSharedGrid(grid.Add(keepaliveInterval)) {
		t.Fatal("cleared sender still sent a keepalive")
	}

	second := installWireGuardKeepaliveSender(func() { calls.Add(1) })
	defer clearWireGuardKeepaliveSender(second)
	if !sendWireGuardKeepaliveOnSharedGrid(grid) {
		t.Fatal("replacement sender inherited the previous sender's grid state")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("sender lifecycle calls=%d, want 2", got)
	}
}

// The repeat of a keepalive nothing answered comes before the grid does, and
// the dead-stream check still cannot be postponed by it.
func TestMissedEchoRepeatComesBeforeTheGrid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now, keepalivePhase(0, 8))
	sentAt := now.Add(10 * time.Second)
	echoAt := sentAt.Add(keepaliveEchoRetry)

	deadline, reason := a.nextDeadline(sentAt, time.Time{}, echoAt)
	if !deadline.Equal(echoAt) || reason != keepaliveEchoRetryWake {
		t.Fatalf("deadline=%v reason=%v, want the repeat at %v", deadline, reason, echoAt)
	}
	// Nothing pending: the grid, as before.
	if _, reason := a.nextDeadline(sentAt, time.Time{}, time.Time{}); reason != keepaliveGridWake {
		t.Fatalf("reason=%v with no repeat pending, want the grid", reason)
	}
	// The dead-stream check wins over a repeat due after it.
	late := now.Add(deadStreamTimeout - time.Second)
	deadline, reason = a.nextDeadline(late, time.Time{}, late.Add(2*time.Second))
	if !deadline.Equal(now.Add(deadStreamTimeout)) || reason != keepaliveDeadCheckWake {
		t.Fatalf("deadline=%v reason=%v, want the dead-stream check", deadline, reason)
	}
}

// Only what arrived since the keepalive went out answers it: its echo, or
// data. A packet from before it does not, nor does a freeze reset.
func TestEchoMissedReadsOnlyWhatArrivedSinceTheSend(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := newStreamActivity(now, 0)
	sentAt := now.Add(10 * time.Second)
	a.noteRx(sentAt.Add(-time.Second))
	if !a.echoMissed(sentAt) {
		t.Fatal("a packet from before the keepalive counted as its answer")
	}
	a.noteRx(sentAt.Add(80 * time.Millisecond))
	if a.echoMissed(sentAt) {
		t.Fatal("a packet after the keepalive did not count as its answer")
	}
	b := newStreamActivity(now, 0)
	b.resetLiveness(sentAt.Add(time.Second))
	if !b.echoMissed(sentAt) {
		t.Fatal("a freeze reset counted as an answer")
	}
}

// keepaliveLoop runs runKeepalive on a fresh stream whose next grid keepalive
// falls due about lead from now, over UDP or TCP. rx, if set, runs inside
// every send, as the RX goroutine would on the echo. The sends' times come
// back on sends; stop ends the loop.
func keepaliveLoop(t *testing.T, overTCP bool, lead time.Duration, rx func(*streamActivity)) (sends chan time.Time, stop func()) {
	t.Helper()
	// The grid is wall-clock: a phase that lands the next grid point lead from
	// now, chosen once the boundary is at least that far off.
	var phase time.Duration
	for {
		now := time.Now()
		phase = now.Sub(now.Truncate(keepaliveInterval)) + lead
		if phase < keepaliveInterval {
			break
		}
		time.Sleep(lead)
	}
	activity := newStreamActivity(time.Now(), phase)
	sends = make(chan time.Time, 64)
	s := &stream{id: 5}
	s.overTCP.Store(overTCP)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runKeepalive(ctx, activity, func(error) {}, func(int) error {
			select {
			case sends <- time.Now():
			default:
			}
			if rx != nil {
				rx(activity)
			}
			return nil
		}, nil)
	}()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return sends, stop
}

func sendWithin(t *testing.T, sends chan time.Time, within time.Duration, what string) time.Time {
	t.Helper()
	select {
	case at := <-sends:
		return at
	case <-time.After(within):
		t.Fatalf("%s did not go out within %v", what, within)
		return time.Time{}
	}
}

func noSendFor(t *testing.T, sends chan time.Time, d time.Duration, what string) {
	t.Helper()
	select {
	case at := <-sends:
		t.Fatalf("%s went out at %v", what, at)
	case <-time.After(d):
	}
}

// A keepalive nothing answers goes out again once, keepaliveEchoRetry later;
// one that is answered — by its echo or by data — does not; over TCP alike,
// the echo crossing the relay's UDP leg to the server (22.10).
func TestKeepaliveIsSentAgainOnceWhenNothingAnswersIt(t *testing.T) {
	defer func(d time.Duration) { keepaliveEchoRetry = d }(keepaliveEchoRetry)
	keepaliveEchoRetry = 100 * time.Millisecond
	const lead = 300 * time.Millisecond
	// The grid point may, rarely, have passed before the loop takes its first
	// look; then the next one is a whole interval away.
	firstWithin := keepaliveInterval + 2*lead

	sends, stop := keepaliveLoop(t, false, lead, nil)
	first := sendWithin(t, sends, firstWithin, "the grid keepalive")
	second := sendWithin(t, sends, time.Second, "the repeat")
	// The repeat is timed from before the first send, the first's stamp taken
	// inside it: the gap can fall a hair short of keepaliveEchoRetry.
	if gap := second.Sub(first); gap < keepaliveEchoRetry/2 || gap > 10*keepaliveEchoRetry {
		t.Fatalf("the keepalive went out again %v after the first, want about %v", gap, keepaliveEchoRetry)
	}
	noSendFor(t, sends, 5*keepaliveEchoRetry, "a second repeat")
	stop()

	sends, stop = keepaliveLoop(t, false, lead, func(a *streamActivity) { a.noteRx(time.Now()) })
	sendWithin(t, sends, firstWithin, "the grid keepalive")
	noSendFor(t, sends, 5*keepaliveEchoRetry, "a repeat of an answered keepalive")
	stop()

	sends, stop = keepaliveLoop(t, true, lead, nil)
	sendWithin(t, sends, firstWithin, "the grid keepalive over TCP")
	sendWithin(t, sends, time.Second, "the repeat over TCP")
	noSendFor(t, sends, 5*keepaliveEchoRetry, "a second repeat over TCP")
	stop()

	sends, stop = keepaliveLoop(t, true, lead, func(a *streamActivity) { a.noteRx(time.Now()) })
	sendWithin(t, sends, firstWithin, "the grid keepalive over TCP")
	noSendFor(t, sends, 5*keepaliveEchoRetry, "a repeat of an answered keepalive over TCP")
	stop()
}

// A wake for the repeat that comes only after the next grid point — the
// process held up past it, short of a freeze — serves that grid point at once,
// not a whole interval later; here over TCP, with the first keepalive's echo
// in, as in the review's case (codex review 2026-10-22). Slow: one grid
// interval of real time.
func TestALateRepeatWakeServesTheGridPointItMissed(t *testing.T) {
	if testing.Short() {
		t.Skip("waits one keepalive interval")
	}
	defer func(d time.Duration) { keepaliveEchoRetry = d }(keepaliveEchoRetry)
	keepaliveEchoRetry = 100 * time.Millisecond
	var waits atomic.Int32
	prev := keepaliveWait
	keepaliveWait = func(ctx context.Context, deadline time.Time, wake <-chan struct{}) (bool, bool) {
		if waits.Add(1) == 2 { // the repeat's, after the first grid keepalive
			deadline = deadline.Add(keepaliveInterval)
		}
		return prev(ctx, deadline, wake)
	}
	t.Cleanup(func() { keepaliveWait = prev })
	const lead = 300 * time.Millisecond

	sends, _ := keepaliveLoop(t, true, lead, func(a *streamActivity) { a.noteRx(time.Now()) })
	first := sendWithin(t, sends, keepaliveInterval+2*lead, "the grid keepalive")
	second := sendWithin(t, sends, keepaliveInterval+2*time.Second, "the keepalive after the late wake")
	if gap := second.Sub(first); gap > keepaliveInterval+time.Second {
		t.Fatalf("the next keepalive went out %v after the first: want the grid point the late wake missed, about %v", gap, keepaliveInterval)
	}
}
