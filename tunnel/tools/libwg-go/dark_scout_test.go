/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// freshDark starts a test with no dark on either transport and none left behind.
func freshDark(t *testing.T) {
	t.Helper()
	resetDarkPaths()
	t.Cleanup(resetDarkPaths)
}

// pinDarkScout sets the scout's timing for a test.
func pinDarkScout(t *testing.T, gap, period, evidence time.Duration) {
	t.Helper()
	prevGap, prevPeriod, prevEvidence := darkScoutGap, darkScoutPeriod, darkEvidenceMin
	darkScoutGap, darkScoutPeriod, darkEvidenceMin = gap, period, evidence
	t.Cleanup(func() { darkScoutGap, darkScoutPeriod, darkEvidenceMin = prevGap, prevPeriod, prevEvidence })
}

// A dark holds until a relay is heard over its transport — and only its own:
// the other transport's path says nothing about it.
func TestADarkHoldsUntilARelayIsHeardOverItsTransport(t *testing.T) {
	freshDark(t)
	now := time.Now()
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	if !pathStillDark(true) {
		t.Fatal("a dark just found does not hold")
	}
	noteRelayHeard(false)
	if !pathStillDark(true) {
		t.Fatal("a relay heard over UDP ended the dark over TCP")
	}
	noteRelayHeard(true)
	if pathStillDark(true) {
		t.Fatal("a relay heard over TCP left the dark holding")
	}

	// Found against a mark that has moved since, it is no dark at all.
	stale := relayHeardMark(true)
	noteRelayHeard(true)
	noteDarkPath(true, stale, darkEpoch(), now, now)
	if pathStillDark(true) {
		t.Fatal("a dark was found on evidence a relay heard since contradicts")
	}
}

// The turns pass down the line: each parked worker dials in its turn and goes
// to the back, a turn is due a period after the last began and a gap after it
// ended, and a scout that does not come back loses its turn to the next.
func TestScoutTurnsPassDownTheLine(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 100*time.Millisecond, time.Second, 0)
	a, b, c := &stream{id: 1}, &stream{id: 2}, &stream{id: 3}
	t0 := time.Now()
	for _, s := range []*stream{a, b, c} {
		waitInTheDark(s, true)
	}
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), t0, t0) // found by an attempt that began and failed at t0

	if taken, _ := takeDarkScout(a, true, t0.Add(500*time.Millisecond)); taken {
		t.Fatal("a turn was taken before a period had passed since the attempt that found the dark")
	}
	at := t0.Add(time.Second)
	if taken, _ := takeDarkScout(b, true, at); taken {
		t.Fatal("the second in line took the first's turn")
	}
	if taken, _ := takeDarkScout(a, true, at); !taken {
		t.Fatal("the head of the line did not get its turn when it was due")
	}
	if taken, _ := takeDarkScout(b, true, at.Add(5*time.Second)); taken {
		t.Fatal("the next turn was taken while the scout's was live")
	}
	if !darkScoutDials(a, true, at) {
		t.Fatal("the scout holding its turn was kept from dialing")
	}

	// a's attempt failed at once: its verdict keeps the dark, and the next turn
	// waits out a period from its start, not just a gap from its end.
	darkScoutDone(a, true, at, at, true)
	waitInTheDark(a, true)
	if taken, _ := takeDarkScout(b, true, at.Add(500*time.Millisecond)); taken {
		t.Fatal("an attempt refused at once was followed by the next within its period")
	}
	at = at.Add(time.Second)
	if taken, _ := takeDarkScout(b, true, at); !taken {
		t.Fatal("the next in line did not get its turn")
	}

	// b never comes back: after its lease c goes, and a after c.
	if taken, _ := takeDarkScout(c, true, at.Add(darkScoutLease-time.Second)); taken {
		t.Fatal("a turn passed on before the scout's lease had run out")
	}
	at = at.Add(darkScoutLease)
	if taken, _ := takeDarkScout(c, true, at); !taken {
		t.Fatal("a scout that never came back kept its turn past its lease")
	}
	if !darkScoutDials(c, true, at) {
		t.Fatal("the next scout was kept from dialing")
	}
	darkScoutDone(c, true, at, at.Add(7*time.Second), true)
	if taken, _ := takeDarkScout(a, true, at.Add(7*time.Second+darkScoutGap)); !taken {
		t.Fatal("the worker back in line did not get its next turn")
	}
}

// A scout that is not back with its credential within its lease loses its
// turn — to the next in line, or to nobody — and has no say after: it does not
// dial beside the next scout, and its late verdict does not find the dark
// again (Codex review, 18.10).
func TestAScoutWhoseTurnHasPassedHasNoSay(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	a, b := &stream{id: 1}, &stream{id: 2}
	now := time.Now()
	waitInTheDark(a, true)
	waitInTheDark(b, true)
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, true, now); !taken {
		t.Fatal("no turn for a")
	}
	if taken, _ := takeDarkScout(b, true, now.Add(darkScoutLease-time.Second)); taken {
		t.Fatal("the turn passed on before the scout's lease had run out")
	}

	// a is not back by its lease: b takes the turn, and a stays out of it.
	later := now.Add(darkScoutLease)
	if taken, _ := takeDarkScout(b, true, later); !taken {
		t.Fatal("no turn for b after a's lease ran out")
	}
	if darkScoutDials(a, true, later) {
		t.Fatal("a former scout dialed beside the one holding the turn")
	}
	litPath(true)
	noteRelayHeard(true)
	darkScoutDone(a, true, now, later, true)
	if pathStillDark(true) {
		t.Fatal("the verdict of a scout whose turn had passed found the dark again")
	}
}

// A scout past its lease with nobody in line to take the turn has lost it all
// the same: back with its credential into a dark that holds, it does not dial;
// back once the light is, it dials as any worker would, and its verdict has no
// say in the dark.
func TestAScoutPastItsLeaseLosesTheTurnWithNobodyToTakeIt(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	a := &stream{id: 1}
	now := time.Now()
	waitInTheDark(a, true)
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, true, now); !taken {
		t.Fatal("no turn for a")
	}
	later := now.Add(darkScoutLease + time.Second)
	if darkScoutDials(a, true, later) {
		t.Fatal("a scout back past its lease dialed the dark as the scout")
	}
	if darkScouted(&stream{id: 2}, true, later) {
		t.Fatal("the lost turn still read as live")
	}
	noteRelayHeard(true)
	if !darkScoutDials(a, true, later) {
		t.Fatal("a worker back once the light was kept from dialing")
	}
	darkScoutDone(a, true, now, later, true)
	if pathStillDark(true) {
		t.Fatal("the verdict of a scout that lost its turn found the dark again")
	}
}

// A scout that has dialed holds its turn until its verdict, however long its
// attempt runs: the lease bounds only the wait for its credential. Past it,
// with a relay heard meanwhile, the line still waits for the verdict, nobody
// takes the turn, and the park's limit does not let anybody go (Codex review,
// 19.10).
func TestADialingScoutHoldsItsTurnPastItsLease(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	a, b := &stream{id: 1}, &stream{id: 2}
	now := time.Now()
	waitInTheDark(a, true)
	waitInTheDark(b, true)
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(a, true, now); !taken {
		t.Fatal("no turn for a")
	}
	dialed := now.Add(15 * time.Second)
	if !darkScoutDials(a, true, dialed) {
		t.Fatal("the scout holding its turn was kept from dialing")
	}
	long := dialed.Add(2 * darkScoutLease)
	if taken, _ := takeDarkScout(b, true, long); taken {
		t.Fatal("the turn passed on while the scout was still dialing")
	}
	noteRelayHeard(true) // its SYN-ACK, say
	if darkReleases(true, long) {
		t.Fatal("the line was let go before the dialing scout's verdict")
	}
	if !darkScouted(b, true, long) {
		t.Fatal("a dialing scout past its lease no longer kept the others parked")
	}
	darkScoutDone(a, true, dialed, long, true)
	if !pathStillDark(true) {
		t.Fatal("the verdict of the scout that held its turn did not find the dark again")
	}
	if taken, _ := takeDarkScout(b, true, long); !taken {
		t.Fatal("no turn for b after a's verdict")
	}
}

// A reset of the dark — a network lost or back on the same handle — empties
// the line without waking anybody. Found again before the parked workers have
// looked, it must not leave them out of the line, with nobody to dial it.
func TestWorkersParkedThroughAResetStillTakeTheirTurns(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 50*time.Millisecond, 400*time.Millisecond, 0)
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	pinRelayConnectGap(t, 0)
	dials := stageRelayDials(t)
	var parks atomic.Int32
	waitsOf(t, func(w workerWait) {
		if w.parked {
			parks.Add(1)
		}
	})
	h := runWorkersAgainstPeer(t, 156, 2, []string{relay.addr}, echoingPeer(t))
	waitFor(t, "two streams over TCP", 8*time.Second, func() bool { return h.ready() == 2 })

	dials.dark.Store(true)
	for _, s := range h.streams {
		recycleAttempt(s.attempt.Load())
	}
	waitFor(t, "the two waiting", 5*time.Second, func() bool { return parks.Load() >= 2 })
	now := time.Now()
	resetDarkPaths()
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	tried := dials.tried.Load()
	waitFor(t, "a scout's dial after the reset", 3*time.Second, func() bool { return dials.tried.Load() > tried })
}

// A relay heard while a scout dials does not let the others go before the
// scout's attempt has had its say: a flicker of light that did not carry it
// through leaves the dark found again; one that did lets them go.
func TestTheOthersWaitForTheScoutsVerdict(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 0, 0, 0)
	scout, other := &stream{id: 1}, &stream{id: 2}
	now := time.Now()
	waitInTheDark(scout, true)
	waitInTheDark(other, true)
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	if taken, _ := takeDarkScout(scout, true, now); !taken {
		t.Fatal("no turn for the scout")
	}
	darkScoutDials(scout, true, now)

	noteRelayHeard(true) // its SYN-ACK, say
	if darkReleases(true, now) {
		t.Fatal("the others were let go on a relay heard while the scout's attempt was still under way")
	}
	darkScoutDone(scout, true, now, now, true)
	if !pathStillDark(true) || darkReleases(true, now) {
		t.Fatal("a flicker that did not carry the scout through ended the dark")
	}

	waitInTheDark(scout, true)
	if taken, _ := takeDarkScout(other, true, now); !taken {
		t.Fatal("no turn for the next scout")
	}
	darkScoutDials(other, true, now)
	noteRelayHeard(true)
	darkScoutDone(other, true, now, now, false)
	if !darkReleases(true, now) {
		t.Fatal("the others were kept once the light carried the scout through")
	}
}

// What finds a dark, and what does not: an attempt that ran long enough with
// no relay heard over its transport and no stream over it hearing its relay
// finds one; an instant failure of the phone's own network, a relay heard
// while it ran, or a stream that heard its relay lately does not.
func TestWhatFindsTheDark(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, darkScoutGap, darkScoutPeriod, 3*time.Second)
	t.Cleanup(func() { activeStreams.Store(nil) })
	timeout := dialTimedOut()
	now := time.Now()
	long := now.Add(-4 * time.Second)

	for _, tc := range []struct {
		name    string
		start   time.Time
		err     error
		heard   bool // a relay heard over TCP while the attempt ran
		streams []*stream
		dark    bool
	}{
		{"a long silent attempt", long, timeout, false, nil, true},
		{"one that failed at once", now, timeout, false, nil, false},
		{"the phone's own network refusing it", long, opErr("connect", syscall.ENETUNREACH), false, nil, false},
		{"a relay heard while it ran", long, timeout, true, nil, false},
		{"a stream that heard its relay 10s ago", long, timeout, false, []*stream{lookout(true, false, now.Add(-10*time.Second))}, false},
		{"a stream silent for a minute", long, timeout, false, []*stream{lookout(true, false, now.Add(-time.Minute))}, true},
		{"a UDP stream hearing, over TCP", long, timeout, false, []*stream{lookout(false, false, now)}, true},
	} {
		resetDarkPaths()
		set := tc.streams
		activeStreams.Store(&set)
		mark := relayHeardMark(true)
		if tc.heard {
			noteRelayHeard(true)
		}
		if dark, _ := findsTheDark(true, mark, darkEpoch(), tc.start, tc.err, now); dark != tc.dark {
			t.Errorf("%s: dark=%v, want %v", tc.name, dark, tc.dark)
		}
	}

	// Once found, an instant local failure joins it.
	resetDarkPaths()
	activeStreams.Store(nil)
	mark := relayHeardMark(true)
	noteDarkPath(true, mark, darkEpoch(), long, now)
	if dark, why := findsTheDark(true, mark, darkEpoch(), now, opErr("connect", syscall.EPERM), now); !dark {
		t.Fatalf("an instant failure into a dark found did not join it (%s)", why)
	}
}

// End to end over TCP: three workers fail into a dark that stays (no lookout,
// the staged connects timing out). They wait, and they dial it one at a time,
// in turn — not all three over and over; the light back, the first to dial gets
// through and the others follow.
func TestWorkersWaitInTheDarkAndTakeTurnsDialingIt(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 50*time.Millisecond, 400*time.Millisecond, 0)
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	resetRevivalPacing()
	pinRelayConnectGap(t, 0) // the turns, not the connects to one relay, are what is timed
	dials := stageRelayDials(t)
	var mu sync.Mutex
	var parks []int
	waitsOf(t, func(w workerWait) {
		if w.parked {
			mu.Lock()
			parks = append(parks, w.stream)
			mu.Unlock()
		}
	})
	h := runWorkersAgainstPeer(t, 153, 3, []string{relay.addr}, echoingPeer(t))
	waitFor(t, "three streams over TCP", 8*time.Second, func() bool { return h.ready() == 3 })

	dials.dark.Store(true)
	began := time.Now()
	tried := dials.tried.Load()
	for _, s := range h.streams {
		recycleAttempt(s.attempt.Load())
	}
	// Every worker takes its turn: each comes back from one and parks again.
	turns := map[int]int{}
	var seen []int
	waitFor(t, "every worker's turn", 10*time.Second, func() bool {
		mu.Lock()
		seen = slices.Clone(parks)
		mu.Unlock()
		clear(turns)
		if len(seen) > 3 {
			for _, id := range seen[3:] {
				turns[id]++
			}
		}
		return len(turns) == 3
	})
	n := dials.tried.Load() - tried
	elapsed := time.Since(began)
	// Three that found the dark, then a turn every period at most — over the
	// time that actually passed, which a loaded machine stretches.
	if max := int32(3 + elapsed/darkScoutPeriod + 1); n > max {
		t.Fatalf("%d connects into the dark in %v, want at most %d: turns, not every worker dialing", n, elapsed.Round(time.Millisecond), max)
	}
	t.Logf("%d connects into the dark in %v; turns %v (parks %v)", n, elapsed.Round(time.Millisecond), turns, seen)

	dials.dark.Store(false)
	back := time.Now()
	waitFor(t, "the three back", 3*darkScoutPeriod+5*time.Second, func() bool { return h.ready() == 3 })
	t.Logf("all three back %v after the light", time.Since(back).Round(time.Millisecond))
}

// A relay heard while the scout dials — a flicker of light — that does not
// carry it through lets nobody else into the dark: its verdict finds it again,
// and the others wait for the next turn instead of all dialing.
func TestAFlickerTheScoutSawLetsNobodyElseIntoTheDark(t *testing.T) {
	freshDark(t)
	pinDarkScout(t, 50*time.Millisecond, 3*time.Second, 0)
	relay := startTCPTestRelay(t, listenTCPRelay(t))
	overTCP(t)
	pinRevivalGap(t, 100*time.Millisecond)
	pinRelayConnectGap(t, 0)
	dials := stageRelayDials(t)
	var flicker atomic.Bool
	var flickered atomic.Int32
	staged := dialRelayTCP
	dialRelayTCP = func(ctx context.Context, d *net.Dialer, to string) (net.Conn, error) {
		c, err := staged(ctx, d, to)
		if flicker.CompareAndSwap(true, false) {
			noteRelayHeard(true) // heard while the scout dialed, and nothing got through
			flickered.Store(dials.tried.Load())
		}
		return c, err
	}
	t.Cleanup(func() { dialRelayTCP = staged })
	var parks atomic.Int32
	waitsOf(t, func(w workerWait) {
		if w.parked {
			parks.Add(1)
		}
	})
	h := runWorkersAgainstPeer(t, 155, 3, []string{relay.addr}, echoingPeer(t))
	waitFor(t, "three streams over TCP", 8*time.Second, func() bool { return h.ready() == 3 })

	dials.dark.Store(true)
	for _, s := range h.streams {
		recycleAttempt(s.attempt.Load())
	}
	waitFor(t, "the three waiting", 5*time.Second, func() bool { return parks.Load() >= 3 })
	flicker.Store(true)
	waitFor(t, "the scout's dial", 5*time.Second, func() bool { return flickered.Load() != 0 })
	time.Sleep(1500 * time.Millisecond)
	if n := dials.tried.Load() - flickered.Load(); n != 0 {
		t.Fatalf("%d connect(s) within 1.5s of a flicker that did not carry the scout through, want none before the next turn", n)
	}
	if !pathStillDark(true) {
		t.Fatal("the flicker ended the dark")
	}
}

// Over UDP nothing stalls, and nothing used to park: an Allocate that no relay
// answered, with nothing heard over UDP meanwhile, now finds the dark.
func TestAnAllocateNobodyAnsweredFindsTheDarkOverUDP(t *testing.T) {
	freshDark(t)
	silent := listenFakeRelay(t)
	entered := waitsOf(t, nil)
	runWorkersAgainst(t, 154, 1, []string{silent.LocalAddr().String()})
	select {
	case w := <-entered:
		if !w.parked {
			t.Fatalf("the wait after an Allocate nobody answered is %+v, want parked", w)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the worker never went into a wait")
	}
	if !pathStillDark(false) {
		t.Fatal("no dark found over UDP")
	}
}

// A stream heard while workers wait ends the dark for all of them; so do a
// move to another network and the network lost.
func TestADarkEndsWithTheStreamsHearingOrTheMove(t *testing.T) {
	freshDark(t)
	resetNetworkSwitch(t)
	resetAllocationBook(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	t.Cleanup(func() { activeStreams.Store(nil) })
	now := time.Now()
	noteDarkPath(false, relayHeardMark(false), darkEpoch(), now, now)
	set := []*stream{lookout(false, false, now)}
	activeStreams.Store(&set)
	if dark, _ := findsTheDark(false, relayHeardMark(false), darkEpoch(), now.Add(-time.Minute), dialTimedOut(), now); dark {
		t.Fatal("a stream hearing its relay left the dark holding")
	}
	if pathStillDark(false) {
		t.Fatal("the dark was not ended by the stream hearing")
	}

	choice := relayTransportChoice.Load()
	setNetworkState(101, choice, now)
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	setNetworkState(202, choice, now)
	if pathStillDark(true) {
		t.Fatal("a move to another network left the dark over TCP")
	}
	noteDarkPath(true, relayHeardMark(true), darkEpoch(), now, now)
	setNetworkState(0, choice, now)
	if pathStillDark(true) {
		t.Fatal("the network lost left the dark over TCP")
	}
}

// How long the path has been silent, for the screen: an idle tunnel that heard
// nothing for a while is not silent; a dark found, or the lookout's stalled
// sockets, are — since the relay last heard; a relay heard ends it.
func TestPathSilenceIsCountedOnlyWhenTheStreamsKnowIt(t *testing.T) {
	freshDark(t)
	noteRelayHeard(true)
	heard := time.Now()
	later := heard.Add(40 * time.Second)

	idle := []*stream{lookout(true, false, heard)}
	if d := pathSilence(idle, true, later); d != 0 {
		t.Fatalf("an idle tunnel read as silent for %v", d)
	}

	stalled := []*stream{lookout(true, true, heard)}
	if d := pathSilence(stalled, true, later); d < 39*time.Second || d > 41*time.Second {
		t.Fatalf("stalled sockets with no relay heard for 40s: silent %v, want about 40s", d)
	}

	noteDarkPath(true, relayHeardMark(true), darkEpoch(), heard, heard)
	if d := pathSilence(nil, true, later); d < 39*time.Second || d > 41*time.Second {
		t.Fatalf("a dark found, the lookout gone: silent %v, want about 40s", d)
	}

	noteRelayHeard(true)
	if d := pathSilence(nil, true, time.Now()); d != 0 {
		t.Fatalf("a relay heard left the path silent for %v", d)
	}
}

// Over a transport no relay ever answered on, the silence counts from when the
// dark was found — not zero for as long as it lasts — and the dark of the
// transport not in use is not asked about (Codex review, 19.10).
func TestPathSilenceOverATransportNeverHeard(t *testing.T) {
	freshDark(t)
	i := proofTransport(false)
	prev := relayHeardAt[i].Load()
	relayHeardAt[i].Store(0)
	t.Cleanup(func() { relayHeardAt[i].Store(prev) })

	found := time.Now()
	noteDarkPath(false, relayHeardMark(false), darkEpoch(), found, found)
	later := found.Add(25 * time.Second)
	if d := pathSilence(nil, false, later); d < 24*time.Second || d > 26*time.Second {
		t.Fatalf("a dark over a transport never heard: silent %v, want about 25s", d)
	}
	if d := pathSilence(nil, true, later); d != 0 {
		t.Fatalf("the dark over UDP made TCP, the transport in use, silent for %v", d)
	}
}

// A dark found by an attempt begun on a path that a reset has since replaced is
// not recorded: the check is made under the reset's own lock, so the window
// between an attempt's look at its move and its finding cannot let it through
// (Codex review, 19.10).
func TestAFindingFromBeforeAResetIsNotRecorded(t *testing.T) {
	freshDark(t)
	t.Cleanup(func() { activeStreams.Store(nil) })
	activeStreams.Store(nil)
	epoch := darkEpoch()
	mark := relayHeardMark(true)
	now := time.Now()
	resetDarkPaths()
	if noteDarkPath(true, mark, epoch, now, now) {
		t.Fatal("a finding from the path before the reset was recorded")
	}
	if dark, _ := findsTheDark(true, mark, epoch, now.Add(-time.Minute), dialTimedOut(), now); dark {
		t.Fatal("an attempt from before the reset found the dark on the path after it")
	}
	if pathStillDark(true) {
		t.Fatal("a dark from the path before the reset holds on the one after")
	}
}

// A change of the transport in use ends the dark of the one left even when no
// attempt is there to recycle — a worker fetching its credential has none.
func TestASwitchOfTransportEndsTheDarkWithNoAttemptToRecycle(t *testing.T) {
	resetNetworkSwitch(t)
	prevUDP := activeUseUDP.Load()
	activeUseUDP.Store(true) // a config that says UDP
	prevChoice := relayTransportChoice.Load()
	t.Cleanup(func() {
		relayTransportChoice.Store(prevChoice)
		activeUseUDP.Store(prevUDP)
	})
	relayTransportChoice.Store(relayTransportAsConfigured)
	now := time.Now()
	setNetworkState(101, relayTransportAsConfigured, now)
	noteDarkPath(false, relayHeardMark(false), darkEpoch(), now, now)

	// "UDP" over a config that says UDP moves nobody, and keeps the dark.
	setNetworkState(101, relayTransportUDP, now)
	if !pathStillDark(false) {
		t.Fatal("a change of the setting that left the transport as it was ended the dark")
	}
	setNetworkState(101, relayTransportTCP, now)
	if pathStillDark(false) {
		t.Fatal("the dark over UDP outlived a switch to TCP with no attempt to recycle")
	}
}
