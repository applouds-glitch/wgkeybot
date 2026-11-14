/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"testing"
	"time"
)

// economyTest puts the dials over TCP or UDP and the mode back to off, and
// restores both when the test ends.
func economyTest(t *testing.T, overTCP bool) {
	t.Helper()
	choice, useUDP := relayTransportChoice.Load(), activeUseUDP.Load()
	resetKeepaliveEconomy()
	if overTCP {
		relayTransportChoice.Store(relayTransportTCP)
	} else {
		relayTransportChoice.Store(relayTransportUDP)
	}
	t.Cleanup(func() {
		relayTransportChoice.Store(choice)
		activeUseUDP.Store(useUDP)
		resetKeepaliveEconomy()
	})
}

// The server's limits the wide grid has to stay inside (vk-turn-proxy,
// server/main.go and server/downlink_feedback.go). Copies: a change there does
// not fail here, and has to be read against keepalive_economy.go by hand.
const (
	serverClosesSilentStreamAfter = 180 * time.Second // 3 × streamReadTimeout
	serverFeedbackTTL             = 75 * time.Second
)

func TestEconomyNeedsTheHostsWordAndTCP(t *testing.T) {
	now := time.Now()

	economyTest(t, true)
	if keepaliveEconomyOn(now) || keepaliveEvery(now) != keepaliveInterval {
		t.Fatal("the grid is wide without the host having asked")
	}
	setKeepaliveEconomyAsked(true)
	if !keepaliveEconomyOn(now) || keepaliveEvery(now) != economyKeepaliveInterval {
		t.Fatalf("asked, over TCP: the grid is %v, want %v", keepaliveEvery(now), economyKeepaliveInterval)
	}

	// Over UDP the interval is what holds the NAT mapping: it stays.
	relayTransportChoice.Store(relayTransportUDP)
	if keepaliveEconomyOn(now) || keepaliveEvery(now) != keepaliveInterval {
		t.Fatal("the grid is wide over UDP")
	}
	// And back with the transport, with nobody telling the mode.
	relayTransportChoice.Store(relayTransportTCP)
	if !keepaliveEconomyOn(now) {
		t.Fatal("the grid did not go wide when the dials went back to TCP")
	}
}

func TestEconomyAgesMoveWithTheGrid(t *testing.T) {
	economyTest(t, true)
	now := time.Now()
	if staleAfter(now) != dispatchStaleAfter || deadStreamAfter(now) != deadStreamTimeout ||
		wholePathGapAt(now) != wholePathGap || darkUpQuietAt(now) != darkUpQuiet {
		t.Fatal("the narrow grid's ages are not the ones it always had")
	}
	setKeepaliveEconomyAsked(true)
	if staleAfter(now) != economyStaleAfter || deadStreamAfter(now) != economyDeadStreamTimeout || wholePathGapAt(now) != economyStaleAfter {
		t.Fatalf("on the wide grid: stale after %v, dead after %v, the path's gap %v", staleAfter(now), deadStreamAfter(now), wholePathGapAt(now))
	}

	// Each age is past what a healthy idle stream shows: one interval, the
	// spread and a round trip between two echoes.
	healthyGap := economyKeepaliveInterval + keepaliveSpread + 3*time.Second
	if staleAfter(now) <= healthyGap {
		t.Fatalf("a healthy idle stream is stale on the wide grid: %v against a gap of %v", staleAfter(now), healthyGap)
	}
	if relayTCPKeepAlive.Idle <= healthyGap {
		t.Fatalf("the kernel probes a healthy idle socket on the wide grid: after %v, the gap is %v", relayTCPKeepAlive.Idle, healthyGap)
	}
	if darkUpQuietAt(now) <= economyKeepaliveInterval {
		t.Fatalf("an idle path is dark between two bursts of the wide grid: quiet for %v counts, the bursts are %v apart", darkUpQuietAt(now), economyKeepaliveInterval)
	}
	// Three windows before the detector, as on the narrow grid.
	if deadStreamAfter(now) < 3*economyKeepaliveInterval {
		t.Fatalf("the detector fires after %v: fewer than three windows of %v", deadStreamAfter(now), economyKeepaliveInterval)
	}

	// The server: the client replaces a silent stream before the server
	// closes it, and a report is repeated before the last one expires.
	if deadStreamAfter(now) >= serverClosesSilentStreamAfter {
		t.Fatalf("the server closes a silent stream after %v, before the detector's %v", serverClosesSilentStreamAfter, deadStreamAfter(now))
	}
	if economyKeepaliveInterval+keepaliveSpread >= serverFeedbackTTL {
		t.Fatalf("a WGH1 report expires on the server (%v) before the next one of the wide grid (%v)", serverFeedbackTTL, economyKeepaliveInterval)
	}
}

func TestWideGridPointsAreNarrowGridPoints(t *testing.T) {
	economyTest(t, true)
	base := time.Unix(1_800_000_000, 0)
	phase := 700 * time.Millisecond
	for off := time.Duration(0); off < 4*economyKeepaliveInterval; off += 3 * time.Second {
		now := base.Add(off)
		setKeepaliveEconomyAsked(false)
		narrow := nextKeepaliveGrid(now, phase)
		setKeepaliveEconomyAsked(true)
		wide := nextKeepaliveGrid(now, phase)

		if wide.Before(narrow) || wide.Sub(now) > economyKeepaliveInterval {
			t.Fatalf("at +%v: the wide grid's next point is %v away, the narrow one's %v", off, wide.Sub(now), narrow.Sub(now))
		}
		if d := wide.Sub(narrow); d != 0 && d != keepaliveInterval {
			t.Fatalf("at +%v: the wide point is %v after the narrow one — not a point of the narrow grid", off, d)
		}
		if next := nextKeepaliveGrid(wide, phase); next.Sub(wide) != economyKeepaliveInterval {
			t.Fatalf("at +%v: two wide points %v apart", off, next.Sub(wide))
		}
	}
}

// The gap a stream's keepalives have when the grid changes under it: never
// more than one wide interval, so nothing counted in wide intervals fires.
func TestChangingTheGridLeavesNoGapLongerThanTheWideInterval(t *testing.T) {
	economyTest(t, true)
	base := time.Unix(1_800_000_000, 0).Truncate(economyKeepaliveInterval)
	for _, start := range []time.Duration{0, keepaliveInterval} {
		for change := time.Second; change < keepaliveInterval; change += 4 * time.Second {
			// Narrow → wide: sent at a narrow point, the next wait already
			// armed on the narrow grid when the screen goes off.
			setKeepaliveEconomyAsked(false)
			sent := base.Add(start)
			armed := nextKeepaliveGrid(sent, 0)
			setKeepaliveEconomyAsked(true)
			after := nextKeepaliveGrid(armed, 0)
			if armed.Sub(sent) > economyKeepaliveInterval || after.Sub(armed) > economyKeepaliveInterval {
				t.Fatalf("narrow→wide from +%v: gaps of %v and %v", start, armed.Sub(sent), after.Sub(armed))
			}

			// Wide → narrow: the armed wait ends at a wide point, which the
			// narrow grid has too.
			sent = base
			armed = nextKeepaliveGrid(sent, 0)
			setKeepaliveEconomyAsked(false)
			_ = keepaliveEconomyOn(sent.Add(change))
			after = nextKeepaliveGrid(armed, 0)
			if armed.Sub(sent) != economyKeepaliveInterval || after.Sub(armed) != keepaliveInterval {
				t.Fatalf("wide→narrow: gaps of %v and %v, want %v and %v", armed.Sub(sent), after.Sub(armed), economyKeepaliveInterval, keepaliveInterval)
			}
			resetKeepaliveEconomy()
		}
	}
}

func TestIdleStreamOnTheWideGridIsNotStaleBetweenEchoes(t *testing.T) {
	economyTest(t, true)
	setKeepaliveEconomyAsked(true)
	// Off the grid's points, so that the detector's deadline is not one too.
	heard := time.Unix(1_800_000_007, 0)
	a := newStreamActivity(heard, 0)
	a.noteRx(heard)

	// The next echo is due one wide interval, the spread and a round trip on.
	for age := time.Second; age <= economyKeepaliveInterval+keepaliveSpread+3*time.Second; age += time.Second {
		if a.stale(heard.Add(age)) {
			t.Fatalf("a stream heard %v ago is stale on the wide grid: the dispatcher benches it and the server is told, between two echoes", age)
		}
	}
	if !a.stale(heard.Add(economyStaleAfter + time.Second)) {
		t.Fatalf("a stream that missed its echo is not stale %v on", economyStaleAfter+time.Second)
	}

	// The detector waits for the wide grid's age, not the narrow one's.
	deadline, reason := a.nextDeadline(heard.Add(2*economyKeepaliveInterval+time.Second), time.Time{}, time.Time{})
	if reason == keepaliveDeadCheckWake && !deadline.After(heard.Add(deadStreamTimeout)) {
		t.Fatalf("the detector's deadline on the wide grid is %v after the last packet", deadline.Sub(heard))
	}
	late := heard.Add(economyDeadStreamTimeout - time.Second)
	if deadline, reason = a.nextDeadline(late, time.Time{}, time.Time{}); reason != keepaliveDeadCheckWake || !deadline.Equal(heard.Add(economyDeadStreamTimeout)) {
		t.Fatalf("a second before the detector's age the next wake is %v after the last packet (reason %d), want the detector at %v",
			deadline.Sub(heard), reason, economyDeadStreamTimeout)
	}
}

// The screen comes on with every stream's last echo up to fifty seconds old:
// healthy by the grid they were on. They keep that grid's ages until each has
// had its points of the narrow one.
func TestNarrowingTheGridDoesNotBenchTheStreamsAtOnce(t *testing.T) {
	economyTest(t, true)
	setKeepaliveEconomyAsked(true)
	heard := time.Unix(1_800_000_000, 0)
	a := newStreamActivity(heard, 0)
	a.noteRx(heard)
	if !keepaliveEconomyOn(heard) {
		t.Fatal("the grid is not wide")
	}

	screenOn := heard.Add(45 * time.Second)
	setKeepaliveEconomyAsked(false)
	if keepaliveEvery(screenOn) != keepaliveInterval {
		t.Fatal("the grid did not narrow with the screen on")
	}
	if a.stale(screenOn) || a.stale(screenOn.Add(10*time.Second)) {
		t.Fatal("a stream healthy on the wide grid went stale the moment the grid narrowed")
	}
	if got := deadStreamAfter(screenOn.Add(time.Second)); got != economyDeadStreamTimeout {
		t.Fatalf("the detector's age a second after the grid narrowed is %v, want the wide grid's %v", got, economyDeadStreamTimeout)
	}
	// Not heard at the narrow grid's points either: stale by its age again.
	if !a.stale(heard.Add(economyStaleAfter + time.Second)) {
		t.Fatal("a stream past the wide grid's own age is not stale during the grace")
	}
	if got := darkUpQuietAt(screenOn.Add(time.Second)); got <= economyKeepaliveInterval {
		t.Fatalf("the dark path's quiet a second after the grid narrowed is %v: an idle path is dark between two wide bursts", got)
	}
	past := screenOn.Add(economyStaleAfter + time.Second)
	if darkUpQuietAt(past) != darkUpQuiet {
		t.Fatalf("after the grace the dark path's quiet is %v, want %v", darkUpQuietAt(past), darkUpQuiet)
	}
	if staleAfter(past) != dispatchStaleAfter || deadStreamAfter(past) != deadStreamTimeout {
		t.Fatalf("after the grace: stale after %v, dead after %v — the wide grid's ages stayed", staleAfter(past), deadStreamAfter(past))
	}
}

func TestWholePathGapOnTheWideGridIsNotAnIdlePeriod(t *testing.T) {
	economyTest(t, true)
	setKeepaliveEconomyAsked(true)
	if !keepaliveEconomyOn(time.Now()) {
		t.Fatal("the grid is not wide")
	}
	const overTCP = true
	i := proofTransport(overTCP)
	heardAt, gapEnd := relayHeardAt[i].Load(), relayGapEndAt[i].Load()
	t.Cleanup(func() {
		relayHeardAt[i].Store(heardAt)
		relayGapEndAt[i].Store(gapEnd)
	})

	// The last relay heard one wide interval ago: the idle tunnel's own gap.
	relayHeardAt[i].Store(int64(time.Since(relayHeardBase) - economyKeepaliveInterval - keepaliveSpread))
	relayGapEndAt[i].Store(0)
	since := time.Now().Add(-time.Hour)
	noteRelayHeard(overTCP)
	if pathGapEndedSince(overTCP, since) {
		t.Fatal("one period of the wide grid was taken for a silence of the whole path")
	}

	relayHeardAt[i].Store(int64(time.Since(relayHeardBase) - economyStaleAfter - 5*time.Second))
	noteRelayHeard(overTCP)
	if !pathGapEndedSince(overTCP, since) {
		t.Fatal("a silence past the wide grid's age is not on the record")
	}
}

func TestRefreshesOnTheWideGridAreNeverLaterThanPionsOwn(t *testing.T) {
	for _, interval := range []time.Duration{300 * time.Second, 240 * time.Second} {
		// Whatever phase the first tick has after the transaction, the tick
		// that sends it is the last one inside pion's interval.
		for first := time.Duration(0); first < economyKeepaliveInterval; first += 500 * time.Millisecond {
			age := first
			for !refreshDueOnGrid(age, interval, economyKeepaliveInterval) {
				age += economyKeepaliveInterval
			}
			if age > interval {
				t.Fatalf("interval %v, first tick at %v: sent %v after the last, later than pion would", interval, first, age)
			}
			if early := interval - age; early > economyKeepaliveInterval+keepaliveSpread {
				t.Fatalf("interval %v, first tick at %v: sent %v early, more than one wide interval", interval, first, early)
			}
		}
		if got := backstopAfter(interval, economyKeepaliveInterval); got != interval {
			t.Fatalf("the backstop of a %v transaction on the wide grid is %v, want pion's own", interval, got)
		}
	}
}

// pion checks the bindings every 30 s. With the backstop left there on the
// wide grid, it would run the check between two ticks of every period.
func TestBindingCheckBackstopStandsBehindTheWideGridsTick(t *testing.T) {
	const check = 30 * time.Second
	if got := backstopAfter(check, keepaliveInterval); got != check {
		t.Fatalf("on the narrow grid the backstop is %v, want pion's %v", got, check)
	}
	got := backstopAfter(check, economyKeepaliveInterval)
	if got <= economyKeepaliveInterval+keepaliveSpread {
		t.Fatalf("on the wide grid the backstop fires after %v: before the next tick, %v on", got, economyKeepaliveInterval)
	}
	// A binding is refreshed when a check finds it five minutes old, and
	// lives ten: a check per tick, and the backstop behind one missed tick,
	// are far inside that.
	if got > 2*economyKeepaliveInterval {
		t.Fatalf("the backstop waits %v", got)
	}

	economyTest(t, true)
	setKeepaliveEconomyAsked(true)
	var binds fakeRefresh
	start := time.Now()
	g := newRefreshGrid(1, start, []*gridRefresh{binds.refresh("the channel bindings", 40*time.Millisecond)})
	defer g.stop()
	// 40 ms is shorter than the wide grid, so the backstop is tens of seconds
	// away: nothing runs until a tick comes, and every tick runs it.
	time.Sleep(150 * time.Millisecond)
	if n := binds.runs.Load(); n != 0 {
		t.Fatalf("the backstop ran the check %d times between ticks of the wide grid", n)
	}
	g.tick(start.Add(economyKeepaliveInterval))
	waitFor(t, "the check at the tick", time.Second, func() bool { return binds.runs.Load() == 1 })
}

func TestFeedbackReportsOncePerWideGridWhileNothingChanges(t *testing.T) {
	economyTest(t, true)
	setKeepaliveEconomyAsked(true)
	start := time.Unix(1_800_000_000, 0).Truncate(economyKeepaliveInterval)
	a, b := feedbackTestStream(0, start), feedbackTestStream(1, start)
	streams := []*stream{a, b}
	var r downlinkReporter

	drain := func() (n int) {
		for _, s := range streams {
			for {
				select {
				case p := <-s.in:
					packetPool.Put(p[:cap(p)])
					n++
					continue
				default:
				}
				break
			}
		}
		return n
	}

	r.update(streams, start)
	r.update(streams, start.Add(time.Second)) // the repeat of a change
	if drain() == 0 {
		t.Fatal("no first report")
	}
	// One wide period of an idle tunnel, a look a second as the reporter
	// takes them: both streams heard at its start only.
	for at := 2 * time.Second; at < economyKeepaliveInterval; at += time.Second {
		r.update(streams, start.Add(at))
		if n := drain(); n != 0 {
			t.Fatalf("%d report(s) %v into a period of the wide grid with nothing changed: the radio woken between two bursts", n, at)
		}
	}
	// At the next point of the grid the streams are heard and the report is
	// repeated, as on the narrow grid.
	next := start.Add(economyKeepaliveInterval)
	a.activity.Load().noteRx(next)
	b.activity.Load().noteRx(next)
	r.update(streams, next)
	if drain() == 0 {
		t.Fatal("no report at the wide grid's next point")
	}
}

// The grid's width changes with the screen: in the second half of a wide period
// the 25 s point is past the 50 s one. Neither change is a new grid point, and
// neither sends a report (codex review of the iOS port, 2026-11-13). A clock
// set back by more than a wide interval is a new point.
func TestFeedbackIsNotResentWhenTheGridWidthChanges(t *testing.T) {
	economyTest(t, true)
	wide := time.Unix(1_800_000_000, 0).Truncate(economyKeepaliveInterval)
	start := wide.Add(keepaliveInterval + 12*time.Second) // second half of the wide period
	a, b := feedbackTestStream(0, start), feedbackTestStream(1, start)
	streams := []*stream{a, b}
	var r downlinkReporter
	drain := func() (n int) {
		for _, s := range streams {
			for {
				select {
				case p := <-s.in:
					packetPool.Put(p[:cap(p)])
					n++
					continue
				default:
				}
				break
			}
		}
		return n
	}

	r.update(streams, start)
	r.update(streams, start.Add(time.Second)) // the repeat of a change
	if drain() == 0 {
		t.Fatal("no first report")
	}
	for i, at := range []time.Duration{2, 3, 4, 5, 6, 7} {
		setKeepaliveEconomyAsked(i%2 == 0) // sleep, wake, sleep…
		r.update(streams, start.Add(at*time.Second))
		if n := drain(); n != 0 {
			t.Fatalf("%d report(s) at +%ds after the grid went %v wide, nothing changed", n, at, keepaliveEvery(start.Add(at*time.Second)))
		}
	}
	setKeepaliveEconomyAsked(false)
	next := wide.Add(economyKeepaliveInterval)
	a.activity.Load().noteRx(next)
	b.activity.Load().noteRx(next)
	r.update(streams, next)
	if drain() == 0 {
		t.Fatal("no report at the next grid point")
	}
	back := next.Add(-2 * time.Hour)
	a.activity.Load().noteRx(back)
	b.activity.Load().noteRx(back)
	r.update(streams, back)
	if drain() == 0 {
		t.Fatal("no report after the clock was set back: the routine reports stopped")
	}
}
