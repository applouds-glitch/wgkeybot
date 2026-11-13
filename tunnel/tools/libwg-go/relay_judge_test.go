package main

import (
	"context"
	"fmt"
	"maps"
	"math"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func window(aLost, bLost int) []relayLossSample {
	return []relayLossSample{
		{relay: "A", rx: 1000 - aLost, lost: aLost},
		{relay: "B", rx: 1000 - bLost, lost: bLost},
	}
}

// judged weighs one window and returns the relays it rests, in sample order.
func judged(j *relayJudge, samples []relayLossSample) string {
	var out []string
	for _, v := range j.step(samples) {
		out = append(out, v.relay)
	}
	return strings.Join(out, ",")
}

func TestRelayJudgeRestsTheRelayThatLosesAlone(t *testing.T) {
	var j relayJudge
	if bad := judged(&j, window(120, 10)); bad != "" {
		t.Fatalf("verdict after one window: %s", bad)
	}
	v := j.step(window(150, 15))
	if len(v) != 1 || v[0].relay != "A" || v[0].rate != 0.15 || v[0].best != 0.015 {
		t.Fatalf("verdict = %+v, want A at 15%% against 1.5%% after two windows", v)
	}
}

// The tired relay of 2026-10-10 that a 5% floor let through: 4-5% against 0%.
func TestRelayJudgeRestsAModestLossAgainstACleanRelay(t *testing.T) {
	var j relayJudge
	if bad := judged(&j, window(42, 0)); bad != "" {
		t.Fatalf("verdict after one window: %s", bad)
	}
	if bad := judged(&j, window(52, 1)); bad != "A" {
		t.Fatalf("verdict = %q, want A after two windows", bad)
	}

	// The relays of 2026-10-11 that a 4-point margin let through: a steady
	// 3.3-4% against 0-0.5%.
	j = relayJudge{}
	if bad := judged(&j, window(39, 2)); bad != "" {
		t.Fatalf("verdict after one window: %s", bad)
	}
	if bad := judged(&j, window(33, 0)); bad != "A" {
		t.Fatalf("verdict = %q, want A after two windows", bad)
	}
}

func TestRelayJudgeLeavesRelaysThatLoseAlike(t *testing.T) {
	cases := map[string][]relayLossSample{
		"both clean":           window(2, 8),       // 0.2% vs 0.8%: a ratio, no margin
		"both saturated":       window(90, 60),     // 9% vs 6%: TCP probing every ceiling
		"bad but not apart":    window(70, 30),     // 7% vs 3%: under the ratio
		"apart but close":      window(15, 2),      // 1.5% vs 0.2%: under the margin
		"one relay of traffic": window(150, 0)[:1], // nothing to compare with
		"a handful lost": { // 2.3% vs 0% of 300: seven packets are no rate
			{relay: "A", rx: 293, lost: 7},
			{relay: "B", rx: 300},
		},
	}
	for name, w := range cases {
		var j relayJudge
		for i := 0; i < 5; i++ {
			if bad := judged(&j, w); bad != "" {
				t.Fatalf("%s: rested %s", name, bad)
			}
		}
	}
}

func TestRelayJudgeNeedsTheWindowsInARow(t *testing.T) {
	var j relayJudge
	j.step(window(150, 10))
	j.step(window(20, 10)) // recovered: the count starts over
	if bad := judged(&j, window(150, 10)); bad != "" {
		t.Fatalf("rested %s on a broken streak", bad)
	}
	// A quiet window says nothing either way and keeps the streak.
	j.step(window(150, 10)[:0])
	if bad := judged(&j, window(150, 10)); bad != "A" {
		t.Fatalf("verdict = %q after a quiet window, want A", bad)
	}
}

// restBook stands for relayRestGen and relayRestedAfter in the tests: begin
// is a rest a relay begins, by whichever judge, and turn weighs a window as
// runRelayLossJudge does — booked since the turn before.
type restBook struct {
	gen, window uint64
	at          map[string]uint64
}

func newRestBook() *restBook { return &restBook{at: map[string]uint64{}} }

func (r *restBook) begin(relay string) { r.gen++; r.at[relay] = r.gen }

func (r *restBook) after(relay string, gen uint64) bool { return r.at[relay] > gen }

func (r *restBook) turn(j *relayJudge, l *relayLedger, samples []relayLossSample) []relayVerdict {
	start := r.window
	r.window = r.gen
	return judgeLossTurn(j, l, samples, true, false, start, r.after)
}

// A strike does not outlive a rest (audit, 2026-11-06). The ledger rests A in
// the turn its third window gives the windows' judge a first strike; nothing is
// weighed for thirty minutes — the others carry under the floor, or nothing at
// all, or carry and are weighed — and one bad window after A is back is no
// verdict; a second is. Through judgeLossTurn, as runRelayLossJudge weighs a
// window.
func TestAStrikeDoesNotOutliveTheLedgersRest(t *testing.T) {
	const a, b = "10.0.0.1:19302", "10.0.0.2:19302"
	for name, quiet := range map[string][]relayLossSample{
		"nothing carried":    nil,
		"under the floor":    {{relay: b, rx: 150}},
		"the others weighed": {{relay: b, rx: 600}, {relay: "10.0.0.3:19302", rx: 600}},
	} {
		t.Run(name, func(t *testing.T) {
			var judge relayJudge
			var ledger relayLedger
			rests := newRestBook()
			win := func(aLost int) []relayLossSample {
				return []relayLossSample{{relay: a, rx: 280 - aLost, lost: aLost}, {relay: b, rx: 280}}
			}
			rests.turn(&judge, &ledger, win(6))
			rests.turn(&judge, &ledger, win(8))
			if v := rests.turn(&judge, &ledger, win(12)); len(v) != 1 || v[0].relay != a {
				t.Fatalf("verdicts %+v: want the ledger resting A", v)
			}
			if judge.strikes[a] != 0 {
				t.Fatalf("strikes %v after the ledger rested A", judge.strikes)
			}
			rests.begin(a) // restJudgedRelays
			for i := 0; i < 180; i++ {
				rests.turn(&judge, &ledger, quiet)
			}
			if v := rests.turn(&judge, &ledger, win(12)); len(v) != 0 || judge.strikes[a] != 1 {
				t.Fatalf("one window after the rest: %+v, strikes %v; want none and a run of one", v, judge.strikes)
			}
			if v := rests.turn(&judge, &ledger, win(12)); len(v) != 1 || v[0].relay != a ||
				!strings.Contains(v[0].evidence, "2 windows running") {
				t.Fatalf("two windows after the rest: %+v, want A on two windows running", v)
			}
		})
	}
}

// A relay rested by anything else — the deaf judge, while the loss judge did
// not tick at all, its mark come and gone (Codex, 2026-11-06) — starts its run
// over; one that rests while its first bad window is still being booked does
// too (Codex, the same day); and one that rests and still carries starts a run
// of its own from the first window wholly after the rest began.
func TestAStrikeDoesNotOutliveAnotherRest(t *testing.T) {
	const a, b = "10.0.0.1:19302", "10.0.0.2:19302"
	win := func(aLost int) []relayLossSample {
		return []relayLossSample{{relay: a, rx: 1000 - aLost, lost: aLost}, {relay: b, rx: 1000}}
	}
	others := []relayLossSample{{relay: b, rx: 1000}, {relay: "10.0.0.3:19302", rx: 1000}}
	t.Run("gone while it rested", func(t *testing.T) {
		var judge relayJudge
		var ledger relayLedger
		rests := newRestBook()
		rests.turn(&judge, &ledger, win(150))
		rests.begin(a) // the deaf judge, between two turns
		rests.turn(&judge, &ledger, nil)
		if judge.strikes[a] != 0 {
			t.Fatalf("strikes %v after the rest: want A's run gone", judge.strikes)
		}
		if v := rests.turn(&judge, &ledger, win(150)); len(v) != 0 || judge.strikes[a] != 1 {
			t.Fatalf("the first window after the rest: %+v, strikes %v; want none and a run of one", v, judge.strikes)
		}
	})
	t.Run("rested while its first window was booked", func(t *testing.T) {
		var judge relayJudge
		var ledger relayLedger
		rests := newRestBook()
		rests.turn(&judge, &ledger, others)
		rests.begin(a) // the deaf judge, before the window with A's loss is weighed
		rests.turn(&judge, &ledger, win(150))
		rests.turn(&judge, &ledger, others)
		if judge.strikes[a] != 0 {
			t.Fatalf("strikes %v: want the run from the window the rest began in gone", judge.strikes)
		}
		if v := rests.turn(&judge, &ledger, win(150)); len(v) != 0 {
			t.Fatalf("one window after the rest: %+v", v)
		}
	})
	t.Run("carrying while it rests", func(t *testing.T) {
		// The windows' judge alone: a book of its own each window keeps the
		// ledger, which would rest A on these windows by itself, out of it.
		var judge relayJudge
		rests := newRestBook()
		rests.turn(&judge, &relayLedger{}, win(150))
		rests.begin(a)
		// The window being booked as the rest began, then the first wholly after.
		for i := 0; i < 2; i++ {
			if v := rests.turn(&judge, &relayLedger{}, win(150)); len(v) != 0 || judge.strikes[a] != 1 {
				t.Fatalf("window %d since the rest: %+v, strikes %v; want none and a run of one", i+1, v, judge.strikes)
			}
		}
		if v := rests.turn(&judge, &relayLedger{}, win(150)); len(v) == 0 || v[0].relay != a {
			t.Fatalf("the second window wholly after the rest: %+v, want A", v)
		}
	})
}

// What a window begins at is read before the take that opens it, and whether
// the transport moved in it after the take that closes it as well: a rest
// begun as the window opens is after the window began, and a move between the
// two reads is the closing window's (Codex, 2026-11-06).
func TestALossWindowBeginsBeforeItOpens(t *testing.T) {
	loss := newRelayLoss()
	gen, restAfterRead := uint64(5), false
	restGen := func() uint64 {
		g := gen
		if restAfterRead { // a rest begins right after the read, as the take opens the window
			gen++
			restAfterRead = false
		}
		return g
	}
	moves, moveAfterRead := uint64(2), false
	reads := 0
	transport := func() (uint64, bool) {
		reads++
		m := moves
		if moveAfterRead && reads%2 == 1 { // a move between the read before the take and the one after
			moves++
			moveAfterRead = false
		}
		return m, true
	}
	windows := relayLossWindows{gen: gen, moves: moves}
	now := time.Now()
	if w := windows.next(loss, now, restGen, transport); w.began != 5 || w.moved {
		t.Fatalf("the first window: began at %d, moved %v; want 5, not moved", w.began, w.moved)
	}
	// The take comes between the two reads: a datagram that arrives as the
	// first is read is the window's, one that arrives as the second is read the
	// next window's.
	ctr := uint64(0)
	arrive := func(at time.Time) { loss.observe(wgTransport(7, ctr), "A", at); ctr++ }
	snapshots := 0
	marking := func() (uint64, bool) {
		snapshots++
		arrive(now.Add(time.Duration(snapshots) * time.Second))
		return transport()
	}
	if w := windows.next(loss, now.Add(10*time.Second), restGen, marking); lossOf(w.samples, "A").rx != 1 {
		t.Fatalf("the window took %d datagram(s) of A, want the one before the take", lossOf(w.samples, "A").rx)
	}
	if w := windows.next(loss, now.Add(20*time.Second), restGen, transport); lossOf(w.samples, "A").rx != 1 {
		t.Fatalf("the next window took %d datagram(s) of A, want the one after the take", lossOf(w.samples, "A").rx)
	}
	restAfterRead, moveAfterRead = true, true
	if w := windows.next(loss, now, restGen, transport); w.began != 5 || !w.moved {
		t.Fatalf("the window closed as the transport moved: began at %d, moved %v; want 5 and moved", w.began, w.moved)
	}
	if w := windows.next(loss, now, restGen, transport); w.began != 5 || w.moved {
		t.Fatalf("the window opened as the rest began: began at %d, moved %v; want 5 — the rest after it — and not moved", w.began, w.moved)
	}
	if w := windows.next(loss, now, restGen, transport); w.began != 6 {
		t.Fatalf("the window after: began at %d, want 6", w.began)
	}
}

// The loss not yet final as the transport moves goes with the window set
// aside, not into the next (Codex, 2026-11-06): A's counters 2600-2999 lost
// every fiftieth, still inside the horizon at the take; after the move every
// counter arrives, and the window after the move charges A nothing.
func TestALossWindowTakesItsTailWithItAcrossAMove(t *testing.T) {
	loss := newRelayLoss()
	now := time.Now()
	for ctr := uint64(0); ctr < 3000; ctr++ {
		if ctr >= 2600 && ctr%50 == 0 {
			continue
		}
		loss.observe(wgTransport(7, ctr), "A", now)
	}
	moves := uint64(0)
	transport := func() (uint64, bool) { return moves, true }
	restGen := func() uint64 { return 0 }
	windows := relayLossWindows{}
	moves = 1 // the dials went over to the other transport
	if w := windows.next(loss, now, restGen, transport); !w.moved {
		t.Fatal("the window of the move: not moved")
	}
	for ctr := uint64(3000); ctr < 6000; ctr++ {
		loss.observe(wgTransport(7, ctr), "A", now)
	}
	w := windows.next(loss, now.Add(time.Second), restGen, transport)
	if a := lossOf(w.samples, "A"); a.lost != 0 {
		t.Fatalf("the window after the move charged A %d lost from before it", a.lost)
	}
}

// A session recycled by a move books no more downlink: its datagrams arriving
// after the loss judge let the window of the move go would put the transport
// left's loss in the next window (Codex, 2026-11-06). setNetworkState marks it
// as it recycles it.
func TestARecycledAttemptsDownlinkIsNotBooked(t *testing.T) {
	downlinkRelayLoss.reset()
	downlinkRelayOrder.reset(time.Now())
	t.Cleanup(func() { downlinkRelayLoss.reset(); downlinkRelayOrder.reset(time.Now()) })
	resetNetworkSwitch(t)
	prevChoice, prevUDP := relayTransportChoice.Load(), activeUseUDP.Load()
	t.Cleanup(func() { relayTransportChoice.Store(prevChoice); activeUseUDP.Store(prevUDP) })
	activeUseUDP.Store(true)
	relayTransportChoice.Store(relayTransportUDP)

	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	defer h.end()
	now := time.Now()
	observeDownlink(wgTransport(7, 0), "A", h.a)
	setNetworkState(0, relayTransportTCP, now)
	if !h.a.stale.Load() {
		t.Fatal("the attempt the move recycled is not marked")
	}
	for ctr := uint64(2); ctr < 40; ctr++ { // and counter 1 lost
		observeDownlink(wgTransport(7, ctr), "A", h.a)
	}
	samples, _, _ := downlinkRelayLoss.take(now.Add(time.Second))
	if a := lossOf(samples, "A"); a.rx != 1 || a.lost != 0 {
		t.Fatalf("A: %d delivered, %d lost; want the one datagram from before the move", a.rx, a.lost)
	}
}

// With no network the attempts over the transport left are not recycled yet,
// but book no more loss from the move on (Codex, 2026-11-06): a config over TCP,
// the transport set to UDP, the network lost and the transport set back to
// what the config says; the order book still takes their datagrams; and one the
// transport comes back to before it is recycled books again.
func TestAnAttemptOverTheTransportLeftIsStaleWithNoNetwork(t *testing.T) {
	downlinkRelayLoss.reset()
	downlinkRelayOrder.reset(time.Now())
	t.Cleanup(func() { downlinkRelayLoss.reset(); downlinkRelayOrder.reset(time.Now()) })
	resetNetworkSwitch(t)
	prevChoice, prevUDP := relayTransportChoice.Load(), activeUseUDP.Load()
	t.Cleanup(func() { relayTransportChoice.Store(prevChoice); activeUseUDP.Store(prevUDP) })
	activeUseUDP.Store(false)
	now := time.Now()
	setNetworkState(101, relayTransportUDP, now)
	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: false})
	defer h.end()
	if h.overTCP {
		t.Fatal("the attempt dials over TCP: the test wants it over UDP")
	}
	setNetworkState(0, relayTransportAsConfigured, now) // the network lost, the transport back to TCP
	if h.moved() || !h.a.stale.Load() {
		t.Fatalf("with no network: moved %v, stale %v; want it waiting to be recycled and stale", h.moved(), h.a.stale.Load())
	}
	before := downlinkRelayOrder.take(now).got
	observeDownlink(wgTransport(7, 0), "A", h.a)
	if got := downlinkRelayOrder.take(now).got; got != before+1 {
		t.Fatalf("the order book took %d datagram(s), want the one", got-before)
	}
	// The network back, the transport back to UDP before the attempt was
	// recycled: it rode out the outage and books again.
	setNetworkState(101, relayTransportUDP, now)
	if h.moved() || h.a.stale.Load() {
		t.Fatalf("the network and its transport back: moved %v, stale %v; want neither", h.moved(), h.a.stale.Load())
	}
	downlinkRelayLoss.reset()
	observeDownlink(wgTransport(9, 0), "A", h.a)
	samples, _, _ := downlinkRelayLoss.take(now.Add(time.Second))
	if a := lossOf(samples, "A"); a.rx != 1 {
		t.Fatalf("the loss book took %d of its datagrams, want the one", a.rx)
	}
}

// The window the transport moved in is not booked (Codex, 2026-11-06): A lost
// 1 and 0 of 280 over TCP, then 21 in the window the dials went over to UDP and
// back to TCP in. Booked under TCP's bars, the three windows rested A on the 22;
// the book starts over with the next window instead.
func TestTheLedgerSetsAsideTheWindowTheTransportMovedIn(t *testing.T) {
	const a, b = "10.0.0.1:19302", "10.0.0.2:19302"
	win := func(aLost int) []relayLossSample {
		return []relayLossSample{{relay: a, rx: 280 - aLost, lost: aLost}, {relay: b, rx: 280}}
	}
	none := func(string, uint64) bool { return false }
	var judge relayJudge
	var ledger relayLedger
	judgeLossTurn(&judge, &ledger, win(1), true, false, 0, none)
	judgeLossTurn(&judge, &ledger, win(0), true, false, 0, none)
	if v := judgeLossTurn(&judge, &ledger, win(21), true, true, 0, none); len(v) != 0 {
		t.Fatalf("the window the transport moved in: %+v", v)
	}
	if ledger.n != 0 || len(ledger.relays()) != 0 {
		t.Fatalf("the book after the move: %d windows, relays %v; want it empty", ledger.n, ledger.relays())
	}
	for i := 0; i < 2; i++ {
		if v := judgeLossTurn(&judge, &ledger, win(0), true, false, 0, none); len(v) != 0 {
			t.Fatalf("window %d after the move: rested %+v on loss from before it", i+1, v)
		}
	}
}

// A move of the dials to the other transport is counted, and a report of the
// transport they are on already is not.
func TestATransportMoveIsCounted(t *testing.T) {
	resetNetworkSwitch(t)
	prevChoice, prevUDP := relayTransportChoice.Load(), activeUseUDP.Load()
	t.Cleanup(func() { relayTransportChoice.Store(prevChoice); activeUseUDP.Store(prevUDP) })
	activeUseUDP.Store(true)
	relayTransportChoice.Store(relayTransportUDP)
	now := time.Now()
	before, _ := relayTransportState()
	setNetworkState(0, relayTransportAsConfigured, now) // UDP as configured: the same transport
	setNetworkState(0, relayTransportTCP, now)
	setNetworkState(0, relayTransportTCP, now)
	if got, overTCP := relayTransportState(); got-before != 1 || !overTCP {
		t.Fatalf("%d move(s) counted, over TCP %v; want 1, over TCP", got-before, overTCP)
	}
	setNetworkState(0, relayTransportUDP, now) // and back
	if got, overTCP := relayTransportState(); got-before != 2 || overTCP {
		t.Fatalf("%d move(s) counted, over TCP %v; want 2, over UDP", got-before, overTCP)
	}
}

// The rests the judge counts by are the rest marks' own: noteRelayRestingFor
// begins one, it stays after the mark is gone, it is the server's, and a
// stopped proxy's verdict begins none.
func TestRelayRestedAfter(t *testing.T) {
	withCleanRelayRest(t)
	const a, b = "10.0.0.1:19302", "10.0.0.2:19302"
	now := time.Now()
	before := relayRestGen()
	noteRelayResting(a, now)
	after := relayRestGen()
	if after != before+1 || !relayRestedAfter(a, before) || relayRestedAfter(a, after) || relayRestedAfter(b, before) {
		t.Fatalf("gen %d → %d, A after %d: %v, after %d: %v, B: %v", before, after, before, relayRestedAfter(a, before),
			after, relayRestedAfter(a, after), relayRestedAfter(b, before))
	}
	clearRelayRest() // the mark gone, out of trouble
	if !relayRestedAfter(a, before) {
		t.Fatal("the rest was forgotten with its mark")
	}
	setRelayRestPeer("server:2")
	if relayRestedAfter(a, before) {
		t.Fatal("a rest from server:1 counted against server:2's traffic")
	}
	setRelayRestPeer("server:1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := noteRelayRestingFor(ctx, b, now); ok || relayRestGen() != after || relayRestedAfter(b, before) {
		t.Fatalf("a stopped proxy's verdict began a rest: gen %d, want %d", relayRestGen(), after)
	}
}

func TestRelayJudgeIgnoresRelaysWithLittleTraffic(t *testing.T) {
	var j relayJudge
	thin := []relayLossSample{{relay: "A", rx: 90, lost: 60}, {relay: "B", rx: 900, lost: 5}}
	for i := 0; i < 3; i++ {
		if bad := judged(&j, thin); bad != "" {
			t.Fatalf("rested %s on %d packets", bad, 150)
		}
	}
}

// Five relays losing about 3% alike at 283 packets a window (audit,
// 2026-11-06): A's ten against E's one is ten times the rate and three points
// above it, two windows running, and the judge used to rest A for it; of the
// eleven lost, ten on one of two equal relays comes by chance once in 170
// times. The tired relay of 2026-10-10 at 300 packets — 4.3% and 5.3% against
// none — still rests at the second window.
func TestRelayJudgeAsksChanceToo(t *testing.T) {
	alike := []relayLossSample{
		{relay: "A", rx: 273, lost: 10}, {relay: "B", rx: 275, lost: 8}, {relay: "C", rx: 274, lost: 9},
		{relay: "D", rx: 276, lost: 7}, {relay: "E", rx: 282, lost: 1},
	}
	var j relayJudge
	for i := 0; i < 3; i++ {
		if bad := judged(&j, alike); bad != "" {
			t.Fatalf("window %d: rested %s among relays losing alike", i+1, bad)
		}
	}
	j = relayJudge{}
	tired := func(lost int) []relayLossSample {
		return []relayLossSample{{relay: "A", rx: 300 - lost, lost: lost}, {relay: "B", rx: 300}}
	}
	if bad := judged(&j, tired(13)); bad != "" {
		t.Fatalf("rested %s after one window", bad)
	}
	if bad := judged(&j, tired(16)); bad != "A" {
		t.Fatalf("verdict = %q, want the tired relay at the second window", bad)
	}
	// A window that fails on chance alone breaks the run, as one that fails
	// the ratio does: pass, chance only, pass — a run of one.
	j = relayJudge{}
	judged(&j, tired(16))
	judged(&j, []relayLossSample{{relay: "A", rx: 273, lost: 10}, {relay: "B", rx: 282, lost: 1}})
	if bad := judged(&j, tired(16)); bad != "" || j.strikes["A"] != 1 {
		t.Fatalf("rested %q, strikes %v: want a run of one after a window that failed on chance", bad, j.strikes)
	}
}

// Against the clearest neighbour, not the cleanest (Codex, 2026-11-06): A loses
// 3% of a thousand beside a clean B of 200 and a C of a thousand losing one.
// Against B alone the loss is a chance of 0.004; against C, of 4e-8.
func TestRelayJudgeWeighsEachNeighbour(t *testing.T) {
	w := []relayLossSample{{relay: "A", rx: 970, lost: 30}, {relay: "B", rx: 200}, {relay: "C", rx: 999, lost: 1}}
	var j relayJudge
	judged(&j, w)
	v := j.step(w)
	if len(v) != 1 || v[0].relay != "A" || !strings.Contains(v[0].evidence, "through C") {
		t.Fatalf("verdict %+v, want A through C at the second window", v)
	}
}

// What the chance costs, held to: ten lost of 200 against clean neighbours is
// a window against one of them, none against two or more; and over UDP a
// relay at 3.9% against 1.1% of 283 — eleven against three, by chance once in
// 35 windows — is rested by neither judge (see the comment on the judge).
func TestRelayJudgeChanceCostsTheThinAndTheClose(t *testing.T) {
	thin := func(neighbours int) []relayLossSample {
		w := []relayLossSample{{relay: "A", rx: 190, lost: 10}}
		for i := 0; i < neighbours; i++ {
			w = append(w, relayLossSample{relay: string(rune('B' + i)), rx: 200})
		}
		return w
	}
	var j relayJudge
	judged(&j, thin(1))
	if bad := judged(&j, thin(1)); bad != "A" {
		t.Fatalf("one clean neighbour: verdict = %q, want A", bad)
	}
	j = relayJudge{}
	for i := 0; i < 3; i++ {
		if bad := judged(&j, thin(2)); bad != "" {
			t.Fatalf("two clean neighbours: rested %s on ten lost of 200", bad)
		}
	}
	close := []relayLossSample{{relay: "A", rx: 272, lost: 11}, {relay: "B", rx: 280, lost: 3}}
	j = relayJudge{}
	var l relayLedger
	for i := 0; i < 3*relayLedgerWindows; i++ {
		if v := append(j.step(close), l.step(close, false)...); len(v) != 0 {
			t.Fatalf("window %d over UDP: rested %+v", i+1, v)
		}
	}
}

// An hour of eight equal relays at 283 packets a window and a common 3% — the
// simulation where the judge without chance rested a relay 28 times an hour —
// rests nothing.
func TestRelayJudgeRestsNothingOnEqualRelaysForAnHour(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var j relayJudge
	for step := 0; step < 360; step++ {
		var w []relayLossSample
		for i := 0; i < 8; i++ {
			lost := 0
			for k := 0; k < 283; k++ {
				if rng.Float64() < 0.03 {
					lost++
				}
			}
			w = append(w, relayLossSample{relay: string(rune('A' + i)), rx: 283 - lost, lost: lost})
		}
		if v := j.step(w); len(v) != 0 {
			t.Fatalf("window %d: rested %+v", step+1, v)
		}
	}
}

// In a pool of relays from several links, two bad relays taking turns as the
// worst do not restart each other's count: each is judged against the best.
func TestRelayJudgeCountsEachRelayAgainstTheBest(t *testing.T) {
	pool := func(aLost, bLost int) []relayLossSample {
		return []relayLossSample{
			{relay: "A", rx: 1000 - aLost, lost: aLost},
			{relay: "B", rx: 1000 - bLost, lost: bLost},
			{relay: "C", rx: 1000, lost: 2},
		}
	}
	var j relayJudge
	if bad := judged(&j, pool(80, 60)); bad != "" {
		t.Fatalf("verdict after one window: %s", bad)
	}
	if bad := judged(&j, pool(60, 80)); bad != "A,B" {
		t.Fatalf("verdict = %q, want A and B after two windows", bad)
	}
}

func TestAssignRelaysSkipsARestingRelay(t *testing.T) {
	resetServerHealth()
	setRelayRestPeer("server:1")
	t.Cleanup(clearRelayRest)
	now := time.Now()
	addrs := []string{"10.0.0.2:3478", "10.0.0.1:3478"}
	if got := assignRelays(addrs, 1, now)[0]; got != "10.0.0.2:3478" {
		t.Fatalf("stream 1 → %s, want the spread to put it on the second relay", got)
	}
	noteRelayResting("10.0.0.2:3478", now)
	for id := 0; id < 4; id++ {
		if got := assignRelays(addrs, id, now); got[0] != "10.0.0.1:3478" || len(got) != 1 {
			t.Fatalf("stream %d → %v while 10.0.0.2 rests", id, got)
		}
	}
	// The mark is the server's: another server's streams still use the relay.
	setRelayRestPeer("server:2")
	if got := assignRelays(addrs, 1, now)[0]; got != "10.0.0.2:3478" {
		t.Fatalf("stream 1 of another server → %s", got)
	}
	setRelayRestPeer("server:1")
	// And it ends.
	if got := assignRelays(addrs, 1, now.Add(relayRestFor+time.Second))[0]; got != "10.0.0.2:3478" {
		t.Fatalf("stream 1 after the rest → %s", got)
	}
	// Every relay resting: both, spread, not nothing.
	noteRelayResting("10.0.0.2:3478", now)
	noteRelayResting("10.0.0.1:3478", now)
	if got := assignRelays(addrs, 0, now); len(got) != 2 {
		t.Fatalf("all resting → %v, want both", got)
	}
}

// With every relay resting the streams spread over the resting relays as over
// live ones; the demoted and the penalized go behind them in the outage order.
// A fresh process on 2026-11-04 with the five relays of the config resting
// (marks kept on disk) put all ten streams on the first address by sort — the
// weakest relay — because the outage order, with no relay proven, stood as
// sorted.
func TestAssignRelaysSpreadsOverRestingRelaysWhenNoneIsUsable(t *testing.T) {
	resetServerHealth()
	defer resetServerHealth()
	setRelayRestPeer("server:1")
	t.Cleanup(clearRelayRest)
	now := time.Now()
	addrs := []string{"193.203.43.37:19302", "95.163.34.145:19302", "95.163.34.160:19302", "95.163.34.48:19302", "95.163.34.166:19302"}
	for _, a := range addrs {
		noteRelayResting(a, now)
	}
	sorted := []string{"193.203.43.37:19302", "95.163.34.145:19302", "95.163.34.160:19302", "95.163.34.166:19302", "95.163.34.48:19302"}
	heads := map[string]int{}
	for id := 0; id < 10; id++ {
		got := assignRelays(addrs, id, now)
		if len(got) != 5 || got[0] != sorted[id%5] {
			t.Fatalf("stream %d → %v, want the head rotated over the resting relays (%s)", id, got, sorted[id%5])
		}
		heads[got[0]]++
	}
	for _, a := range addrs {
		if heads[a] != 2 {
			t.Fatalf("heads %v, want two streams on each resting relay", heads)
		}
	}
	// A demoted relay among them goes last for every stream; the rest still
	// spread.
	noteServerDemotedAt("95.163.34.145:19302", now)
	for id := 0; id < 8; id++ {
		got := assignRelays(addrs, id, now)
		if got[4] != "95.163.34.145:19302" || got[0] == "95.163.34.145:19302" {
			t.Fatalf("stream %d → %v, want the demoted relay last", id, got)
		}
	}
	// With one relay back from its rest, it alone leads, as before.
	clearRelayRest()
	for _, a := range addrs[1:] {
		noteRelayResting(a, now)
	}
	for id := 0; id < 4; id++ {
		if got := assignRelays(addrs, id, now); len(got) != 1 || got[0] != "193.203.43.37:19302" {
			t.Fatalf("stream %d → %v while only .37 is usable", id, got)
		}
	}
}

// A session moves off a rested relay only if its own link has another usable
// relay: with both out it would land right back on the rested one.
func TestHasOtherUsableRelay(t *testing.T) {
	resetServerHealth()
	setRelayRestPeer("server:1")
	clearRelayRest()
	t.Cleanup(clearRelayRest)
	now := time.Now()
	link := []string{"10.0.0.1:3478", "10.0.0.2:3478"}
	if !hasOtherUsableRelay(link, "10.0.0.1:3478", now) {
		t.Fatal("no other relay while the link's second one is fine")
	}
	noteRelayResting("10.0.0.2:3478", now)
	if hasOtherUsableRelay(link, "10.0.0.1:3478", now) {
		t.Fatal("another relay while the link's second one rests")
	}
	if hasOtherUsableRelay(link[:1], "10.0.0.1:3478", now) {
		t.Fatal("another relay on a link pinned to one")
	}
}

func clearRelayRest() {
	relayRest.Lock()
	relayRest.marks = map[string]relayRestMark{}
	relayRest.Unlock()
}

// A relay judged bad again soon after its rest rests twice as long, up to the
// cap; one that stays out of trouble long enough starts over.
func TestRelayRestDoublesForARelapse(t *testing.T) {
	setRelayRestPeer("server:1")
	clearRelayRest()
	t.Cleanup(clearRelayRest)
	const relay = "10.0.0.2:3478"
	now := time.Now()
	want := []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 4 * time.Hour}
	for i, w := range want {
		if got := noteRelayResting(relay, now); got != w {
			t.Fatalf("verdict %d: rest %v, want %v", i+1, got, w)
		}
		if !relayResting(relay, now.Add(w-time.Second)) || relayResting(relay, now.Add(w)) {
			t.Fatalf("verdict %d: the rest does not end at %v", i+1, w)
		}
		now = now.Add(w + 10*time.Minute) // back for ten minutes, then bad again
	}

	// Out of trouble for relayRestRelapse after its return: the next verdict
	// starts over.
	now = now.Add(relayRestRelapse)
	relayResting(relay, now)
	if got := noteRelayResting(relay, now); got != relayRestFor {
		t.Fatalf("after a quiet spell: rest %v, want %v", got, relayRestFor)
	}
}

// sessionOn puts a live session of a stream on relay, dialed from link, the way
// attemptOnce and runSession register it, and returns its attempt.
func sessionOn(t *testing.T, relay string, link []string) *attemptHandle {
	t.Helper()
	h := beginAttempt(context.Background(), WorkerGroupConfig{UseUDP: true})
	s := &stream{}
	s.attempt.Store(h.a)
	s.relays.Store(&link)
	untrack := trackLiveSession(relay, s)
	t.Cleanup(func() {
		untrack()
		h.end()
	})
	return h
}

func withCleanRelayRest(t *testing.T) {
	t.Helper()
	resetServerHealth()
	clearRelayRest()
	setRelayRestPeer("server:1")
	t.Cleanup(func() {
		resetServerHealth()
		clearRelayRest()
	})
}

// A relay judged bad moves the sessions on it when their link has another
// relay to go to.
func TestRestJudgedRelaysMovesTheSessionsOff(t *testing.T) {
	withCleanRelayRest(t)
	h := sessionOn(t, "10.0.0.1:3478", []string{"10.0.0.1:3478", "10.0.0.2:3478"})

	restJudgedRelays(context.Background(), []relayVerdict{{relay: "10.0.0.1:3478", rate: 0.1}}, time.Now())

	select {
	case <-h.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the session stayed on the rested relay with another relay of its link usable")
	}
	if !relayResting("10.0.0.1:3478", time.Now()) {
		t.Error("the judged relay is not resting")
	}
}

// Both relays of a link judged in one window — against a third relay of
// another link — leave the sessions where they are: rested one at a time, the
// sessions on the first moved to the second, which was rested next, and
// redialed straight back onto a resting relay.
func TestRestJudgedRelaysMovesNoSessionOntoARelayRestedWithIt(t *testing.T) {
	withCleanRelayRest(t)
	link := []string{"10.0.0.1:3478", "10.0.0.2:3478"}
	h := sessionOn(t, link[0], link)

	restJudgedRelays(context.Background(), []relayVerdict{
		{relay: link[0], rate: 0.08},
		{relay: link[1], rate: 0.06},
	}, time.Now())

	select {
	case <-h.ctx.Done():
		t.Fatal("the session was moved although every relay of its link is resting")
	case <-time.After(200 * time.Millisecond):
	}
	for _, r := range link {
		if !relayResting(r, time.Now()) {
			t.Errorf("%s is not resting", r)
		}
	}
}

// fieldWindow is one window of the bench of 2026-11-04: five relays with two
// streams each at 14 packets/s, 280 packets a window, the first relay losing
// lost of them and the rest nothing.
func fieldWindow(lost int) []relayLossSample {
	return []relayLossSample{
		{relay: "193.203.43.37", rx: 280 - lost, lost: lost},
		{relay: "95.163.34.145", rx: 280},
		{relay: "95.163.34.160", rx: 280},
		{relay: "95.163.34.166", rx: 280},
		{relay: "95.163.34.48", rx: 280},
	}
}

// ledgerVerdictAt books the windows one by one over TCP and returns the index
// (from 1) of the first window with a verdict, with the verdict, or 0.
func ledgerVerdictAt(l *relayLedger, windows [][]relayLossSample) (int, []relayVerdict) {
	return ledgerVerdictOver(l, true, windows)
}

// ledgerVerdictOver is ledgerVerdictAt over the given transport.
func ledgerVerdictOver(l *relayLedger, overTCP bool, windows [][]relayLossSample) (int, []relayVerdict) {
	for i, w := range windows {
		if v := l.step(w, overTCP); len(v) > 0 {
			return i + 1, v
		}
	}
	return 0, nil
}

// The relay of 2026-11-04: 3.6% once, 0% the next window, a few lost here and
// there — 1.3% of the minute against 0% on four neighbours, and never two
// windows in a row for the windows' judge.
func TestRelayLedgerRestsARelayThatLosesALittleForAMinute(t *testing.T) {
	windows := [][]relayLossSample{
		fieldWindow(10), fieldWindow(0), fieldWindow(4), fieldWindow(0), fieldWindow(0), fieldWindow(8),
	}
	var j relayJudge
	for _, w := range windows {
		if bad := judged(&j, w); bad != "" {
			t.Fatalf("the windows' judge rested %s", bad)
		}
	}
	var l relayLedger
	at, v := ledgerVerdictAt(&l, windows)
	if at != 6 || len(v) != 1 || v[0].relay != "193.203.43.37" {
		t.Fatalf("verdict %+v at window %d, want .37 at the sixth, with the twentieth packet lost", v, at)
	}
	if v[0].rate < 0.013 || v[0].rate > 0.0135 || v[0].best != 0 {
		t.Fatalf("verdict %+v, want 22 of 1680 against 0", v[0])
	}
	if !strings.Contains(v[0].evidence, "22 lost over 6 windows") {
		t.Fatalf("evidence %q", v[0].evidence)
	}
	// Rested, the relay's minute starts over: the same book does not rest it
	// again on the next window.
	if v := l.step(fieldWindow(0), true); len(v) != 0 {
		t.Fatalf("verdict repeated: %+v", v)
	}

	// A steady 1% on three streams against 0%: 4-5 lost of 420 a window.
	steady := func(lost int) []relayLossSample {
		return []relayLossSample{
			{relay: "A", rx: 420 - lost, lost: lost},
			{relay: "B", rx: 420},
			{relay: "C", rx: 420},
		}
	}
	l = relayLedger{}
	at, v = ledgerVerdictAt(&l, [][]relayLossSample{steady(4), steady(5), steady(4), steady(4), steady(5), steady(4)})
	if at != 5 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v at window %d, want A at the fifth, 22 lost", v, at)
	}
}

// Twenty lost over the minute is the floor: 1% of 280 a window never gets
// there, however long it goes on.
func TestRelayLedgerNeedsTwentyLost(t *testing.T) {
	var l relayLedger
	for i := 0; i < 3*relayLedgerWindows; i++ {
		if v := l.step(fieldWindow(3), true); len(v) != 0 {
			t.Fatalf("window %d: rested %+v on 18 lost a minute", i+1, v)
		}
	}
	// Nor nineteen in one window and nothing after.
	l = relayLedger{}
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{fieldWindow(19), fieldWindow(0), fieldWindow(0), fieldWindow(0)}); at != 0 {
		t.Fatalf("rested %+v at window %d on 19 lost", v, at)
	}
}

// Loss on every relay at once — the phone's own leg, or every relay at its
// ceiling — rests nothing: the verdict is against the best neighbour.
func TestRelayLedgerLeavesRelaysThatLoseTogether(t *testing.T) {
	pool := func(lost ...int) []relayLossSample {
		var out []relayLossSample
		for i, n := range lost {
			out = append(out, relayLossSample{relay: string(rune('A' + i)), rx: 1000 - n, lost: n})
		}
		return out
	}
	cases := map[string][][]relayLossSample{
		"a dip on every relay": {
			pool(0, 0, 0), pool(0, 0, 0), pool(30, 25, 28), pool(22, 31, 19), pool(0, 0, 0), pool(0, 0, 0),
			pool(0, 0, 0), pool(0, 0, 0), pool(0, 0, 0), pool(0, 0, 0),
		},
		"all saturated": {
			pool(90, 60, 70), pool(80, 65, 75), pool(95, 55, 60), pool(85, 70, 65), pool(90, 60, 70), pool(88, 62, 71),
		},
		"a steady loss on every relay": {
			pool(10, 8, 12), pool(9, 11, 10), pool(12, 8, 9), pool(10, 10, 11), pool(8, 12, 10), pool(11, 9, 10),
		},
		"apart but under the ratio": { // 0.5% against 0.2%, thirty lost
			pool(5, 2, 2), pool(5, 2, 2), pool(5, 2, 2), pool(5, 2, 2), pool(5, 2, 2), pool(5, 2, 2),
		},
		"apart but under the margin": { // 0.4% of 6000 against 0%: twenty-four lost
			pool(4, 0, 0), pool(4, 0, 0), pool(4, 0, 0), pool(4, 0, 0), pool(4, 0, 0), pool(4, 0, 0),
		},
	}
	for name, windows := range cases {
		var l relayLedger
		if at, v := ledgerVerdictAt(&l, windows); at != 0 {
			t.Fatalf("%s: rested %+v at window %d", name, v, at)
		}
	}
}

// ledgerCascade books the window w over TCP the given number of times, each
// time without the relays rested so far — their sessions move off them — and
// returns the window (from 1) each relay was rested at.
func ledgerCascade(l *relayLedger, w []relayLossSample, windows int) map[string]int {
	at := map[string]int{}
	for i := 1; i <= windows; i++ {
		var carrying []relayLossSample
		for _, s := range w {
			if at[s.relay] == 0 {
				carrying = append(carrying, s)
			}
		}
		for _, v := range l.step(carrying, true) {
			at[v.relay] = i
		}
	}
	return at
}

// minuteOf is the windows of relays losing the given packets of n a window
// each, window by window: lost[i][w] is relay i's in window w.
func minuteOf(n int, lost ...[]int) [][]relayLossSample {
	out := make([][]relayLossSample, len(lost[0]))
	for w := range out {
		for i, l := range lost {
			out[w] = append(out[w], relayLossSample{relay: string(rune('A' + i)), rx: n - l[w], lost: l[w]})
		}
	}
	return out
}

// Five relays losing about 1% alike over TCP (audit, 2026-11-06): A's 21 of
// 1698 is 3.5 times E's 6, and the book used to rest A against E alone. Against
// the four together — 57 of 6792, 14 where A lost 21 — A is nothing apart.
func TestRelayLedgerLeavesFiveRelaysLosingAlike(t *testing.T) {
	windows := minuteOf(283,
		[]int{4, 3, 4, 3, 4, 3},
		[]int{3, 3, 2, 3, 3, 3},
		[]int{3, 3, 3, 3, 3, 3},
		[]int{3, 2, 3, 3, 2, 3},
		[]int{1, 1, 1, 1, 1, 1},
	)
	var l relayLedger
	if at, v := ledgerVerdictAt(&l, windows); at != 0 {
		t.Fatalf("rested %+v at window %d on five relays losing alike", v, at)
	}
}

// A pair losing about 1% alike over TCP: 22 against 6 over the minute is 3.7
// times the rate and a point above it, and the book used to rest A for it —
// but of the 28 lost, 22 on one of two equal relays comes by chance once in
// 540 times.
func TestRelayLedgerLeavesAnEqualPair(t *testing.T) {
	windows := minuteOf(283, []int{4, 4, 3, 4, 4, 3}, []int{1, 1, 1, 1, 1, 1})
	var l relayLedger
	if at, v := ledgerVerdictAt(&l, windows); at != 0 {
		t.Fatalf("rested %+v at window %d on a pair losing alike", v, at)
	}
}

// The expected loss is taken window by window (Codex, 2026-11-06): A and B
// lose 7% alike while A carries three times B, then nothing while B carries
// three times A. In the minute's sums A came out 2.6% against 0.44% and was
// rested, over either transport; window by window it lost what was due.
func TestRelayLedgerWeighsTheWindowsOneByOne(t *testing.T) {
	windows := [][]relayLossSample{
		{{relay: "A", rx: 279, lost: 21}, {relay: "B", rx: 93, lost: 7}},
		{{relay: "A", rx: 279, lost: 21}, {relay: "B", rx: 93, lost: 7}},
		{{relay: "A", rx: 1000}, {relay: "B", rx: 3000}},
	}
	for _, overTCP := range []bool{true, false} {
		var l relayLedger
		if at, v := ledgerVerdictOver(&l, overTCP, windows); at != 0 {
			t.Fatalf("over TCP %v: rested %+v at window %d on the same 7%% in each window", overTCP, v, at)
		}
	}
}

// Two relays losing alike beside a clean one (Codex, 2026-11-06): against the
// other relays together each stood at twice the rate of the pool, the other
// bad one in it, and neither was ever rested. Each against the clean one, both
// are, over TCP and over UDP alike.
func TestRelayLedgerRestsTwoRelaysLosingAlike(t *testing.T) {
	bad := func(clean int) []relayLossSample {
		w := []relayLossSample{{relay: "A", rx: 135, lost: 15}, {relay: "B", rx: 135, lost: 15}}
		for i := 0; i < clean; i++ {
			w = append(w, relayLossSample{relay: string(rune('C' + i)), rx: 150})
		}
		return w
	}
	for _, c := range []struct {
		overTCP bool
		clean   int
	}{{true, 1}, {false, 3}} {
		var l relayLedger
		at, v := ledgerVerdictOver(&l, c.overTCP, [][]relayLossSample{bad(c.clean), bad(c.clean), bad(c.clean)})
		if at != 3 || len(v) != 2 {
			t.Fatalf("over TCP %v: verdict %+v at window %d, want A and B at the third", c.overTCP, v, at)
		}
	}
}

// The chance is weighed window by window too (Codex, 2026-11-06): A loses 1%
// of a thousand beside a clean neighbour of fifty, twice, then carries fifty
// beside a clean ten thousand. Every loss on A at its share in the windows they
// fell in — 95% of the packets — is a chance of 0.38; in the minute's sums the
// clean ten thousand made it 3.5e-16.
func TestRelayLedgerWeighsTheChanceWindowByWindow(t *testing.T) {
	for _, c := range []struct {
		overTCP bool
		lost    int
	}{{true, 10}, {false, 21}} {
		windows := [][]relayLossSample{
			{{relay: "A", rx: 1000 - c.lost, lost: c.lost}, {relay: "B", rx: 50}},
			{{relay: "A", rx: 1000 - c.lost, lost: c.lost}, {relay: "C", rx: 50}},
			{{relay: "A", rx: 50}, {relay: "D", rx: 10000}},
		}
		var l relayLedger
		if at, v := ledgerVerdictOver(&l, c.overTCP, windows); at != 0 {
			t.Fatalf("over TCP %v: rested %+v at window %d", c.overTCP, v, at)
		}
	}
}

// A clean neighbour of a third of the relay's load (Codex, 2026-11-06): A
// loses 8 of 600 a window, B carries 200 clean. All the losses on A at its
// three quarters of the packets: 0.75^40 at the fifth window is just over the
// bar, 0.75^48 at the sixth under it. The old book took three windows.
func TestRelayLedgerRestsBesideACleanNeighbourOfAThirdTheLoad(t *testing.T) {
	w := []relayLossSample{{relay: "A", rx: 592, lost: 8}, {relay: "B", rx: 200}}
	var l relayLedger
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{w, w, w, w, w, w}); at != 6 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v at window %d, want A at the sixth", v, at)
	}
}

// The pools Codex took apart (2026-11-06, second round), each against the
// relays that lost less over the minute. A relay losing 1.8% beside five new
// thin neighbours a window, three clean and two at a packet each: the pool,
// picked by its losses, came out clean and rested A; no neighbour shares three
// windows with it, and nothing is. A slightly bad B beside a worse A and a thin
// clean C shielded A for good; against C alone A rests at the sixth window. And
// windows B carried alone decided that A never met it; over the windows they
// shared A loses 6% against none, and rests at the sixth.
func TestRelayLedgerWeighsEachNeighbourOnItsOwn(t *testing.T) {
	var rotating [][]relayLossSample
	for w := 0; w < 2*relayLedgerWindows; w++ {
		win := []relayLossSample{{relay: "A", rx: 278, lost: 5}}
		for k := 0; k < 5; k++ {
			lost := 0
			if k >= 3 {
				lost = 1
			}
			win = append(win, relayLossSample{relay: fmt.Sprintf("n%d-%d", w, k), rx: 50 - lost, lost: lost})
		}
		rotating = append(rotating, win)
	}
	var l relayLedger
	if at, v := ledgerVerdictAt(&l, rotating); at != 0 {
		t.Fatalf("rotating thin neighbours: rested %+v at window %d", v, at)
	}

	shield := []relayLossSample{{relay: "A", rx: 142, lost: 8}, {relay: "B", rx: 145, lost: 5}, {relay: "C", rx: 50}}
	l = relayLedger{}
	if at := ledgerCascade(&l, shield, 2*relayLedgerWindows); !maps.Equal(at, map[string]int{"A": 6}) {
		t.Fatalf("a slightly bad neighbour: rested at %v, want A at the sixth window and B never", at)
	}

	var cycle [][]relayLossSample
	for c := 0; c < 3; c++ {
		for i := 0; i < 3; i++ {
			cycle = append(cycle, []relayLossSample{{relay: "B", rx: 120, lost: 30}})
		}
		for i := 0; i < 3; i++ {
			cycle = append(cycle, []relayLossSample{{relay: "A", rx: 141, lost: 9}, {relay: "B", rx: 150}})
		}
	}
	l = relayLedger{}
	at, v := ledgerVerdictAt(&l, cycle)
	if at != 6 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("windows alone: verdict %+v at window %d, want A at the sixth", v, at)
	}
}

// An hour of equal relays, two or five, at a common 0.5-2% over TCP — the
// simulation of the audit of 2026-11-06, where the book judging against the
// cleanest neighbour rested a relay eight times an hour — rests nothing.
func TestRelayLedgerRestsNothingOnEqualRelaysForAnHour(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, relays := range []int{2, 5} {
		for _, p := range []float64{0.005, 0.01, 0.02} {
			var l relayLedger
			for step := 0; step < 360; step++ {
				var w []relayLossSample
				for i := 0; i < relays; i++ {
					lost := 0
					for k := 0; k < 283; k++ {
						if rng.Float64() < p {
							lost++
						}
					}
					w = append(w, relayLossSample{relay: string(rune('A' + i)), rx: 283 - lost, lost: lost})
				}
				if v := l.step(w, true); len(v) != 0 {
					t.Fatalf("%d relays at %.1f%%, window %d: rested %+v", relays, 100*p, step+1, v)
				}
			}
		}
	}
}

// exactBinomialTail is the chance of x or more successes in n trials at p,
// summed term by term.
func exactBinomialTail(n, x int, p float64) float64 {
	var sum float64
	for k := x; k <= n; k++ {
		lgn, _ := math.Lgamma(float64(n + 1))
		lgk, _ := math.Lgamma(float64(k + 1))
		lgr, _ := math.Lgamma(float64(n - k + 1))
		sum += math.Exp(lgn - lgk - lgr + float64(k)*math.Log(p) + float64(n-k)*math.Log1p(-p))
	}
	return sum
}

// lossChanceAtMost is a bound: never under the chance, close to it, exact when
// every loss is the relay's, and the same for one window as for the window
// split in two at the same share.
func TestLossChanceAtMost(t *testing.T) {
	one := func(lost int, share float64) []lossShare { return []lossShare{{lost: lost, share: share}} }
	if got := lossChanceAtMost(0, one(10, 0.3)); got != 1 {
		t.Fatalf("none of the losses: %v, want 1", got)
	}
	if got := lossChanceAtMost(11, one(10, 0.3)); got != 0 {
		t.Fatalf("more than all the losses: %v, want 0", got)
	}
	if got := lossChanceAtMost(3, one(10, 0.3)); got != 1 {
		t.Fatalf("the mean: %v, want 1", got)
	}
	if got, want := lossChanceAtMost(22, one(22, 0.2)), math.Pow(0.2, 22); math.Abs(got-want) > 1e-12*want {
		t.Fatalf("every loss on the relay: %v, want %v", got, want)
	}
	// Codex's windows (2026-11-06): ten of 1000 beside a clean 50, twice, then
	// a clean window of a clean 10000. Every loss on the relay, at its share in
	// the windows they fell in: 0.38, not the 3.5e-16 of the minute's sums.
	codex := []lossShare{{lost: 10, share: 1000.0 / 1050}, {lost: 10, share: 1000.0 / 1050}, {lost: 0, share: 50.0 / 10050}}
	if got, want := lossChanceAtMost(20, codex), math.Pow(1000.0/1050, 20); math.Abs(got-want) > 1e-12 {
		t.Fatalf("Codex's windows: %v, want %v", got, want)
	}
	for _, c := range []struct {
		n, x int
		p    float64
	}{{28, 22, 0.5}, {26, 20, 0.5}, {54, 30, 0.25}, {72, 40, 0.25}, {1000, 60, 0.03}, {5000, 300, 0.05}} {
		exact := exactBinomialTail(c.n, c.x, c.p)
		got := lossChanceAtMost(c.x, one(c.n, c.p))
		if got < exact || got > 20*exact {
			t.Fatalf("%d of %d at %v: bound %v, the chance %v", c.x, c.n, c.p, got, exact)
		}
		split := lossChanceAtMost(c.x, []lossShare{{lost: c.n / 2, share: c.p}, {lost: c.n - c.n/2, share: c.p}})
		if math.Abs(split-got) > 1e-12 {
			t.Fatalf("%d of %d at %v: %v split in two windows, %v whole", c.x, c.n, c.p, split, got)
		}
	}
	// Windows of different shares, against the chance summed term by term. At
	// x = 62, every loss, the bound and the chance are the same product taken
	// in a different order, and on arm64 (the phone, 2026-11-07) they differ in
	// the last bits — the bound may not fall below the chance by more than
	// rounding.
	mixed := []lossShare{{lost: 30, share: 0.3}, {lost: 20, share: 0.6}, {lost: 12, share: 0.9}}
	for _, x := range []int{25, 35, 45, 55, 62} {
		exact := exactSumTail(x, mixed)
		got := lossChanceAtMost(x, mixed)
		if math.IsNaN(got) || got < exact*(1-1e-9) || got > 20*exact {
			t.Fatalf("%d of the mixed windows: bound %v, the chance %v", x, got, exact)
		}
	}
	// Counts no minute holds: an answer, no hang, no NaN.
	// Counts no minute holds, past what a float holds exactly (Codex,
	// 2026-11-06): the slope never turned upward and the bracket doubled for
	// ever. Now the answer is 1 — no verdict. Built from int64 so that the
	// test compiles where int is 32 bits, and run only where it is 64.
	if strconv.IntSize == 64 {
		var a, b, x int64 = 1<<54 + 2, 1<<54 + 4, 1<<55 + 5
		huge := []lossShare{{lost: int(a), share: 0.5}, {lost: int(b), share: 0.5}}
		if got := lossChanceAtMost(int(x), huge); got != 1 {
			t.Fatalf("huge counts: %v, want 1", got)
		}
	}
}

// exactSumTail is the chance of x or more over windows of independent
// binomials, by convolution.
func exactSumTail(x int, parts []lossShare) float64 {
	dist := []float64{1}
	for _, p := range parts {
		next := make([]float64, len(dist)+p.lost)
		for k := 0; k <= p.lost; k++ {
			pk := float64(1)
			for i := 0; i < k; i++ {
				pk *= float64(p.lost-i) / float64(i+1)
			}
			pk *= math.Pow(p.share, float64(k)) * math.Pow(1-p.share, float64(p.lost-k))
			for s, v := range dist {
				next[s+k] += v * pk
			}
		}
		dist = next
	}
	var tail float64
	for s := x; s < len(dist); s++ {
		tail += dist[s]
	}
	return tail
}

// Two relays of a pool losing alone are both rested at the third window, each
// against a clean one.
func TestRelayLedgerRestsEveryRelayThatLosesAlone(t *testing.T) {
	w := []relayLossSample{
		{relay: "A", rx: 990, lost: 10},
		{relay: "B", rx: 992, lost: 8},
		{relay: "C", rx: 1000},
		{relay: "D", rx: 1000},
	}
	var l relayLedger
	if at := ledgerCascade(&l, w, 6); !maps.Equal(at, map[string]int{"A": 3, "B": 3}) {
		t.Fatalf("rested at %v, want A and B at the third window", at)
	}
}

// The relays are weighed over the windows they carried together. A relay that
// lost alone — to its own ceiling, with nothing to compare it with — is not
// held against a neighbour that joined clean; and a neighbour of ten seconds
// is no neighbour yet.
func TestRelayLedgerWeighsRelaysOverTheWindowsTheyShared(t *testing.T) {
	alone := []relayLossSample{{relay: "A", rx: 970, lost: 30}}
	joined := func(aLost int) []relayLossSample {
		return []relayLossSample{{relay: "A", rx: 1000 - aLost, lost: aLost}, {relay: "B", rx: 1000}}
	}
	var l relayLedger
	for i := 0; i < 4; i++ {
		if v := l.step(alone, true); len(v) != 0 {
			t.Fatalf("rested %+v with one relay in the book", v)
		}
	}
	// Clean in the windows it shares with B: the 120 lost alone do not count.
	for i := 0; i < relayLedgerWindows; i++ {
		if v := l.step(joined(0), true); len(v) != 0 {
			t.Fatalf("shared window %d: rested %+v on loss before B joined", i+1, v)
		}
	}
	// Losing in the shared windows, A is judged over those: from the third.
	l = relayLedger{}
	for i := 0; i < 4; i++ {
		l.step(alone, true)
	}
	at, v := ledgerVerdictAt(&l, [][]relayLossSample{joined(8), joined(7), joined(8)})
	if at != 3 || len(v) != 1 || v[0].relay != "A" || !strings.Contains(v[0].evidence, "23 lost over 3 windows") {
		t.Fatalf("verdict %+v at shared window %d, want A at the third on 23 lost", v, at)
	}
	// A quiet window on one relay (under relayLedgerMinWindowPackets) is not
	// shared, and does not count against it.
	l = relayLedger{}
	quiet := []relayLossSample{{relay: "A", rx: 988, lost: 12}, {relay: "B", rx: 30}}
	at, v = ledgerVerdictAt(&l, [][]relayLossSample{quiet, quiet, quiet, quiet, quiet, quiet})
	if at != 0 {
		t.Fatalf("rested %+v at window %d against a relay that carried 30 packets a window", v, at)
	}
}

// The stuck tunnel of 2026-11-04 (06_W5): .37 losing 5-15% among five relays
// held the one TCP flow inside at 0.6 Mbit/s, so each relay carried 130-210
// packets a window — under the windows' floor of 200, where neither judge
// counted a window, for two minutes. The book counts them, and takes the
// weight from the sums.
func TestRelayLedgerCountsTheWindowsOfAStuckTunnel(t *testing.T) {
	thin := func(n, lost int) []relayLossSample {
		return []relayLossSample{
			{relay: "193.203.43.37", rx: n - lost, lost: lost},
			{relay: "95.163.34.145", rx: n},
			{relay: "95.163.34.160", rx: n},
			{relay: "95.163.34.166", rx: n},
			{relay: "95.163.34.48", rx: n},
		}
	}
	windows := [][]relayLossSample{thin(133, 6), thin(160, 12), thin(213, 32)}
	var j relayJudge
	for _, w := range windows {
		if bad := judged(&j, w); bad != "" {
			t.Fatalf("the windows' judge rested %s under its floor", bad)
		}
	}
	var l relayLedger
	at, v := ledgerVerdictAt(&l, windows)
	if at != 3 || len(v) != 1 || v[0].relay != "193.203.43.37" || !strings.Contains(v[0].evidence, "50 lost over 3 windows") {
		t.Fatalf("verdict %+v at window %d, want .37 at the third on 50 lost of 506", v, at)
	}
	// The link's own pair alone (04_OWN): 14% of 119, then 150 and 220 a
	// window, 0% on .166 throughout — the windows' judge took 115 s to see two
	// windows of 200 in a row.
	pair := func(n, lost int) []relayLossSample {
		return []relayLossSample{{relay: "193.203.43.37", rx: n - lost, lost: lost}, {relay: "95.163.34.166", rx: n}}
	}
	l = relayLedger{}
	at, v = ledgerVerdictAt(&l, [][]relayLossSample{pair(119, 17), pair(150, 21), pair(220, 32)})
	if at != 3 || len(v) != 1 || v[0].relay != "193.203.43.37" {
		t.Fatalf("verdict %+v at window %d, want .37 at the third", v, at)
	}
}

// Booked from fifty packets a window, a relay still has to carry
// relayJudgeMinPackets over the shared windows before it is weighed, or
// weighed against: 199 over three windows is not enough, the fourth is.
func TestRelayLedgerNeedsTwoHundredInTheSums(t *testing.T) {
	// A thin neighbour: clean, 67+66+66 = 199 over three windows, against a
	// relay losing 15% of a thousand (a count the neighbour would have shown).
	thinB := func(n int) []relayLossSample {
		return []relayLossSample{{relay: "A", rx: 850, lost: 150}, {relay: "B", rx: n}}
	}
	var l relayLedger
	at, v := ledgerVerdictAt(&l, [][]relayLossSample{thinB(67), thinB(66), thinB(66), thinB(66)})
	if at != 4 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v at window %d, want A at the fourth, once B has carried 265", v, at)
	}
	// A thin relay: 199 over three windows, ten of each window lost, against
	// a clean neighbour.
	thinA := func(rx int) []relayLossSample {
		return []relayLossSample{{relay: "A", rx: rx, lost: 10}, {relay: "B", rx: 1000}}
	}
	l = relayLedger{}
	at, v = ledgerVerdictAt(&l, [][]relayLossSample{thinA(57), thinA(56), thinA(56), thinA(56)})
	if at != 4 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v at window %d, want A at the fourth, once it has carried 265", v, at)
	}
}

// A window is booked for a relay from relayLedgerMinWindowPackets: at 49 the
// relay is not in the book, at 50 it is.
func TestRelayLedgerBooksAWindowFromFiftyPackets(t *testing.T) {
	var l relayLedger
	l.step([]relayLossSample{{relay: "A", rx: 44, lost: 5}, {relay: "B", rx: 1000}}, true)
	if r := l.relays(); len(r) != 1 || r[0] != "B" {
		t.Fatalf("book %v after a window of 49 packets on A, want B alone", r)
	}
	l = relayLedger{}
	l.step([]relayLossSample{{relay: "A", rx: 45, lost: 5}, {relay: "B", rx: 1000}}, true)
	if r := l.relays(); len(r) != 2 || r[0] != "A" {
		t.Fatalf("book %v after a window of 50 packets on A, want A and B", r)
	}
}

// A clean neighbour is evidence only if it carried enough to have shown the
// loss (Codex review, 2026-11-04): at a common 1%, a neighbour of 240 packets
// is clean by chance once in eleven times, and an equally good relay of four
// thousand would rest for it. At the relay's rate the neighbour must have
// stood to lose seven.
func TestRelayLedgerNeedsANeighbourThatWouldHaveShownTheLoss(t *testing.T) {
	// A loses 1.2% of a thousand a window; B carries sixty, clean: at 1.2% of
	// its 360 over the minute B would have lost four — no evidence.
	thin := func() []relayLossSample {
		return []relayLossSample{{relay: "A", rx: 988, lost: 12}, {relay: "B", rx: 60}}
	}
	var l relayLedger
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{thin(), thin(), thin(), thin(), thin(), thin()}); at != 0 {
		t.Fatalf("rested %+v at window %d against a neighbour that would have lost four at A's rate", v, at)
	}
	// At six hundred a window B would have lost seven by the third window
	// (1800 × 1.2% = 21.6), and the verdict stands.
	wide := func() []relayLossSample {
		return []relayLossSample{{relay: "A", rx: 988, lost: 12}, {relay: "B", rx: 600}}
	}
	l = relayLedger{}
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{wide(), wide(), wide()}); at != 3 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v at window %d, want A at the third", v, at)
	}
	// The field verdicts pass the gate with room: .37's minute at 1.3% against
	// a neighbour of 1680 would have shown 22 (the live one of 02_W5, 0.8%
	// against ~2800, 23); the stuck tunnel at 10% against 506, 50.
	l = relayLedger{}
	if at, _ := ledgerVerdictAt(&l, [][]relayLossSample{fieldWindow(10), fieldWindow(0), fieldWindow(4), fieldWindow(0), fieldWindow(0), fieldWindow(8)}); at != 6 {
		t.Fatalf("the field verdict moved to window %d", at)
	}
}

// The verdict is relative, so the book can never empty the pool: with graded
// loss it rests every relay that stands against the cleanest, in one turn or
// over several, and the one left — however much it then loses, alone at its
// ceiling — has nothing to be judged against (relay_rest.go: what has nothing
// to compare with is logged, relay_collapse.go, not rested).
func TestRelayLedgerNeverRestsTheLastRelay(t *testing.T) {
	graded := func(a, b, c, d int) []relayLossSample {
		return []relayLossSample{
			{relay: "A", rx: 1000 - a, lost: a}, {relay: "B", rx: 1000 - b, lost: b},
			{relay: "C", rx: 1000 - c, lost: c}, {relay: "D", rx: 1000 - d, lost: d},
		}
	}
	var l relayLedger
	// 5%, 2% and 0.7% against 0%: all three rested at the third window, each
	// against D, and D never.
	at := ledgerCascade(&l, graded(50, 20, 7, 0), 3*relayLedgerWindows)
	if !maps.Equal(at, map[string]int{"A": 3, "B": 3, "C": 3}) {
		t.Fatalf("rested at %v, want A, B and C at the third window", at)
	}
	// D carries everything now and loses 30% of it: never rested.
	alone := []relayLossSample{{relay: "D", rx: 2800, lost: 1200}}
	for i := 0; i < 2*relayLedgerWindows; i++ {
		if v := l.step(alone, true); len(v) != 0 {
			t.Fatalf("window %d: rested %+v, the last relay", i+1, v)
		}
	}
	// Nor is a pair rested together: the two left cannot both be 3× the other.
	l = relayLedger{}
	pair := []relayLossSample{{relay: "A", rx: 950, lost: 50}, {relay: "B", rx: 900, lost: 100}}
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{pair, pair, pair, pair, pair, pair}); at != 0 {
		t.Fatalf("rested %+v at window %d: 10%% against 5%% is under the ratio", v, at)
	}
	// Nor a ring of three, each losing alone in a window the next carried
	// clean (Codex, 2026-11-06): pair by pair each stands against the next,
	// and every one of them would rest in one turn. Against a neighbour rested
	// with it, no verdict stands.
	ring := [][]relayLossSample{
		{{relay: "A", rx: 900, lost: 100}, {relay: "B", rx: 1000}, {relay: "C", rx: 50}},
		{{relay: "A", rx: 50}, {relay: "B", rx: 900, lost: 100}, {relay: "C", rx: 1000}},
		{{relay: "A", rx: 1000}, {relay: "B", rx: 50}, {relay: "C", rx: 900, lost: 100}},
		{{relay: "A", rx: 50}, {relay: "B", rx: 50}, {relay: "C", rx: 50}},
		{{relay: "A", rx: 50}, {relay: "B", rx: 50}, {relay: "C", rx: 50}},
		{{relay: "A", rx: 49, lost: 1}, {relay: "B", rx: 49, lost: 1}, {relay: "C", rx: 49, lost: 1}},
	}
	for _, overTCP := range []bool{true, false} {
		l = relayLedger{}
		if at, v := ledgerVerdictOver(&l, overTCP, ring); at != 0 {
			t.Fatalf("over TCP %v: rested %+v at window %d, a ring of three", overTCP, v, at)
		}
	}
	// But a relay worse than every relay of the ring is rested against it
	// (Codex, 2026-11-06): D losing 20%, joining once the ring has formed —
	// every relay D meets has a case of its own then — round after round.
	l = relayLedger{}
	for _, w := range ring {
		if v := l.step(w, true); len(v) != 0 {
			t.Fatalf("the ring forming: rested %+v", v)
		}
	}
	restedAt := 0
	for i := 0; i < 3*len(ring) && restedAt == 0; i++ {
		w := append(slices.Clone(ring[i%len(ring)]), relayLossSample{relay: "D", rx: 120, lost: 30})
		for _, v := range l.step(w, true) {
			if v.relay != "D" {
				t.Fatalf("window %d after D joined: rested %+v, a relay of the ring", i+1, v)
			}
			restedAt = i + 1
		}
	}
	if restedAt != relayLedgerMinWindows {
		t.Fatalf("D, worse than the whole ring, rested at window %d after it joined, want %d", restedAt, relayLedgerMinWindows)
	}
	worse := []relayLossSample{{relay: "A", rx: 990, lost: 10}, {relay: "B", rx: 900, lost: 100}}
	l = relayLedger{}
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{worse, worse, worse}); at != 3 || len(v) != 1 || v[0].relay != "B" {
		t.Fatalf("verdict %+v at window %d, want B alone at the third", v, at)
	}
}

// Twenty lost in one window with nothing before or after is a burst — a
// stream's TCP connection to the relay re-dialed — not a relay to rest for
// half an hour: the loss has to be in two of the shared windows.
func TestRelayLedgerNeedsTheLossInTwoWindows(t *testing.T) {
	burst := []relayLossSample{{relay: "A", rx: 80, lost: 20}, {relay: "B", rx: 1000}}
	clean := []relayLossSample{{relay: "A", rx: 100}, {relay: "B", rx: 1000}}
	var l relayLedger
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{burst, clean, clean}); at != 0 {
		t.Fatalf("rested %+v at window %d on one window of loss", v, at)
	}
	// One more lost in a fourth window: two windows of loss, 21 over 400.
	if v := l.step([]relayLossSample{{relay: "A", rx: 99, lost: 1}, {relay: "B", rx: 1000}}, true); len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v, want A once the loss is in two windows", v)
	}
}

// Over UDP the book keeps the windows' judge's bars and twice its lost: forty
// over the minute at five times the neighbour's rate and two points above it.
// The phone's own loss lands on the relays, so twenty at half a point would
// rest a clean one by chance; the 1-2% relay is the UDP's blind spot.
func TestRelayLedgerOverUDPAsksForFortyAtFiveTimes(t *testing.T) {
	// .37's field minute (10, 0, 4, 0, 0, 8 of 280: 1.3%) rests the relay over
	// TCP and not over UDP, however long it goes on.
	minute := [][]relayLossSample{fieldWindow(10), fieldWindow(0), fieldWindow(4), fieldWindow(0), fieldWindow(0), fieldWindow(8)}
	var l relayLedger
	for i := 0; i < 3; i++ {
		for _, w := range minute {
			if v := l.step(w, false); len(v) != 0 {
				t.Fatalf("rested %+v over UDP on 1.3%%", v)
			}
		}
	}
	// 3.6% alone on one relay (10 of 280 a window, the neighbours clean) is no
	// radio: forty lost at the fourth window.
	l = relayLedger{}
	at, v := ledgerVerdictOver(&l, false, [][]relayLossSample{fieldWindow(10), fieldWindow(10), fieldWindow(10), fieldWindow(10)})
	if at != 4 || len(v) != 1 || v[0].relay != "193.203.43.37" {
		t.Fatalf("verdict %+v at window %d, want .37 at the fourth (40 lost)", v, at)
	}
	if !strings.Contains(v[0].evidence, "40 lost over 4 windows") || !strings.Contains(v[0].evidence, "over UDP") {
		t.Fatalf("evidence %q", v[0].evidence)
	}
	// 36 of 1680 (2.1%) over the minute is under forty, however long it goes on.
	l = relayLedger{}
	for i := 0; i < 2*relayLedgerWindows; i++ {
		if v := l.step(fieldWindow(6), false); len(v) != 0 {
			t.Fatalf("rested %+v over UDP on 36 lost a minute", v)
		}
	}
	// Under the ratio: 5% against 1.2% is 4×.
	pool := func(a, b int) []relayLossSample {
		return []relayLossSample{{relay: "A", rx: 1000 - a, lost: a}, {relay: "B", rx: 1000 - b, lost: b}}
	}
	l = relayLedger{}
	if at, v := ledgerVerdictOver(&l, false, [][]relayLossSample{pool(50, 12), pool(50, 12), pool(50, 12)}); at != 0 {
		t.Fatalf("rested %+v at window %d: 5%% against 1.2%% is under 5×", v, at)
	}
	// Under the margin: 1.9% against 0% — 57 lost, any ratio, 1.9 points.
	l = relayLedger{}
	if at, v := ledgerVerdictOver(&l, false, [][]relayLossSample{pool(19, 0), pool(19, 0), pool(19, 0)}); at != 0 {
		t.Fatalf("rested %+v at window %d: 1.9 points over the neighbour is under the UDP margin", v, at)
	}
	// Over TCP the same three windows rest A at the third.
	l = relayLedger{}
	if at, v := ledgerVerdictAt(&l, [][]relayLossSample{pool(50, 12), pool(50, 12), pool(50, 12)}); at != 3 || len(v) != 1 || v[0].relay != "A" {
		t.Fatalf("verdict %+v at window %d, want A at the third over TCP", v, at)
	}
}

// The stuck tunnel over UDP (bench 2026-11-04, LTE, the transport forced): .37
// losing 3-12% among five relays held the flow at 0.67 Mbit/s for 90 s, 159
// then 258 packets a window on each relay, and no judge spoke. With the UDP
// bars the book rests it at the third booked window.
func TestRelayLedgerOverUDPRestsTheStuckTunnelsRelay(t *testing.T) {
	thin := func(n, lost int) []relayLossSample {
		return []relayLossSample{
			{relay: "193.203.43.37", rx: n - lost, lost: lost},
			{relay: "95.163.34.145", rx: n}, {relay: "95.163.34.160", rx: n},
			{relay: "95.163.34.48", rx: n}, {relay: "95.163.34.166", rx: n},
		}
	}
	var l relayLedger
	windows := [][]relayLossSample{thin(159, 5), thin(258, 30), thin(250, 25)}
	for i, w := range windows {
		v := l.step(w, false)
		if (len(v) != 0) != (i == 2) {
			t.Fatalf("window %d: verdict %+v, want .37 at the third on 60 lost of 667", i+1, v)
		}
		if i == 2 && (v[0].relay != "193.203.43.37" || v[0].rate < 0.089 || v[0].rate > 0.091) {
			t.Fatalf("verdict %+v, want .37 at 9%%", v[0])
		}
	}
	// The pair alone (04_OWN): 9% of 173, 12% of 525.
	pair := func(n, lost int) []relayLossSample {
		return []relayLossSample{{relay: "193.203.43.37", rx: n - lost, lost: lost}, {relay: "95.163.34.166", rx: n + 150}}
	}
	l = relayLedger{}
	for i, w := range [][]relayLossSample{pair(173, 16), pair(525, 65), pair(300, 30)} {
		if v := l.step(w, false); (len(v) != 0) != (i == 2) {
			t.Fatalf("window %d: verdict %+v, want .37 at the third", i+1, v)
		}
	}
}

// A change of transport empties the book: the windows on either side of it are
// not the same path.
func TestRelayLedgerStartsOverOnAChangeOfTransport(t *testing.T) {
	var l relayLedger
	for i := 0; i < 3; i++ {
		if v := l.step(fieldWindow(6), true); len(v) != 0 {
			t.Fatalf("rested %+v over TCP on %d lost", v, 6*(i+1))
		}
	}
	// 18 booked over TCP; three UDP windows of 10 are 30, not 48: no verdict
	// over UDP (forty), and none that the TCP windows would have given (twenty)
	// had they stayed.
	for i := 0; i < 3; i++ {
		if v := l.step(fieldWindow(10), false); len(v) != 0 {
			t.Fatalf("UDP window %d: rested %+v on windows booked over TCP", i+1, v)
		}
	}
	// Back to TCP: the UDP windows go; the verdict comes at the third TCP
	// window (30 lost), not the first.
	for i := 0; i < 3; i++ {
		v := l.step(fieldWindow(10), true)
		if (len(v) != 0) != (i == 2) {
			t.Fatalf("TCP window %d after UDP: verdict %+v, want one at the third", i+1, v)
		}
	}
}

// The minute slides: what was lost seven windows ago is forgotten.
func TestRelayLedgerForgetsTheWindowBeforeTheMinute(t *testing.T) {
	var l relayLedger
	windows := [][]relayLossSample{fieldWindow(15), fieldWindow(0), fieldWindow(0), fieldWindow(0), fieldWindow(0), fieldWindow(0), fieldWindow(0), fieldWindow(6)}
	if at, v := ledgerVerdictAt(&l, windows); at != 0 {
		t.Fatalf("rested %+v at window %d: 15 lost seven windows before 6", v, at)
	}
	// Within the minute the two add up.
	l = relayLedger{}
	windows = [][]relayLossSample{fieldWindow(15), fieldWindow(0), fieldWindow(0), fieldWindow(0), fieldWindow(0), fieldWindow(6)}
	if at, v := ledgerVerdictAt(&l, windows); at != 6 || len(v) != 1 {
		t.Fatalf("verdict %+v at window %d, want .37 at the sixth", v, at)
	}
}
