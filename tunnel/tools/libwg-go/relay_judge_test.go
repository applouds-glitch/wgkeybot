package main

import (
	"context"
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

func TestRelayJudgeIgnoresRelaysWithLittleTraffic(t *testing.T) {
	var j relayJudge
	thin := []relayLossSample{{relay: "A", rx: 90, lost: 60}, {relay: "B", rx: 900, lost: 5}}
	for i := 0; i < 3; i++ {
		if bad := judged(&j, thin); bad != "" {
			t.Fatalf("rested %s on %d packets", bad, 150)
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
	// Every relay resting: the outage order, not nothing.
	noteRelayResting("10.0.0.2:3478", now)
	noteRelayResting("10.0.0.1:3478", now)
	if got := assignRelays(addrs, 0, now); len(got) != 2 {
		t.Fatalf("all resting → %v, want both in outage order", got)
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
