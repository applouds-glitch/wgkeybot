package main

import (
	"testing"
	"time"
)

// rx delivered packets in a 10 s window over the relay's streams, lossPct of
// what was sent lost.
func collapseSample(relay string, rx int, lossPct float64) relayLossSample {
	lost := int(float64(rx) * lossPct / (100 - lossPct))
	return relayLossSample{relay: relay, rx: rx, lost: lost, active: 10}
}

func TestRelayCollapseNeedsLossAtALowRate(t *testing.T) {
	streams := map[string]int{"A": 10}
	cases := map[string]relayLossSample{
		"healthy saturation":   collapseSample("A", 14000, 12), // 140/s per stream, TCP at the ceiling
		"light traffic, clean": collapseSample("A", 300, 0.3),  // 3/s per stream, nothing lost
		"low rate, clean":      collapseSample("A", 2500, 1),   // 25/s per stream, under the loss floor
	}
	// A page load: a burst that lost its slow-start overshoot, quiet the rest
	// of the window.
	burst := collapseSample("A", 2500, 6)
	burst.active = 3
	cases["bursts"] = burst
	for name, s := range cases {
		var j relayCollapseJudge
		for i := 0; i < 4; i++ {
			if got := j.step([]relayLossSample{s}, streams, 10*time.Second); len(got) != 0 {
				t.Fatalf("%s: collapsed %v", name, got)
			}
		}
	}

	var j relayCollapseJudge
	bad := collapseSample("A", 2500, 6) // 25/s per stream, 6% lost
	if got := j.step([]relayLossSample{bad}, streams, 10*time.Second); len(got) != 0 {
		t.Fatalf("collapsed after one window: %v", got)
	}
	if got := j.step([]relayLossSample{bad}, streams, 10*time.Second); len(got) != 1 || got[0] != "A" {
		t.Fatalf("got %v after two windows, want A", got)
	}
}

func TestRelayCollapseCountsWindowsInARow(t *testing.T) {
	streams := map[string]int{"A": 10}
	bad := collapseSample("A", 2500, 6)
	var j relayCollapseJudge
	j.step([]relayLossSample{bad}, streams, 10*time.Second)
	j.step([]relayLossSample{collapseSample("A", 14000, 12)}, streams, 10*time.Second) // back to speed
	if got := j.step([]relayLossSample{bad}, streams, 10*time.Second); len(got) != 0 {
		t.Fatalf("collapsed on a broken streak: %v", got)
	}
	// A quiet window keeps the streak.
	j.step([]relayLossSample{{relay: "A", rx: 50, lost: 10}}, streams, 10*time.Second)
	if got := j.step([]relayLossSample{bad}, streams, 10*time.Second); len(got) != 1 {
		t.Fatalf("got %v after a quiet window, want A", got)
	}
}

// With two relays carrying the session the relative judge decides: both losing
// alike is the phone's network, which recycling does not cure.
func TestRelayCollapseLeavesTwoRelaysToTheRelativeJudge(t *testing.T) {
	streams := map[string]int{"A": 5, "B": 5}
	both := []relayLossSample{collapseSample("A", 1250, 6), collapseSample("B", 1250, 6)}
	var j relayCollapseJudge
	for i := 0; i < 4; i++ {
		if got := j.step(both, streams, 10*time.Second); len(got) != 0 {
			t.Fatalf("collapsed with two relays carrying: %v", got)
		}
	}

	// A window over two relays breaks a streak on one.
	alone := []relayLossSample{collapseSample("A", 1250, 6)}
	j.step(alone, streams, 10*time.Second)
	j.step(both, streams, 10*time.Second)
	if got := j.step(alone, streams, 10*time.Second); len(got) != 0 {
		t.Fatalf("collapsed on a streak broken by two relays: %v", got)
	}

	// A trickle through the other relay is not a second one to compare with.
	trickle := []relayLossSample{collapseSample("A", 1250, 6), {relay: "B", rx: 60, lost: 1, active: 10}}
	if got := j.step(trickle, streams, 10*time.Second); len(got) != 1 || got[0] != "A" {
		t.Fatalf("got %v beside a trickle, want A", got)
	}
}

func TestRelayCollapseIgnoresARelayWithNoSessions(t *testing.T) {
	var j relayCollapseJudge
	bad := collapseSample("A", 2500, 6)
	for i := 0; i < 3; i++ {
		if got := j.step([]relayLossSample{bad}, map[string]int{}, 10*time.Second); len(got) != 0 {
			t.Fatalf("collapsed with no sessions on the relay: %v", got)
		}
	}
}
