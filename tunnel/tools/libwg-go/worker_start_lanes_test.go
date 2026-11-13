/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */
package main

import (
	"testing"
	"time"
)

// Ten streams over three extras start three at once, and each lane keeps the
// 500 ms floor between its own streams: the tenth is up at ~1.5 s, not 4.5 s.
func TestWorkerStartDelaysOneLanePerRelay(t *testing.T) {
	noJitter := func() time.Duration { return 0 }
	got := workerStartDelays(10, 3, noJitter)
	want := []time.Duration{0, 0, 0, 500 * time.Millisecond, 500 * time.Millisecond, 500 * time.Millisecond,
		time.Second, time.Second, time.Second, 1500 * time.Millisecond}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stream %d: delay %v, want %v (all %v)", i, got[i], want[i], got)
		}
	}
}

// Without lanes the streams queue as before: one every 500 ms plus the jitter,
// never less, and stream 0 at once.
func TestWorkerStartDelaysOneLaneKeepsTheFloor(t *testing.T) {
	j := []time.Duration{100 * time.Millisecond, 0, 199 * time.Millisecond}
	k := 0
	jitter := func() time.Duration { d := j[k%len(j)]; k++; return d }
	got := workerStartDelays(4, 1, jitter)
	if got[0] != 0 {
		t.Fatalf("stream 0 waited %v", got[0])
	}
	for i := 1; i < len(got); i++ {
		if gap := got[i] - got[i-1]; gap < workerStagger {
			t.Fatalf("gap before stream %d is %v, under the %v floor (all %v)", i, gap, workerStagger, got)
		}
	}
	if got[3] != 1799*time.Millisecond { // 0 + (500+100) + (500+0) + (500+199)
		t.Fatalf("stream 3 at %v, want 1.799s", got[3])
	}
	if got := workerStartDelays(3, 0, jitter); got[1] == 0 {
		t.Fatalf("lanes 0 must mean one lane, got %v", got)
	}
}

// Lanes come from the extras alone: a TurnIP pin or fewer than two distinct
// extras leaves one lane, since the link's own relays are not known at start.
func TestStartLanes(t *testing.T) {
	cases := []struct {
		name string
		cfg  WorkerGroupConfig
		want int
	}{
		{"no extras", WorkerGroupConfig{}, 1},
		{"one extra", WorkerGroupConfig{ExtraRelays: []string{"95.163.34.160"}}, 1},
		{"three extras", WorkerGroupConfig{ExtraRelays: []string{"95.163.34.160", "95.163.34.48", "95.163.34.145"}}, 3},
		{"duplicate extras", WorkerGroupConfig{ExtraRelays: []string{"95.163.34.160", "95.163.34.160"}}, 1},
		{"pinned", WorkerGroupConfig{TurnIP: "95.163.34.160", ExtraRelays: []string{"95.163.34.160", "95.163.34.48"}}, 1},
	}
	for _, c := range cases {
		if got := startLanes(c.cfg); got != c.want {
			t.Errorf("%s: lanes %d, want %d", c.name, got, c.want)
		}
	}
}
