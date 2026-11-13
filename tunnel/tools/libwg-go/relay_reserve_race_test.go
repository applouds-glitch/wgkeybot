/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// The relays raced behind the extras begin at the first of the link's own
// after an extra at the head; what the order has behind them goes with them.
func TestReserveSplit(t *testing.T) {
	reserve := map[string]bool{"R1": true, "Rfull": true}
	cases := []struct {
		order []string
		want  int
	}{
		{[]string{"E1", "E2", "R1", "Efull", "Rfull"}, 2},
		{[]string{"E1", "R1", "Rfull"}, 1},
		{[]string{"E1", "E2"}, 2},
		{[]string{"R1", "E2", "Rfull"}, 3}, // the head is the link's own: no stages
		{[]string{"E1"}, 1},
		{nil, 0},
	}
	for _, c := range cases {
		if got := reserveSplit(c.order, reserve); got != c.want {
			t.Fatalf("%v: split at %d, want %d", c.order, got, c.want)
		}
	}
	if got := reserveSplit([]string{"E1", "E2", "R1"}, nil); got != 3 {
		t.Fatalf("no reserve: split at %d, want 3", got)
	}
}

// reserveRace is the relays of a race with extras: the extras in the order
// stream 0 dials them — the head first — and the link's own, the one the link
// hands out.
type reserveRace struct {
	extras []net.PacketConn
	own    net.PacketConn
	causes *reserveCauses
}

// reserveCauses records why the link's own were raced (reserveRaced).
type reserveCauses struct {
	mu  sync.Mutex
	got []reserveCause
}

func (c *reserveCauses) all() []reserveCause {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.got)
}

// reserveRaceSockets returns n extras in the order stream 0 will dial them and
// the link's own, and records why the link's own are raced.
func reserveRaceSockets(t *testing.T, n int) reserveRace {
	t.Helper()
	var extras []net.PacketConn
	for i := 0; i < n; i++ {
		extras = append(extras, listenFakeRelay(t))
	}
	slices.SortFunc(extras, func(a, b net.PacketConn) int {
		return strings.Compare(a.LocalAddr().String(), b.LocalAddr().String())
	})
	causes := &reserveCauses{}
	prev := reserveRaced
	reserveRaced = func(stream int, cause reserveCause) {
		causes.mu.Lock()
		causes.got = append(causes.got, cause)
		causes.mu.Unlock()
	}
	t.Cleanup(func() { reserveRaced = prev })
	return reserveRace{extras: extras, own: listenFakeRelay(t), causes: causes}
}

// pinReserveWait sets relayReserveStep and relayReserveCap for the test.
func pinReserveWait(t *testing.T, step, cap time.Duration) {
	t.Helper()
	prevStep, prevCap := relayReserveStep, relayReserveCap
	relayReserveStep, relayReserveCap = step, cap
	t.Cleanup(func() { relayReserveStep, relayReserveCap = prevStep, prevCap })
}

// run starts one worker with the extras configured and the link's own relay as
// the link's list, and checks the order it will dial in.
func (r reserveRace) run(t *testing.T, group int) *raceHarness {
	t.Helper()
	var extras []string
	for _, e := range r.extras {
		extras = append(extras, e.LocalAddr().String())
	}
	own := r.own.LocalAddr().String()
	answer := make(chan struct{})
	close(answer)
	cfg := WorkerGroupConfig{GroupID: group, Link: "test", UseUDP: true, PeerType: "wireguard",
		PeerAddr: fakeRelay(t, answer), ExtraRelays: extras}
	addrs := withExtraRelays([]string{own}, cfg)
	if got, want := streamAttemptOrder("test", addrs, 0, cfg, time.Now()), append(slices.Clone(extras), own); !slices.Equal(got, want) {
		t.Fatalf("stream 0 dials %v, want %v: the extras, the link's own", got, want)
	}
	return runWorkersWithConfig(t, 1, []string{own}, cfg)
}

// The head is silent and the other extra answers in about 100 ms: the session
// is on the extra, and the link's own relay — answering at once — is never
// raced. Raced together with the extra, as before, it won.
func TestTheLinksOwnWaitBehindAnAnsweringExtra(t *testing.T) {
	r := reserveRaceSockets(t, 2)
	extra := startTestRelay(t, r.extras[1], 50*time.Millisecond)
	own := startTestRelay(t, r.own, 0)
	h := r.run(t, 141)

	waitFor(t, "a stream on the answering extra", relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != extra.addr {
		t.Fatalf("session runs on %s, want the extra %s", got, extra.addr)
	}
	time.Sleep(relayHeadStart + 500*time.Millisecond)
	if n, causes := own.seen.count(), r.causes.all(); n != 0 || len(causes) != 0 {
		t.Fatalf("the link's own relay was dialed %d time(s) (%v) although an extra answered", n, causes)
	}
}

// The head is silent and the other extra refuses: the link's own are raced on
// that refusal.
func TestTheLinksOwnAreRacedOnceEveryExtraHasFailed(t *testing.T) {
	r := reserveRaceSockets(t, 2)
	// No clock can race them before the refusal does, however slow the host.
	pinReserveWait(t, time.Minute, time.Minute)
	startRefusalServerOn(t, r.extras[1], 100, stun.CodeAllocQuotaReached)
	own := startTestRelay(t, r.own, 0)

	h := r.run(t, 142)
	waitFor(t, "a stream on the link's own relay", 2*relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != own.addr {
		t.Fatalf("session runs on %s, want the link's own %s", got, own.addr)
	}
	if causes := r.causes.all(); !slices.Equal(causes, []reserveCause{reserveAfterFailures}) {
		t.Fatalf("the link's own raced for %v, want once, on the extra's refusal", causes)
	}
}

// Both extras silent: the link's own are raced relayReserveStep after the
// other extra's Allocate went out.
func TestTheLinksOwnAreRacedWhenNoExtraWins(t *testing.T) {
	r := reserveRaceSockets(t, 2)
	pinReserveWait(t, 300*time.Millisecond, time.Minute)
	own := startTestRelay(t, r.own, 0)

	h := r.run(t, 143)
	waitFor(t, "a stream on the link's own relay", 2*relayHeadStart+3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != own.addr {
		t.Fatalf("session runs on %s, want the link's own %s", got, own.addr)
	}
	if causes := r.causes.all(); !slices.Equal(causes, []reserveCause{reserveAfterSteps}) {
		t.Fatalf("the link's own raced for %v, want once, a head start after the extra's step", causes)
	}
}

// holdSlots takes every Allocate slot of addr until the returned func.
func holdSlots(t *testing.T, addr string) (release func()) {
	t.Helper()
	var slots []*allocSlot
	for i := 0; i < allocSlotsPerRelay; i++ {
		slots = append(slots, acquireAllocSlot(context.Background(), addr))
	}
	done := false
	release = func() {
		if !done {
			done = true
			for _, s := range slots {
				s.release()
			}
		}
	}
	t.Cleanup(release)
	return release
}

// The other extra is healthy, but its dial queues for an Allocate slot for two
// seconds — the queue of a mass reconnect. The wait for the link's own runs
// from the extra's Allocate going out, not from its being raced: the session is
// on the extra, and the link's own — no queue, nobody else dials them — are
// not raced.
func TestAnExtrasQueueDoesNotHandTheRaceToTheLinksOwn(t *testing.T) {
	r := reserveRaceSockets(t, 2)
	pinReserveWait(t, relayHeadStart, time.Minute)
	extra := startTestRelay(t, r.extras[1], 0)
	own := startTestRelay(t, r.own, 0)
	release := holdSlots(t, extra.addr)

	h := r.run(t, 144)
	time.Sleep(relayHeadStart + 2*time.Second)
	release()
	waitFor(t, "a stream on the extra", 3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != extra.addr {
		t.Fatalf("session runs on %s, want the extra %s", got, extra.addr)
	}
	if n, causes := own.seen.count(), r.causes.all(); n != 0 || len(causes) != 0 {
		t.Fatalf("the link's own relay was dialed %d time(s) (%v) while the extra queued", n, causes)
	}
}

// Two extras after the head: one refuses at once, the other queues for a slot
// (Codex, 2026-11-06). The refusal's step no longer holds the reserve's clock:
// the queued one has its time, wins, and the link's own are not raced.
func TestARefusedExtraDoesNotCutTheQueuedOnesTime(t *testing.T) {
	r := reserveRaceSockets(t, 3)
	pinReserveWait(t, relayHeadStart, time.Minute)
	startRefusalServerOn(t, r.extras[1], 100, stun.CodeAllocQuotaReached)
	queued := startTestRelay(t, r.extras[2], 0)
	own := startTestRelay(t, r.own, 0)
	release := holdSlots(t, queued.addr)

	h := r.run(t, 146)
	time.Sleep(relayHeadStart + 2*time.Second)
	release()
	waitFor(t, "a stream on the queued extra", 3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != queued.addr {
		t.Fatalf("session runs on %s, want the queued extra %s", got, queued.addr)
	}
	if n, causes := own.seen.count(), r.causes.all(); n != 0 || len(causes) != 0 {
		t.Fatalf("the link's own relay was dialed %d time(s) (%v) while an extra queued", n, causes)
	}
}

// A queue does not hold the link's own back for ever: relayReserveCap after the
// extras were raced, they are raced too.
func TestTheLinksOwnAreRacedWhenTheExtrasQueueTooLong(t *testing.T) {
	r := reserveRaceSockets(t, 2)
	pinReserveWait(t, relayHeadStart, 1500*time.Millisecond)
	extra := startTestRelay(t, r.extras[1], 0)
	own := startTestRelay(t, r.own, 0)
	holdSlots(t, extra.addr)

	h := r.run(t, 145)
	waitFor(t, "a stream on the link's own relay", relayHeadStart+relayReserveCap+3*time.Second, func() bool { return h.ready() == 1 })
	if got := h.streams[0].serverAddr; got != own.addr {
		t.Fatalf("session runs on %s, want the link's own %s", got, own.addr)
	}
	if causes := r.causes.all(); !slices.Equal(causes, []reserveCause{reserveAfterCap}) {
		t.Fatalf("the link's own raced for %v, want once, at the cap", causes)
	}
}
